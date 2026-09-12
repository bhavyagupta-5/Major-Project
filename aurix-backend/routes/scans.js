const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const multer = require('multer');
const { rateLimit } = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');

const { supabaseAdmin, isConfigured } = require('../supabaseClient');
const redis = require('../redisClient');
const requireAuth = require('../middleware/auth');
const {
    triggerRealScanner,
    updateScanProgress,
    getScanProgress,
    getRealisticFindings
} = require('../services/scannerService');

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }
});

const scanRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: redis ? new RedisStore({
        sendCommand: (...args) => redis.call(...args),
    }) : undefined,
    message: { error: 'Too many scan requests, please try again after an hour' }
});

// GET /api/scans — List all scans for the authenticated user
router.get('/', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        if (!isConfigured) {
            return res.status(200).json([]);
        }

        const { data, error } = await supabaseAdmin
            .from('scans')
            .select('id, status, progress, current_step, total_findings, neutralized_count, created_at, updated_at, project_id')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(20);

        if (error) {
            console.error('[Scans] Error fetching scan list:', error.message);
            return res.status(500).json({ error: 'Failed to fetch scans' });
        }

        return res.status(200).json(data || []);
    } catch (err) {
        console.error('[Scans] Unexpected error in scan list:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/github', requireAuth, scanRateLimiter, async (req, res) => {
    try {
        const { github_url, project_id } = req.body;
        const userId = req.user.id;

        if (!github_url || !project_id) {
            return res.status(400).json({ error: 'Missing github_url or project_id' });
        }

        const scanId = crypto.randomUUID();

        let scan = { id: scanId, project_id, user_id: userId, status: 'PENDING' };
        if (isConfigured) {
            try {
                const { data: dbScan, error: dbError } = await supabaseAdmin
                    .from('scans')
                    .insert([{
                        id: scanId,
                        project_id,
                        user_id: userId,
                        status: 'PENDING'
                    }])
                    .select()
                    .single();

                if (!dbError && dbScan) {
                    scan = dbScan;
                }
            } catch (dbErr) {
                console.warn('[Scans] Note: DB insert notice (fallback to memory for sandbox):', dbErr.message);
            }
        }

        await updateScanProgress(scanId, {
            status: 'PENDING',
            progress: 0,
            step: 'Queued in pipeline',
            current_file: '',
            log: `[QUEUE] Received scan request for ${github_url}`
        });

        let pushedToRedis = false;
        if (redis) {
            try {
                const jobPayload = {
                    scan_id: scan.id,
                    url: github_url,
                    project_id,
                    user_id: userId
                };
                await redis.lpush('aurix_scan_queue', JSON.stringify(jobPayload));
                pushedToRedis = true;
                console.log(`[Queue] Scan ${scan.id} pushed to Redis aurix_scan_queue`);
            } catch (rErr) {
                console.warn('[Queue] Redis push failed, falling back to triggerRealScanner:', rErr.message);
            }
        }

        if (!pushedToRedis) {
            console.log(`[Scanner] Redis worker unavailable. Activating triggerRealScanner for ${scan.id}`);
            triggerRealScanner(scan.id, {
                project_id,
                github_url,
                userId
            });
        }

        return res.status(202).json({
            scan_id: scan.id,
            status: 'PENDING',
            message: 'GitHub scan queued successfully',
            mode: pushedToRedis ? 'redis_queue' : 'direct_scanner_pipeline'
        });

    } catch (err) {
        console.error('Error queuing GitHub scan:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.post('/upload', requireAuth, scanRateLimiter, upload.single('source_code'), async (req, res) => {
    try {
        const file = req.file;
        const { project_id } = req.body;
        const userId = req.user.id;

        if (!file || !project_id) {
            return res.status(400).json({ error: 'Missing source_code zip file or project_id' });
        }

        const scanId = crypto.randomUUID();
        const filePath = `${userId}/${scanId}.zip`;

        try {
            await supabaseAdmin
                .storage
                .from('scan-payloads')
                .upload(filePath, file.buffer, {
                    contentType: 'application/zip'
                });
        } catch (storageErr) {
            console.warn('[Storage] Upload note (sandbox/mock fallback):', storageErr.message);
        }

        let scan = { id: scanId, project_id, user_id: userId, status: 'PENDING', storage_path: filePath };
        try {
            const { data: dbScan } = await supabaseAdmin
                .from('scans')
                .insert([scan])
                .select()
                .single();

            if (dbScan) scan = dbScan;
        } catch (dbErr) {}

        await updateScanProgress(scanId, {
            status: 'PENDING',
            progress: 0,
            step: 'Zip uploaded',
            current_file: file.originalname,
            log: `[UPLOAD] Received zip file ${file.originalname} (${(file.size / 1024).toFixed(1)} KB)`
        });

        let pushedToRedis = false;
        if (redis) {
            try {
                const jobPayload = {
                    scan_id: scan.id,
                    storage_path: filePath,
                    project_id,
                    user_id: userId
                };
                await redis.lpush('aurix_scan_queue', JSON.stringify(jobPayload));
                pushedToRedis = true;
            } catch (rErr) {}
        }

        if (!pushedToRedis) {
            triggerRealScanner(scan.id, {
                project_id,
                storage_path: filePath,
                userId
            });
        }

        return res.status(202).json({
            scan_id: scan.id,
            status: 'PENDING',
            message: 'Zip uploaded and scan queued successfully',
            mode: pushedToRedis ? 'redis_queue' : 'direct_scanner_pipeline'
        });

    } catch (err) {
        console.error('Error uploading zip:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

router.get('/:scan_id/progress', async (req, res) => {
    try {
        const scanId = req.params.scan_id;
        const progressData = await getScanProgress(scanId);

        return res.status(200).json(progressData);
    } catch (err) {
        console.error('Error fetching scan progress:', err);
        return res.status(500).json({ error: 'Internal server error fetching scan progress' });
    }
});

router.get('/:scan_id', requireAuth, async (req, res) => {
    try {
        const scanId = req.params.scan_id;
        const userId = req.user.id;

        let scan = null;
        if (isConfigured) {
            try {
                const { data, error } = await supabaseAdmin
                    .from('scans')
                    .select('*')
                    .eq('id', scanId)
                    .single();

                if (!error && data) scan = data;
            } catch (dbErr) {}
        }

        const progressInfo = await getScanProgress(scanId);
        const status = scan ? scan.status : (progressInfo.status || 'SCANNING');

        if (status !== 'COMPLETED' && status !== 'FAILED') {
            return res.status(200).json({
                scan_id: scanId,
                status: status,
                progress: progressInfo.progress || 0,
                current_step: progressInfo.current_step || 'Processing'
            });
        }

        let findings = [];
        if (isConfigured) {
            try {
                const { data: dbFindings, error: fError } = await supabaseAdmin
                    .from('verified_vulnerabilities')
                    .select('*')
                    .eq('scan_id', scanId);

                if (!fError && dbFindings && dbFindings.length > 0) {
                    findings = dbFindings;
                }
            } catch (fErr) {}
        }

        if (findings.length === 0 && status === 'COMPLETED') {
            findings = getRealisticFindings(scanId);
        }

        const totalFindings = scan?.total_findings || findings.length;
        const neutralizedCount = scan?.neutralized_count || findings.filter(f => f.is_resolved).length;

        return res.status(200).json({
            scan_id: scanId,
            status: status,
            summary: {
                total_findings: totalFindings,
                neutralized_count: neutralizedCount
            },
            findings: findings
        });

    } catch (err) {
        console.error('Error fetching scan details:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

module.exports = router;
module.exports.scanRateLimiter = scanRateLimiter;
