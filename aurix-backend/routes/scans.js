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
    getScanProgress
} = require('../services/scannerService');

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 200 * 1024 * 1024 } // 200MB file size limit
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

        let { data, error } = await supabaseAdmin
            .from('scans')
            .select('id, status, total_findings, neutralized_count, created_at, updated_at, project_id')
            .eq('user_id', userId)
            .order('created_at', { ascending: false })
            .limit(30);

        if (error || !data || data.length === 0) {
            const fallbackRes = await supabaseAdmin
                .from('scans')
                .select('id, status, total_findings, neutralized_count, created_at, updated_at, project_id')
                .order('created_at', { ascending: false })
                .limit(30);
            if (!fallbackRes.error && fallbackRes.data) {
                data = fallbackRes.data;
            }
        }

        const formatted = (data || []).map(s => ({
            ...s,
            progress: s.status === 'COMPLETED' ? 100 : 0,
            current_step: s.status === 'COMPLETED' ? 'Scan Completed' : 'Processing'
        }));

        return res.status(200).json(formatted);
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

router.post('/upload', requireAuth, scanRateLimiter, (req, res, next) => {
    upload.single('source_code')(req, res, (err) => {
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(400).json({ error: 'File size exceeds the 200MB limit. Please upload a smaller zip package.' });
            }
            return res.status(400).json({ error: `Upload error: ${err.message}` });
        } else if (err) {
            return res.status(500).json({ error: err.message });
        }
        next();
    });
}, async (req, res) => {
    try {
        const file = req.file;
        let { project_id } = req.body;
        const userId = req.user.id;

        if (!file) {
            return res.status(400).json({ error: 'Missing source_code zip file in upload request' });
        }

        const scanId = crypto.randomUUID();
        const filePath = `${userId}/${scanId}.zip`;

        try {
            // Ensure bucket exists and is marked public
            const { data: buckets } = await supabaseAdmin.storage.listBuckets();
            const exists = buckets?.some(b => b.name === 'scan-payloads');
            if (!exists) {
                await supabaseAdmin.storage.createBucket('scan-payloads', { public: true });
            }

            const { error: upErr } = await supabaseAdmin
                .storage
                .from('scan-payloads')
                .upload(filePath, file.buffer, {
                    contentType: 'application/zip',
                    upsert: true
                });

            if (upErr) {
                console.error('[Storage Upload Error]:', upErr.message);
            }
        } catch (storageErr) {
            console.warn('[Storage] Upload note:', storageErr.message);
        }

        // Generate a 24-hour signed download URL for external AI worker access
        let cleanDownloadUrl = null;
        try {
            const { data: signedData, error: signErr } = await supabaseAdmin
                .storage
                .from('scan-payloads')
                .createSignedUrl(filePath, 60 * 60 * 24);
            if (!signErr && signedData?.signedUrl) {
                cleanDownloadUrl = signedData.signedUrl;
            }
        } catch (signErr) {
            console.warn('[Storage] Signed URL generation notice:', signErr.message);
        }

        if (!cleanDownloadUrl) {
            const backendBaseUrl = process.env.SERVER_URL || process.env.BACKEND_URL || (process.env.PORT ? `http://localhost:${process.env.PORT}` : 'http://localhost:8000');
            cleanDownloadUrl = `${backendBaseUrl}/api/scans/download/${scanId}.zip`;
        }

        // Auto-resolve or create project if not provided
        if (!project_id && isConfigured) {
            try {
                const projectName = file.originalname.replace(/\.zip$/i, '') || 'Uploaded Project';
                const { data: newProj, error: projErr } = await supabaseAdmin
                    .from('projects')
                    .insert([{
                        user_id: userId,
                        name: projectName,
                        repository_url: cleanDownloadUrl
                    }])
                    .select()
                    .single();
                if (!projErr && newProj?.id) {
                    project_id = newProj.id;
                }
            } catch (pErr) {
                console.warn('[Upload] Project auto-creation notice:', pErr.message);
            }
        }

        let scan = { id: scanId, project_id, user_id: userId, status: 'PENDING', storage_path: filePath };
        try {
            const { data: dbScan } = await supabaseAdmin
                .from('scans')
                .insert([scan])
                .select()
                .single();

            if (dbScan) scan = dbScan;
        } catch (dbErr) {
            console.warn('[Scans] Note: DB insert notice for zip scan:', dbErr.message);
        }

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
                    download_url: cleanDownloadUrl,
                    url: cleanDownloadUrl,
                    project_id,
                    user_id: userId
                };
                await redis.lpush('aurix_scan_queue', JSON.stringify(jobPayload));
                pushedToRedis = true;
                console.log(`[Queue] Zip scan ${scan.id} pushed to Redis aurix_scan_queue with clean URL: ${cleanDownloadUrl}`);
            } catch (rErr) {
                console.warn('[Queue] Redis push failed for zip scan, falling back to triggerRealScanner:', rErr.message);
            }
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

// GET /api/scans/download/:file_name — Clean streaming endpoint for AI worker zip ingestion
router.get('/download/:file_name', async (req, res) => {
    try {
        const fileName = req.params.file_name.replace(/\.zip$/i, '');
        const scanId = fileName;

        let storagePath = null;
        if (isConfigured) {
            const { data: scan } = await supabaseAdmin
                .from('scans')
                .select('storage_path, user_id')
                .eq('id', scanId)
                .single();
            if (scan?.storage_path) {
                storagePath = scan.storage_path;
            }
        }

        if (!storagePath) {
            return res.status(404).json({ error: 'Scan zip file payload not found' });
        }

        const { data: blob, error } = await supabaseAdmin
            .storage
            .from('scan-payloads')
            .download(storagePath);

        if (error || !blob) {
            return res.status(404).json({ error: 'Could not download zip payload from storage' });
        }

        const buffer = Buffer.from(await blob.arrayBuffer());
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${scanId}.zip"`);
        return res.send(buffer);

    } catch (err) {
        console.error('[Download Proxy] Error serving zip file:', err.message);
        return res.status(500).json({ error: 'Internal server error downloading zip payload' });
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
            // The AI worker writes findings directly to DB via the scan-complete webhook.
            // If DB has 0 findings after COMPLETED, it means the scan genuinely found nothing
            // (or the AI worker determined all findings were false positives).
            // We do NOT fall back to mock data here.
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
