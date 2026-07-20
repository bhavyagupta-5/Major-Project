const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const multer = require('multer');
const { rateLimit } = require('express-rate-limit');
const { RedisStore } = require('rate-limit-redis');
const cron = require('node-cron');
require('dotenv').config();

const { supabase, supabaseAdmin } = require('./supabaseClient');
const redis = require('./redisClient');
const requireAuth = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 }
});

const scanRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 10,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: redis ? new RedisStore({
        sendCommand: (...args) => redis.call(...args),
    }) : undefined,
    message: { error: 'Too many scan requests, please try again after an hour' }
});

app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'AURIX API Gateway is running' });
});

app.use('/api/scans', requireAuth);

app.post('/api/scans/github', scanRateLimiter, async (req, res) => {
    try {
        const { github_url, project_id } = req.body;
        const userId = req.user.id;

        if (!github_url || !project_id) {
            return res.status(400).json({ error: 'Missing github_url or project_id' });
        }

        const { data: scan, error: dbError } = await supabaseAdmin
            .from('scans')
            .insert([{
                project_id,
                user_id: userId,
                status: 'PENDING'
            }])
            .select()
            .single();

        if (dbError) throw dbError;

        if (redis) {
            const jobPayload = {
                scan_id: scan.id,
                url: github_url,
                user_id: userId
            };
            await redis.lpush('aurix_scan_queue', JSON.stringify(jobPayload));
        }

        return res.status(202).json({
            scan_id: scan.id,
            status: 'PENDING',
            message: 'GitHub scan queued successfully'
        });

    } catch (err) {
        console.error('Error queuing GitHub scan:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/scans/upload', scanRateLimiter, upload.single('source_code'), async (req, res) => {
    try {
        const file = req.file;
        const { project_id } = req.body;
        const userId = req.user.id;

        if (!file || !project_id) {
            return res.status(400).json({ error: 'Missing source_code zip file or project_id' });
        }

        const scanId = crypto.randomUUID();
        const filePath = `${userId}/${scanId}.zip`;

        const { error: uploadError } = await supabaseAdmin
            .storage
            .from('scan-payloads')
            .upload(filePath, file.buffer, {
                contentType: 'application/zip'
            });

        if (uploadError) throw uploadError;

        const { data: scan, error: dbError } = await supabaseAdmin
            .from('scans')
            .insert([{
                id: scanId,
                project_id,
                user_id: userId,
                status: 'PENDING',
                storage_path: filePath
            }])
            .select()
            .single();

        if (dbError) throw dbError;

        if (redis) {
            const jobPayload = {
                scan_id: scan.id,
                storage_path: filePath,
                user_id: userId
            };
            await redis.lpush('aurix_scan_queue', JSON.stringify(jobPayload));
        }

        return res.status(202).json({
            scan_id: scan.id,
            status: 'PENDING',
            message: 'Zip uploaded and scan queued successfully'
        });

    } catch (err) {
        console.error('Error uploading zip:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/scans/:scan_id', async (req, res) => {
    try {
        const scanId = req.params.scan_id;
        const userId = req.user.id;

        const { data: scan, error: scanError } = await supabaseAdmin
            .from('scans')
            .select('*')
            .eq('id', scanId)
            .eq('user_id', userId)
            .single();

        if (scanError || !scan) {
            return res.status(404).json({ error: 'Scan not found' });
        }

        if (scan.status !== 'COMPLETED' && scan.status !== 'FAILED') {
            return res.status(200).json({
                scan_id: scan.id,
                status: scan.status
            });
        }

        const { data: findings, error: findingsError } = await supabaseAdmin
            .from('verified_vulnerabilities')
            .select('*')
            .eq('scan_id', scanId);

        if (findingsError) throw findingsError;

        return res.status(200).json({
            scan_id: scan.id,
            status: scan.status,
            summary: {
                total_findings: scan.total_findings,
                neutralized_count: scan.neutralized_count
            },
            findings: findings || []
        });

    } catch (err) {
        console.error('Error fetching scan status:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/internal/webhook/scan-complete', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader !== 'Bearer aurix-dev-token') {
            return res.status(401).json({ error: 'Unauthorized webhook call' });
        }

        const { scan_id, summary, findings } = req.body;

        if (!scan_id) {
            return res.status(400).json({ error: 'Missing scan_id' });
        }

        const status = (findings && findings.length >= 0) ? 'COMPLETED' : 'FAILED';
        
        const { error: updateError } = await supabaseAdmin
            .from('scans')
            .update({ 
                status,
                total_findings: summary?.total_findings || 0,
                neutralized_count: summary?.neutralized_count || 0,
                updated_at: new Date().toISOString()
            })
            .eq('id', scan_id);

        if (updateError) throw updateError;

        if (findings && findings.length > 0) {
            const vulnerabilities = findings.map(f => ({
                scan_id,
                rule_id: f.rule_id,
                tool: f.tool,
                category: f.category,
                title: f.title,
                description: f.description,
                severity: f.severity,
                cvss: f.cvss,
                file_path: f.file,
                line_number: f.line,
                evidence: f.evidence,
                fix: f.fix,
                verified: f.verified || false,
                wargame_status: f.wargame_status,
                ai_reasoning: f.ai_reasoning,
                poc_script: f.poc_script,
                patch_code: f.patch_code
            }));

            const { error: insertError } = await supabaseAdmin
                .from('verified_vulnerabilities')
                .insert(vulnerabilities);
            
            if (insertError) throw insertError;
        }

        return res.status(200).json({ message: 'Webhook processed successfully' });
    } catch (err) {
        console.error('Webhook error:', err);
        return res.status(500).json({ error: 'Internal server error processing webhook' });
    }
});

app.post('/api/internal/threat-intel/search', async (req, res) => {
    try {
        const { query_embedding } = req.body;

        if (!query_embedding) {
            return res.status(400).json({ error: 'Missing query_embedding' });
        }

        const { data, error } = await supabaseAdmin.rpc('match_threat_intel', {
            query_embedding,
            match_threshold: 0.7,
            match_count: 3
        });

        if (error) throw error;

        return res.status(200).json(data);
    } catch (err) {
        console.error('Threat Intel search error:', err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

cron.schedule('0 * * * *', async () => {
    console.log('Running automated data sanitization cron job...');
    try {
        const { data: scans, error } = await supabaseAdmin
            .from('scans')
            .select('id, storage_path')
            .in('status', ['COMPLETED', 'FAILED'])
            .not('storage_path', 'is', null);

        if (error) throw error;

        for (const scan of scans) {
            if (scan.storage_path) {
                const { error: removeError } = await supabaseAdmin
                    .storage
                    .from('scan-payloads')
                    .remove([scan.storage_path]);

                if (!removeError) {
                    await supabaseAdmin
                        .from('scans')
                        .update({ storage_path: null })
                        .eq('id', scan.id);
                    console.log(`Deleted storage payload for scan ${scan.id}`);
                } else {
                    console.error(`Failed to delete payload for scan ${scan.id}:`, removeError);
                }
            }
        }
    } catch (err) {
        console.error('Error in data sanitization cron:', err);
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
