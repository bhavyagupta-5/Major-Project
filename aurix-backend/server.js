const express = require('express');
const cors = require('cors');
const cron = require('node-cron');
require('dotenv').config();

const { supabase, supabaseAdmin } = require('./supabaseClient');
const redis = require('./redisClient');
const requireAuth = require('./middleware/auth');
const {
    triggerRealScanner,
    updateScanProgress,
    getScanProgress
} = require('./services/scannerService');

const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const scanRoutes = require('./routes/scans');
const findingsRoutes = require('./routes/findings');
const prRoutes = require('./routes/pr');

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = [
  process.env.CLIENT_URL || 'http://localhost:5173',
  process.env.WEB_APP_URL || 'https://aurix-web.vercel.app',
  'http://localhost:3000',
  'http://localhost:5173',
];
app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (VS Code extension, curl, Postman, server-to-server)
    if (!origin) return callback(null, true);
    // Allow VS Code webview origins
    if (origin.startsWith('vscode-webview://')) return callback(null, true);
    // Allow any origin in the whitelist
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    // Allow any origin in development
    if (process.env.NODE_ENV !== 'production') return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AURIX - Email Verified</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #f8fafc;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 40px;
            max-width: 520px;
            width: 100%;
            text-align: center;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
        }
        .icon {
            font-size: 54px;
            margin-bottom: 20px;
        }
        h1 {
            font-size: 24px;
            margin-bottom: 12px;
            color: #38bdf8;
        }
        p {
            color: #94a3b8;
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        .btn {
            display: inline-block;
            background: #0284c7;
            color: white;
            text-decoration: none;
            padding: 12px 28px;
            border-radius: 8px;
            font-weight: 600;
            transition: background 0.2s;
        }
        .btn:hover {
            background: #0369a1;
        }
        .token-box {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 12px;
            margin-top: 20px;
            text-align: left;
            font-family: monospace;
            font-size: 12px;
            color: #a5f3fc;
            word-break: break-all;
            max-height: 120px;
            overflow-y: auto;
            display: none;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">✅</div>
        <h1>Email Verified Successfully!</h1>
        <p>Your AURIX account is verified and active. You can now login or return to the application.</p>
        <a href="http://localhost:5173" class="btn" id="frontend-link">Open AURIX App</a>
        <div class="token-box" id="token-display"></div>
    </div>
    <script>
        const hash = window.location.hash;
        if (hash) {
            const params = new URLSearchParams(hash.substring(1));
            const token = params.get('access_token');
            if (token) {
                const box = document.getElementById('token-display');
                box.style.display = 'block';
                box.innerHTML = '<strong>Access Token (JWT):</strong><br/>' + token;
            }
        }
    </script>
</body>
</html>
    `);
});

app.get('/health', async (req, res) => {
    let redisStatus = 'not_configured';
    if (redis) {
        try {
            const pong = await redis.ping();
            redisStatus = pong === 'PONG' ? 'connected' : 'degraded';
        } catch (err) {
            redisStatus = `error: ${err.message}`;
        }
    }

    const isHealthy = redisStatus === 'connected';
    res.status(isHealthy ? 200 : 503).json({
        status: isHealthy ? 'ok' : 'degraded',
        service: 'AURIX API Gateway',
        timestamp: new Date().toISOString(),
        redis: redisStatus,
        database: 'Supabase PostgreSQL'
    });
});

app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/findings', findingsRoutes);
app.use('/api/pr', prRoutes);

app.post('/api/internal/webhook/scan-progress', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader !== 'Bearer aurix-dev-token' && process.env.NODE_ENV === 'production') {
            return res.status(401).json({ error: 'Unauthorized webhook call' });
        }

        const { scan_id, step, progress, current_file, log, status } = req.body;

        if (!scan_id) {
            return res.status(400).json({ error: 'Missing required field: scan_id' });
        }

        const updated = await updateScanProgress(scan_id, {
            step,
            progress,
            current_file,
            log,
            status
        });

        return res.status(200).json({
            message: 'Scan progress updated successfully',
            progress: updated
        });
    } catch (err) {
        console.error('Scan progress webhook error:', err);
        return res.status(500).json({ error: 'Internal server error updating scan progress' });
    }
});

app.post('/api/internal/webhook/scan-complete', async (req, res) => {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader !== 'Bearer aurix-dev-token' && process.env.NODE_ENV === 'production') {
            return res.status(401).json({ error: 'Unauthorized webhook call' });
        }

        const { scan_id, summary, findings } = req.body;

        if (!scan_id) {
            return res.status(400).json({ error: 'Missing scan_id' });
        }

        const status = (findings && findings.length >= 0) ? 'COMPLETED' : 'FAILED';
        
        try {
            await supabaseAdmin
                .from('scans')
                .update({ 
                    status,
                    total_findings: summary?.total_findings || (findings ? findings.length : 0),
                    neutralized_count: summary?.neutralized_count || 0,
                    updated_at: new Date().toISOString()
                })
                .eq('id', scan_id);

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
                    file_path: f.file || f.file_path,
                    line_number: f.line || f.line_number,
                    evidence: f.evidence,
                    fix: f.fix,
                    verified: f.verified !== undefined ? f.verified : true,
                    wargame_status: f.wargame_status || 'Neutralized',
                    ai_reasoning: f.ai_reasoning,
                    poc_script: f.poc_script,
                    patch_code: f.patch_code,
                    is_resolved: false
                }));

                await supabaseAdmin
                    .from('verified_vulnerabilities')
                    .insert(vulnerabilities);
            }
        } catch (dbErr) {
            console.warn('[Webhook] DB sync notice:', dbErr.message);
        }

        await updateScanProgress(scan_id, {
            status: 'COMPLETED',
            progress: 100,
            step: 'Scan Completed',
            log: `[WEBHOOK] AI Worker finalized scan. ${summary?.exploitable_count || 0} exploitable found, ${summary?.neutralized_count || 0} neutralized.`
        });

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

        return res.status(200).json(data || []);
    } catch (err) {
        console.error('Threat Intel search error:', err);
        return res.status(500).json({ error: 'Internal server error performing threat intel similarity search' });
    }
});

cron.schedule('0 * * * *', async () => {
    console.log('[Sanitizer] Running automated storage sanitization cron job...');
    try {
        const { data: scans, error } = await supabaseAdmin
            .from('scans')
            .select('id, storage_path')
            .in('status', ['COMPLETED', 'FAILED'])
            .not('storage_path', 'is', null);

        if (error) throw error;

        for (const scan of scans || []) {
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
                    console.log(`[Sanitizer] Deleted storage payload for scan ${scan.id}`);
                }
            }
        }
    } catch (err) {
        console.error('[Sanitizer] Error in data sanitization cron:', err);
    }
});

if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`\n🚀 AURIX Backend API Gateway listening on port ${PORT}`);
        console.log(`👉 Health Check: http://localhost:${PORT}/health`);
        console.log(`👉 Auth Routes: http://localhost:${PORT}/api/auth/*`);
        console.log(`👉 Projects: http://localhost:${PORT}/api/projects`);
        console.log(`👉 Scans: http://localhost:${PORT}/api/scans/*`);
        console.log(`👉 Findings: http://localhost:${PORT}/api/findings/active`);
        console.log(`👉 PR Creation: http://localhost:${PORT}/api/pr/create\n`);
    });
}

module.exports = app;
module.exports.triggerRealScanner = triggerRealScanner;
