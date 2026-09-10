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
    getScanProgress,
    getRealisticFindings
} = require('./services/scannerService');

// Route modules
const authRoutes = require('./routes/auth');
const projectRoutes = require('./routes/projects');
const scanRoutes = require('./routes/scans');
const findingsRoutes = require('./routes/findings');
const prRoutes = require('./routes/pr');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ==============================================================================
// Health Check Endpoint
// ==============================================================================
app.get('/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        service: 'AURIX API Gateway',
        timestamp: new Date().toISOString(),
        redis_connected: !!redis,
        database: 'Supabase PostgreSQL'
    });
});

// ==============================================================================
// API Route Handlers
// ==============================================================================
// 1. Authentication Routes (/api/auth)
app.use('/api/auth', authRoutes);

// 2. Project Management Routes (/api/projects)
app.use('/api/projects', projectRoutes);

// 3. Scan & Ingestion Routes (/api/scans)
app.use('/api/scans', scanRoutes);

// 4. Vulnerability Findings Routes (/api/findings)
app.use('/api/findings', findingsRoutes);

// 5. Automated GitHub PR Remediation Routes (/api/pr)
app.use('/api/pr', prRoutes);

// ==============================================================================
// Internal Worker Webhooks & RAG Threat Intel Endpoints
// ==============================================================================

/**
 * POST /api/internal/webhook/scan-progress
 * Scanner worker streams live step and percentage updates
 */
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

/**
 * POST /api/internal/webhook/scan-complete
 * AI worker pushes verified findings and marks scan completed
 */
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
                    progress: 100,
                    current_step: 'Completed',
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
            log: `[WEBHOOK] AI Worker finalized scan. ${findings ? findings.length : 0} vulnerabilities verified.`
        });

        return res.status(200).json({ message: 'Webhook processed successfully' });
    } catch (err) {
        console.error('Webhook error:', err);
        return res.status(500).json({ error: 'Internal server error processing webhook' });
    }
});

/**
 * POST /api/internal/threat-intel/search
 * Cosine similarity search against pgvector THREAT_INTELLIGENCE table
 */
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

// ==============================================================================
// Automated Storage Sanitization Cron Job (Hourly)
// ==============================================================================
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

// Start listening if run directly
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

// Export app and scanner trigger function for direct integration and testing
module.exports = app;
module.exports.triggerRealScanner = triggerRealScanner;
