const express = require('express');
const router = express.Router();
const { supabaseAdmin, isConfigured } = require('../supabaseClient');
const requireAuth = require('../middleware/auth');

// GET /api/findings/active — all unresolved findings for the authenticated user or for a specific scan
router.get('/active', requireAuth, async (req, res) => {
    try {
        const userId = req.user?.id;
        const scanId = req.query.scan_id;

        let findings = [];
        if (isConfigured) {
            try {
                if (scanId) {
                    const { data, error } = await supabaseAdmin
                        .from('verified_vulnerabilities')
                        .select('*')
                        .eq('scan_id', scanId);

                    if (!error && data && data.length > 0) {
                        findings = data;
                    }
                } else {
                    const { data, error } = await supabaseAdmin
                        .from('verified_vulnerabilities')
                        .select('*, scans!inner(user_id, project_id)')
                        .eq('scans.user_id', userId)
                        .eq('is_resolved', false);

                    if (!error && data && data.length > 0) {
                        findings = data;
                    }
                }
            } catch (dbErr) {
                console.warn('[Findings] Active query notice:', dbErr.message);
            }
        }

        return res.status(200).json({
            count: findings.length,
            findings: findings
        });
    } catch (err) {
        console.error('Fetch active findings error:', err);
        return res.status(500).json({ error: 'Internal server error fetching active findings' });
    }
});

// GET /api/findings/scan/:scanId — dedicated route to fetch all findings & exploit codes for a scan
router.get('/scan/:scanId', requireAuth, async (req, res) => {
    try {
        const { scanId } = req.params;
        let findings = [];
        if (isConfigured) {
            try {
                const { data, error } = await supabaseAdmin
                    .from('verified_vulnerabilities')
                    .select('*')
                    .eq('scan_id', scanId);

                if (!error && data) {
                    findings = data;
                }
            } catch (dbErr) {
                console.warn('[Findings] Scan query notice:', dbErr.message);
            }
        }

        return res.status(200).json({
            scan_id: scanId,
            count: findings.length,
            findings
        });
    } catch (err) {
        console.error('Fetch scan findings error:', err);
        return res.status(500).json({ error: 'Internal server error fetching scan findings' });
    }
});

// PATCH /api/findings/:id/resolve — mark a finding as resolved
router.patch('/:id/resolve', requireAuth, async (req, res) => {
    try {
        const findingId = req.params.id;

        let updatedFinding = null;
        if (isConfigured) {
            try {
                const { data, error } = await supabaseAdmin
                    .from('verified_vulnerabilities')
                    .update({ is_resolved: true })
                    .eq('id', findingId)
                    .select()
                    .single();

                if (!error && data) {
                    updatedFinding = data;

                    if (data.scan_id) {
                        const { data: scan } = await supabaseAdmin
                            .from('scans')
                            .select('neutralized_count')
                            .eq('id', data.scan_id)
                            .single();

                        const newCount = (scan?.neutralized_count || 0) + 1;
                        await supabaseAdmin
                            .from('scans')
                            .update({ neutralized_count: newCount })
                            .eq('id', data.scan_id);
                    }
                }
            } catch (dbErr) {
                console.warn('[Findings] DB resolve notice:', dbErr.message);
            }
        }

        return res.status(200).json({
            message: 'Finding marked as resolved',
            id: findingId,
            is_resolved: true,
            finding: updatedFinding || { id: findingId, is_resolved: true }
        });
    } catch (err) {
        console.error('Resolve finding error:', err);
        return res.status(500).json({ error: 'Internal server error resolving finding' });
    }
});

module.exports = router;
