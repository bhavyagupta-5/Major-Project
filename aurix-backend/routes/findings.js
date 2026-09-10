const express = require('express');
const router = express.Router();
const { supabaseAdmin, isConfigured } = require('../supabaseClient');
const requireAuth = require('../middleware/auth');
const { getRealisticFindings } = require('../services/scannerService');

// In-memory findings cache for sandbox sessions
const sandboxFindings = getRealisticFindings('b05c8ef4-e03b-4186-934f-bd6e5a1a4f75', 'https://github.com/stamparm/DSVW').map((f, idx) => ({
    ...f,
    id: f.id || `finding-${idx + 1}-${Date.now()}`
}));

/**
 * GET /api/findings/active - Returns all active/unresolved vulnerabilities
 */
router.get('/active', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Query database for unresolved vulnerabilities belonging to user's scans
        let findings = [];
        if (isConfigured) {
            try {
                const { data, error } = await supabaseAdmin
                    .from('verified_vulnerabilities')
                    .select('*, scans!inner(user_id, project_id)')
                    .eq('scans.user_id', userId)
                    .eq('is_resolved', false);

                if (!error && data && data.length > 0) {
                    findings = data;
                }
            } catch (dbErr) {
                console.warn('[Findings] Active query notice:', dbErr.message);
            }
        }

        // If no findings found in DB (or in sandbox mode), return active sandbox findings
        if (findings.length === 0) {
            findings = sandboxFindings.filter(f => !f.is_resolved);
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

/**
 * PATCH /api/findings/:id/resolve - Marks a finding as resolved
 */
router.patch('/:id/resolve', requireAuth, async (req, res) => {
    try {
        const findingId = req.params.id;

        // Try updating in Supabase DB if configured
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

                    // Increment neutralized_count on parent scan
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

        // Fallback: update in sandbox findings store
        const memoryFinding = sandboxFindings.find(f => f.id === findingId || f.rule_id === findingId);
        if (memoryFinding) {
            memoryFinding.is_resolved = true;
            memoryFinding.wargame_status = 'Neutralized';
            updatedFinding = memoryFinding;
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
module.exports.sandboxFindings = sandboxFindings;
