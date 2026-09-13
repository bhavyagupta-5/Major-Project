const { supabaseAdmin, isConfigured } = require('../supabaseClient');

const scanProgressStore = new Map();

const updateScanProgress = async (scanId, { step, progress, current_file, log, status }) => {
    const existing = scanProgressStore.get(scanId) || {
        scan_id: scanId,
        status: status || 'SCANNING',
        progress: 0,
        current_step: 'Initializing',
        current_file: '',
        logs: [],
        updated_at: new Date().toISOString()
    };

    const newLogs = [...existing.logs];
    if (log) {
        newLogs.push({
            timestamp: new Date().toISOString(),
            message: log
        });
        if (newLogs.length > 100) newLogs.shift();
    }

    const updatedState = {
        scan_id: scanId,
        status: status || existing.status,
        progress: progress !== undefined ? progress : existing.progress,
        current_step: step || existing.current_step,
        current_file: current_file !== undefined ? current_file : existing.current_file,
        logs: newLogs,
        updated_at: new Date().toISOString()
    };

    scanProgressStore.set(scanId, updatedState);

    if (isConfigured) {
        try {
            await supabaseAdmin
                .from('scans')
                .update({
                    status: updatedState.status,
                    progress: updatedState.progress,
                    current_step: updatedState.current_step,
                    updated_at: updatedState.updated_at
                })
                .eq('id', scanId);
        } catch (err) {
            // non-critical: in-memory state is still up-to-date
        }
    }

    return updatedState;
};

const getScanProgress = async (scanId) => {
    if (scanProgressStore.has(scanId)) {
        return scanProgressStore.get(scanId);
    }

    // Fallback: pull state from Supabase DB (e.g. after a server restart on Render)
    if (isConfigured) {
        try {
            const { data: scan } = await supabaseAdmin
                .from('scans')
                .select('*')
                .eq('id', scanId)
                .single();

            if (scan) {
                const fallbackState = {
                    scan_id: scanId,
                    status: scan.status,
                    progress: scan.status === 'COMPLETED' ? 100 : (scan.progress || 0),
                    current_step: scan.current_step || (scan.status === 'COMPLETED' ? 'Scan Completed' : 'Queued – waiting for AI worker'),
                    current_file: '',
                    logs: [
                        {
                            timestamp: scan.created_at,
                            message: `[AURIX] Scan record found in database. Status: ${scan.status}`
                        }
                    ],
                    updated_at: scan.updated_at
                };
                scanProgressStore.set(scanId, fallbackState);
                return fallbackState;
            }
        } catch (err) {
            // Supabase unavailable – return unknown state
        }
    }

    return {
        scan_id: scanId,
        status: 'PENDING',
        progress: 0,
        current_step: 'Queued – waiting for AI worker',
        current_file: '',
        logs: [{ timestamp: new Date().toISOString(), message: '[QUEUE] Job dispatched. Waiting for AWS AI worker to pick it up...' }],
        updated_at: new Date().toISOString()
    };
};

/**
 * DEAD-LETTER / REDIS-DOWN FALLBACK:
 * This is called ONLY when the Redis queue is completely unreachable.
 * It marks the scan as FAILED with a clear error message so the user
 * knows there is an infrastructure problem rather than silently returning 0 results.
 * 
 * ❌ OLD BEHAVIOR: silently ran a fake mock and returned 0 findings.
 * ✅ NEW BEHAVIOR: reports a clear FAILED status so the user knows Redis is down.
 */
const triggerRealScanner = async (scanId, { project_id, github_url, storage_path, userId }) => {
    setImmediate(async () => {
        console.error(`[AURIX Scanner] ❌ CRITICAL: Redis queue is unavailable for scan ${scanId}.`);
        console.error('[AURIX Scanner] The job cannot be dispatched to the AI worker. Marking scan as FAILED.');

        await updateScanProgress(scanId, {
            status: 'FAILED',
            progress: 0,
            step: 'Queue Unreachable',
            current_file: '',
            log: '[INFRASTRUCTURE ERROR] Could not connect to the Redis job queue. The AI Worker never received this scan. Please check the UPSTASH_REDIS_URL environment variable on Render and ensure the queue is accessible. Contact the team admin.'
        });

        if (isConfigured) {
            try {
                await supabaseAdmin
                    .from('scans')
                    .update({
                        status: 'FAILED',
                        current_step: 'Queue Unreachable – Redis connection failed',
                        updated_at: new Date().toISOString()
                    })
                    .eq('id', scanId);
            } catch (e) {}
        }
    });
};

module.exports = {
    triggerRealScanner,
    updateScanProgress,
    getScanProgress,
    scanProgressStore
};
