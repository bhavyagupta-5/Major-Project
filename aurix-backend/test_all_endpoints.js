/**
 * AURIX Backend End-to-End Test Suite
 * Validates all 9 user requirements and API endpoints
 */

const app = require('./server');

async function runTests() {
    console.log('====================================================');
    console.log('🧪 RUNNING AURIX BACKEND COMPREHENSIVE TEST SUITE');
    console.log('====================================================\n');

    const server = app.listen(4001);
    const BASE_URL = 'http://localhost:4001';
    let testsPassed = 0;
    let testsFailed = 0;

    const assert = (condition, testName, details = '') => {
        if (condition) {
            console.log(`✅ [PASS] ${testName}`);
            testsPassed++;
        } else {
            console.error(`❌ [FAIL] ${testName} - ${details}`);
            testsFailed++;
        }
    };

    try {
        // 1. Health Check
        const healthRes = await fetch(`${BASE_URL}/health`);
        const healthData = await healthRes.json();
        assert(healthRes.status === 200 && healthData.status === 'ok', 'GET /health returns 200 OK');

        // 2. Auth: Generate Sandbox Session
        const sandboxRes = await fetch(`${BASE_URL}/api/auth/sandbox`, { method: 'POST' });
        const sandboxData = await sandboxRes.json();
        assert(
            sandboxRes.status === 200 && sandboxData.token && sandboxData.profile.role === 'auditor',
            'POST /api/auth/sandbox returns demo session with token'
        );

        const sandboxToken = sandboxData.token;

        // 3. Auth: GET /api/auth/me WITH sandbox token
        const meWithTokenRes = await fetch(`${BASE_URL}/api/auth/me`, {
            headers: { 'Authorization': `Bearer ${sandboxToken}` }
        });
        const meWithTokenData = await meWithTokenRes.json();
        assert(
            meWithTokenRes.status === 200 && meWithTokenData.user.email === 'sandbox.auditor@aurix.local',
            'GET /api/auth/me with Bearer token returns profile'
        );

        // 4. Requirement 3: Sandbox Fallback on unauthenticated request
        const meWithoutTokenRes = await fetch(`${BASE_URL}/api/auth/me`);
        const meWithoutTokenData = await meWithoutTokenRes.json();
        assert(
            meWithoutTokenRes.status === 200 && meWithoutTokenData.user.is_sandbox === true,
            'GET /api/auth/me without token succeeds via Sandbox Fallback (No 401 crash)'
        );

        // 5. Auth: GET /api/auth/github
        const githubOAuthRes = await fetch(`${BASE_URL}/api/auth/github`);
        const githubOAuthData = await githubOAuthRes.json();
        assert(
            githubOAuthRes.status === 200 && githubOAuthData.provider === 'github',
            'GET /api/auth/github returns OAuth URL & configuration'
        );

        // 6. Requirement 6: POST /api/projects
        const createProjectRes = await fetch(`${BASE_URL}/api/projects`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                name: 'Test Vuln App',
                repository_url: 'https://github.com/stamparm/DSVW'
            })
        });
        const createProjectData = await createProjectRes.json();
        assert(
            createProjectRes.status === 201 && createProjectData.project.id,
            'POST /api/projects creates a new project'
        );

        const projectId = createProjectData.project.id;

        // 7. Requirement 6: GET /api/projects
        const getProjectsRes = await fetch(`${BASE_URL}/api/projects`);
        const getProjectsData = await getProjectsRes.json();
        assert(
            getProjectsRes.status === 200 && Array.isArray(getProjectsData) && getProjectsData.length > 0,
            'GET /api/projects returns user projects list'
        );

        // 8. Requirement 4 & Ingestion: POST /api/scans/github
        const scanGithubRes = await fetch(`${BASE_URL}/api/scans/github`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                github_url: 'https://github.com/stamparm/DSVW',
                project_id: projectId
            })
        });
        const scanGithubData = await scanGithubRes.json();
        assert(
            scanGithubRes.status === 202 && scanGithubData.scan_id && scanGithubData.status === 'PENDING',
            'POST /api/scans/github queues scan and returns 202 Accepted'
        );

        const scanId = scanGithubData.scan_id;

        // 9. Requirement 7: GET /api/scans/:scan_id/progress (Polling)
        const progressRes = await fetch(`${BASE_URL}/api/scans/${scanId}/progress`);
        const progressData = await progressRes.json();
        assert(
            progressRes.status === 200 && progressData.scan_id === scanId && Array.isArray(progressData.logs),
            'GET /api/scans/:scan_id/progress returns animated progress data and live logs'
        );

        // 10. Requirement 7: POST /api/internal/webhook/scan-progress
        const webhookProgressRes = await fetch(`${BASE_URL}/api/internal/webhook/scan-progress`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_id: scanId,
                step: 'SAST Analysis',
                progress: 45,
                current_file: 'src/auth.js',
                log: '[SAST] Analyzed authentication module'
            })
        });
        const webhookProgressData = await webhookProgressRes.json();
        assert(
            webhookProgressRes.status === 200 && webhookProgressData.progress.progress === 45,
            'POST /api/internal/webhook/scan-progress records scanner step & percentage'
        );

        // 11. Requirement 8: GET /api/findings/active
        const activeFindingsRes = await fetch(`${BASE_URL}/api/findings/active`);
        const activeFindingsData = await activeFindingsRes.json();
        assert(
            activeFindingsRes.status === 200 && Array.isArray(activeFindingsData.findings) && activeFindingsData.count > 0,
            'GET /api/findings/active returns list of active vulnerabilities'
        );

        const targetFinding = activeFindingsData.findings[0];

        // 12. Requirement 8: PATCH /api/findings/:id/resolve
        const resolveRes = await fetch(`${BASE_URL}/api/findings/${targetFinding.id}/resolve`, {
            method: 'PATCH'
        });
        const resolveData = await resolveRes.json();
        assert(
            resolveRes.status === 200 && resolveData.is_resolved === true,
            'PATCH /api/findings/:id/resolve marks finding as resolved'
        );

        // 13. Requirement 8: POST /api/pr/create
        const createPrRes = await fetch(`${BASE_URL}/api/pr/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                finding_id: targetFinding.id,
                repo_url: 'https://github.com/stamparm/DSVW'
            })
        });
        const createPrData = await createPrRes.json();
        assert(
            createPrRes.status === 201 && createPrData.pr_url && createPrData.status === 'OPEN',
            'POST /api/pr/create generates automated GitHub Pull Request with security patch'
        );

        // 14. Wait for background scanner to run simulated steps
        console.log('\n⏳ Awaiting background scanner pipeline execution...');
        await new Promise(r => setTimeout(r, 6000));

        // 15. Check finalized scan status: GET /api/scans/:scan_id
        const finalScanRes = await fetch(`${BASE_URL}/api/scans/${scanId}`);
        const finalScanData = await finalScanRes.json();
        assert(
            finalScanRes.status === 200 && (finalScanData.status === 'COMPLETED' || finalScanData.status === 'SCANNING'),
            'GET /api/scans/:scan_id transitions out of PENDING without getting stuck (triggerRealScanner active)'
        );

    } catch (err) {
        console.error('Fatal test error:', err);
        testsFailed++;
    } finally {
        server.close();
        console.log('\n====================================================');
        console.log(`📊 TEST SUMMARY: ${testsPassed} Passed, ${testsFailed} Failed`);
        console.log('====================================================\n');
        process.exit(testsFailed > 0 ? 1 : 0);
    }
}

runTests();
