const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { supabaseAdmin, isConfigured } = require('../supabaseClient');
const requireAuth = require('../middleware/auth');

// In-memory cache for sandbox projects
const sandboxProjectsStore = [
    {
        id: 'b05c8ef4-e03b-4186-934f-bd6e5a1a4f75',
        user_id: '00000000-0000-0000-0000-000000000001',
        name: 'Damn Small Vulnerable Web App (DSVW)',
        repository_url: 'https://github.com/stamparm/DSVW',
        total_scans: 2,
        last_scan_status: 'COMPLETED',
        created_at: new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString()
    },
    {
        id: 'c12d3e4f-5a6b-7c8d-9e0f-1a2b3c4d5e6f',
        user_id: '00000000-0000-0000-0000-000000000001',
        name: 'NodeGoat OWASP Benchmark',
        repository_url: 'https://github.com/OWASP/NodeGoat',
        total_scans: 1,
        last_scan_status: 'COMPLETED',
        created_at: new Date(Date.now() - 2 * 24 * 3600 * 1000).toISOString()
    }
];

/**
 * GET /api/projects - List user's projects
 */
router.get('/', requireAuth, async (req, res) => {
    try {
        const userId = req.user.id;

        // Fetch user's projects from Supabase if configured
        let projects = [];
        if (isConfigured) {
            try {
                const { data: dbProjects, error } = await supabaseAdmin
                    .from('projects')
                    .select('*, scans(id, status, created_at, total_findings)')
                    .eq('user_id', userId)
                    .order('created_at', { ascending: false });

                if (!error && dbProjects) {
                    projects = dbProjects;
                }
            } catch (err) {}
        }

        // If in sandbox mode or no projects in DB, provide sandbox projects
        if (req.is_sandbox || req.user.is_sandbox || projects.length === 0) {
            const userSandboxProjects = sandboxProjectsStore.filter(
                p => p.user_id === userId || p.user_id === '00000000-0000-0000-0000-000000000001'
            );
            if (projects.length === 0) {
                projects = userSandboxProjects;
            }
        }

        // Format project statistics
        const formatted = projects.map(p => {
            const scans = p.scans || [];
            const latestScan = scans.length > 0 ? scans[0] : null;
            return {
                id: p.id,
                name: p.name,
                repository_url: p.repository_url,
                total_scans: p.total_scans !== undefined ? p.total_scans : scans.length,
                last_scan_status: p.last_scan_status || (latestScan ? latestScan.status : 'NONE'),
                created_at: p.created_at
            };
        });

        return res.status(200).json(formatted);
    } catch (err) {
        console.error('List projects error:', err);
        return res.status(500).json({ error: 'Internal server error fetching projects' });
    }
});

/**
 * POST /api/projects - Create a new project
 */
router.post('/', requireAuth, async (req, res) => {
    try {
        const { name, repository_url } = req.body;
        const userId = req.user.id;

        if (!name || !repository_url) {
            return res.status(400).json({ error: 'Project name and repository_url are required' });
        }

        const projectId = crypto.randomUUID();
        const newProject = {
            id: projectId,
            user_id: userId,
            name: name.trim(),
            repository_url: repository_url.trim(),
            created_at: new Date().toISOString()
        };

        // Try inserting into Supabase if configured
        let savedProject = null;
        if (isConfigured) {
            try {
                const { data, error } = await supabaseAdmin
                    .from('projects')
                    .insert([newProject])
                    .select()
                    .single();

                if (!error && data) {
                    savedProject = data;
                } else if (error) {
                    console.warn('[Projects] DB insert notice (fallback to memory for sandbox):', error.message);
                }
            } catch (dbErr) {
                console.warn('[Projects] DB insert exception:', dbErr.message);
            }
        }

        // If DB didn't save (e.g. sandbox foreign key or mock DB), store in sandboxProjectsStore
        if (!savedProject) {
            sandboxProjectsStore.unshift(newProject);
            savedProject = newProject;
        }

        return res.status(201).json({
            message: 'Project created successfully',
            project: savedProject
        });
    } catch (err) {
        console.error('Create project error:', err);
        return res.status(500).json({ error: 'Internal server error creating project' });
    }
});

module.exports = router;
module.exports.sandboxProjectsStore = sandboxProjectsStore;
