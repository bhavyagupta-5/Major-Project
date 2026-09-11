const express = require('express');
const router = express.Router();
const { supabase, supabaseAdmin, isConfigured } = require('../supabaseClient');
const requireAuth = require('../middleware/auth');
const { SANDBOX_USER } = require('../middleware/auth');

router.post('/signup', async (req, res) => {
    try {
        const { email, password, full_name, role } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!isConfigured) {
            return res.status(201).json({
                message: 'Registration successful (Sandbox Mode)',
                user: { ...SANDBOX_USER, email, user_metadata: { full_name, role: role || 'auditor' } },
                session: { access_token: 'aurix-sandbox-demo-token' },
                token: 'aurix-sandbox-demo-token'
            });
        }

        const { data: adminData, error: adminError } = await supabaseAdmin.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
            user_metadata: {
                full_name: full_name || email.split('@')[0],
                role: role || 'auditor'
            }
        });

        if (adminError) {
            return res.status(400).json({ error: adminError.message });
        }

        const createdUser = adminData.user;

        if (createdUser) {
            try {
                await supabaseAdmin
                    .from('profiles')
                    .upsert({
                        id: createdUser.id,
                        email: createdUser.email,
                        full_name: full_name || email.split('@')[0],
                        role: role || 'auditor',
                        updated_at: new Date().toISOString()
                    });
            } catch (pErr) {}
        }

        const { data: sessionData } = await supabaseAdmin.auth.admin.generateLink({
            type: 'magiclink',
            email
        });

        const { data: loginData, error: loginError } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        return res.status(201).json({
            message: 'Registration successful',
            user: createdUser,
            session: loginData?.session || null,
            token: loginData?.session?.access_token || null
        });
    } catch (err) {
        console.error('Signup error:', err);
        return res.status(500).json({ error: 'Internal server error during registration' });
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (!isConfigured) {
            return res.status(200).json({
                message: 'Login successful (Sandbox Mode)',
                user: { ...SANDBOX_USER, email },
                session: { access_token: 'aurix-sandbox-demo-token' },
                token: 'aurix-sandbox-demo-token'
            });
        }

        const { data, error } = await supabase.auth.signInWithPassword({
            email,
            password
        });

        if (error) {
            return res.status(401).json({ error: error.message });
        }

        return res.status(200).json({
            message: 'Login successful',
            user: data.user,
            session: data.session,
            token: data.session?.access_token
        });
    } catch (err) {
        console.error('Login error:', err);
        return res.status(500).json({ error: 'Internal server error during login' });
    }
});

router.post('/forgot-password', async (req, res) => {
    try {
        const { email, redirectTo } = req.body;

        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
            redirectTo: redirectTo || `${process.env.FRONTEND_URL || 'http://localhost:5173'}/reset-password`
        });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        return res.status(200).json({
            message: 'Password reset link sent to your email address',
            data
        });
    } catch (err) {
        console.error('Forgot password error:', err);
        return res.status(500).json({ error: 'Internal server error processing password recovery' });
    }
});

router.post('/reset-password', async (req, res) => {
    try {
        const { password, access_token } = req.body;

        if (!password) {
            return res.status(400).json({ error: 'New password is required' });
        }

        const authHeader = req.headers.authorization;
        const token = access_token || (authHeader && authHeader.startsWith('Bearer ') ? authHeader.split(' ')[1] : null);

        if (!token) {
            return res.status(401).json({ error: 'Missing recovery authorization token' });
        }

        const { data: { user }, error: userError } = await supabase.auth.getUser(token);
        if (userError || !user) {
            return res.status(401).json({ error: 'Invalid or expired password reset token' });
        }

        const { data, error } = await supabaseAdmin.auth.admin.updateUserById(user.id, { password });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        return res.status(200).json({
            message: 'Password updated successfully. You can now login with your new credentials.'
        });
    } catch (err) {
        console.error('Reset password error:', err);
        return res.status(500).json({ error: 'Internal server error updating password' });
    }
});

router.get('/github', async (req, res) => {
    try {
        const redirectTo = req.query.redirectTo || `${process.env.FRONTEND_URL || 'http://localhost:5173'}/auth/callback`;
        const autoRedirect = req.query.redirect === 'true';

        const { data, error } = await supabase.auth.signInWithOAuth({
            provider: 'github',
            options: {
                redirectTo,
                scopes: 'repo read:user user:email'
            }
        });

        if (error) {
            return res.status(400).json({ error: error.message });
        }

        if (autoRedirect && data.url) {
            return res.redirect(data.url);
        }

        return res.status(200).json({
            provider: 'github',
            url: data.url,
            redirectTo
        });
    } catch (err) {
        console.error('GitHub OAuth error:', err);
        return res.status(500).json({ error: 'Internal server error initiating GitHub OAuth' });
    }
});

router.post('/sandbox', (req, res) => {
    return res.status(200).json({
        message: 'Sandbox demo auditor session generated successfully',
        token: 'aurix-sandbox-demo-token',
        user: SANDBOX_USER,
        profile: {
            id: SANDBOX_USER.id,
            email: SANDBOX_USER.email,
            full_name: 'Demo Auditor',
            role: 'auditor',
            avatar_url: SANDBOX_USER.user_metadata.avatar_url,
            is_sandbox: true
        }
    });
});

router.get('/me', requireAuth, async (req, res) => {
    try {
        if (!isConfigured || req.is_sandbox || req.user.is_sandbox) {
            return res.status(200).json({
                user: req.user,
                profile: {
                    id: req.user.id,
                    email: req.user.email,
                    full_name: req.user.user_metadata?.full_name || 'Demo Auditor',
                    role: req.user.user_metadata?.role || 'auditor',
                    avatar_url: req.user.user_metadata?.avatar_url || '',
                    is_sandbox: true
                }
            });
        }

        const { data: profile, error } = await supabaseAdmin
            .from('profiles')
            .select('*')
            .eq('id', req.user.id)
            .single();

        return res.status(200).json({
            user: req.user,
            profile: profile || {
                id: req.user.id,
                email: req.user.email,
                full_name: req.user.user_metadata?.full_name || req.user.email.split('@')[0],
                role: 'auditor',
                avatar_url: req.user.user_metadata?.avatar_url || ''
            }
        });
    } catch (err) {
        console.error('Fetch me error:', err);
        return res.status(500).json({ error: 'Internal server error fetching user profile' });
    }
});

router.post('/logout', async (req, res) => {
    try {
        await supabase.auth.signOut();
        return res.status(200).json({ message: 'Logged out successfully' });
    } catch (err) {
        console.error('Logout error:', err);
        return res.status(200).json({ message: 'Logged out successfully' });
    }
});

module.exports = router;
