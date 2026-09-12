const { supabase } = require('../supabaseClient');

const SANDBOX_USER = {
    id: 'bd85429f-232c-4671-9612-851c20cfb9dd',
    aud: 'authenticated',
    role: 'authenticated',
    email: 'sandbox.auditor@aurix.local',
    app_metadata: { provider: 'sandbox', providers: ['sandbox'] },
    user_metadata: {
        full_name: 'Demo Auditor',
        name: 'Demo Auditor',
        role: 'auditor',
        avatar_url: 'https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=100&auto=format&fit=crop&q=60',
        is_sandbox: true
    },
    is_sandbox: true
};

const requireAuth = async (req, res, next) => {
    const isStrictMode = process.env.STRICT_AUTH === 'true';
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        if (!isStrictMode) {
            req.user = SANDBOX_USER;
            req.is_sandbox = true;
            return next();
        }
        return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    const token = authHeader.split(' ')[1];

    if (token === 'aurix-sandbox-demo-token' || token.toLowerCase().startsWith('sandbox') || token === 'demo-token') {
        req.user = SANDBOX_USER;
        req.is_sandbox = true;
        return next();
    }

    try {
        const { data: { user }, error } = await supabase.auth.getUser(token);

        if (!error && user) {
            req.user = user;
            req.is_sandbox = false;
            return next();
        }

        if (!isStrictMode) {
            console.warn(`[Auth Warning] Token validation failed (${error?.message || 'user not found'}). Falling back to Sandbox demo session.`);
            req.user = SANDBOX_USER;
            req.is_sandbox = true;
            return next();
        }

        return res.status(401).json({ error: 'Invalid or expired token' });
    } catch (err) {
        console.error('[Auth Error] Supabase auth exception:', err);
        if (!isStrictMode) {
            req.user = SANDBOX_USER;
            req.is_sandbox = true;
            return next();
        }
        return res.status(401).json({ error: 'Authentication verification failed' });
    }
};

module.exports = requireAuth;
module.exports.SANDBOX_USER = SANDBOX_USER;
