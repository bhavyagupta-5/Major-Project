const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Ensure Node.js 20 compatibility for Supabase Realtime Client
if (typeof globalThis.WebSocket === 'undefined') {
    globalThis.WebSocket = class DummyWebSocket {
        constructor() {}
        addEventListener() {}
        removeEventListener() {}
        send() {}
        close() {}
    };
}

let supabaseUrl = process.env.SUPABASE_URL;
let supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const isConfigured = supabaseUrl && supabaseUrl !== 'your_supabase_url' && supabaseKey && supabaseKey !== 'your_supabase_anon_key';

if (!isConfigured) {
    console.warn("\n⚠️  [AURIX Backend Notice]: SUPABASE_URL or SUPABASE_ANON_KEY is not yet configured in .env.");
    console.warn("   Running in Sandbox / Demo Fallback Mode. Database writes and auth will operate safely with in-memory fallbacks.\n");
    supabaseUrl = supabaseUrl && supabaseUrl !== 'your_supabase_url' ? supabaseUrl : 'https://placeholder-aurix-demo.supabase.co';
    supabaseKey = supabaseKey && supabaseKey !== 'your_supabase_anon_key' ? supabaseKey : 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_anon_key';
}

const clientOptions = {
    auth: {
        persistSession: false,
        autoRefreshToken: false
    }
};

const supabase = createClient(supabaseUrl, supabaseKey, clientOptions);

const supabaseAdmin = supabaseServiceKey && supabaseServiceKey !== 'your_supabase_service_role_key'
    ? createClient(supabaseUrl, supabaseServiceKey, clientOptions) 
    : supabase;

module.exports = { supabase, supabaseAdmin, isConfigured };
