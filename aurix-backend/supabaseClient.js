const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || supabaseUrl === 'your_supabase_url') {
    throw new Error("\n\n❌ ERROR: You haven't added your real Supabase URL to the .env file yet!\nOpen aurix-backend/.env and replace 'your_supabase_url' with your actual project URL from the Supabase dashboard (it should look like https://xxxxxx.supabase.co).\n\n");
}

if (!supabaseUrl || !supabaseKey) {
    console.warn("Missing SUPABASE_URL or SUPABASE_ANON_KEY in environment variables.");
}

const supabase = createClient(supabaseUrl, supabaseKey);

const supabaseAdmin = supabaseServiceKey 
    ? createClient(supabaseUrl, supabaseServiceKey) 
    : supabase;

module.exports = { supabase, supabaseAdmin };
