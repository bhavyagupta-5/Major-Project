# 🔐 AURIX: GitHub OAuth & Supabase Dashboard Configuration Guide

This guide walks you step-by-step through configuring **GitHub OAuth Developer Settings**, enabling the GitHub provider in the **Supabase Dashboard**, setting up **Redirect URLs**, and executing the **Database Migration**.

---

## 🛠️ Step 1: Create a GitHub OAuth Application

To allow users to log in with GitHub and grant AURIX permission to scan repositories and create Pull Requests:

1. Log into your GitHub account and navigate to:
   👉 **[GitHub Developer Settings > OAuth Apps](https://github.com/settings/developers)**
2. Click the **New OAuth App** button (or **Register a new application**).
3. Fill in the application form with the following details:

| Field | Value | Notes |
|---|---|---|
| **Application name** | `AURIX Security Platform` | Name displayed to users on the GitHub authorization screen |
| **Homepage URL** | `http://localhost:5173` *(or your production frontend URL)* | The main landing page of the AURIX dashboard |
| **Application description** | `Autonomous AI-Powered SAST & Vulnerability Remediation Platform` | (Optional) Description of the platform |
| **Authorization callback URL** | `https://<YOUR-SUPABASE-PROJECT-REF>.supabase.co/auth/v1/callback` | **CRITICAL:** Copy this exact Callback URL from your Supabase Dashboard (see Step 2 below) |

4. Click **Register application**.
5. On the application details page:
   - Copy your **Client ID** (e.g., `Iv1.8a2b3c4d5e6f7g8h`).
   - Under **Client secrets**, click **Generate a new client secret**.
   - Copy the generated **Client Secret** immediately (you will not be able to view it again).

---

## ⚡ Step 2: Enable GitHub Provider in Supabase Dashboard

1. Open your project on the **[Supabase Dashboard](https://supabase.com/dashboard)**.
2. In the left navigation menu, go to **Authentication** > **Providers**.
3. Locate **GitHub** in the list and toggle it to **Enabled**.
4. Fill in the fields:
   - **Client ID (for OAuth)**: Paste the Client ID copied from GitHub.
   - **Client Secret (for OAuth)**: Paste the Client Secret copied from GitHub.
   - **Scopes**: Ensure the following scopes are included:
     ```text
     repo, read:user, user:email
     ```
     *(The `repo` scope is required so AURIX can inspect repositories and push remediation Pull Requests).*
5. Note the **Callback URL (for OAuth)** displayed in this panel:
   `https://<project-ref>.supabase.co/auth/v1/callback`
   *(Ensure this matches the Authorization callback URL in your GitHub OAuth App from Step 1).*
6. Click **Save**.

---

## 🌐 Step 3: Configure Supabase Redirect URLs

To ensure redirect security and prevent open redirect vulnerabilities:

1. In the Supabase Dashboard, navigate to **Authentication** > **URL Configuration**.
2. **Site URL**: Set to your frontend base URL:
   ```text
   http://localhost:5173
   ```
3. **Redirect URLs (Allow list)**: Click **Add URL** and add the following patterns:
   - `http://localhost:5173/**`
   - `http://localhost:3000/**`
   - `http://localhost:5173/auth/callback`
   - `vscode://aurix.aurix-vscode-extension/**` *(for the VS Code extension)*
4. Click **Save**.

---

## 🗄️ Step 4: Execute Database Schema & RAG Permissions in Supabase SQL Editor

Open **SQL Editor** in the Supabase Dashboard, click **New query**, paste the following script, and click **Run**:

```sql
-- 1. Ensure pgvector and uuid extensions are active
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Create Public PROFILES Table linked to auth.users
CREATE TABLE IF NOT EXISTS public.PROFILES (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    full_name TEXT,
    avatar_url TEXT,
    role TEXT DEFAULT 'auditor',
    github_username TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- Enable RLS on Profiles
ALTER TABLE public.PROFILES ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own profile" ON public.PROFILES;
CREATE POLICY "Users can view their own profile" ON public.PROFILES
    FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update their own profile" ON public.PROFILES;
CREATE POLICY "Users can update their own profile" ON public.PROFILES
    FOR UPDATE USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can insert their own profile" ON public.PROFILES;
CREATE POLICY "Users can insert their own profile" ON public.PROFILES
    FOR INSERT WITH CHECK (auth.uid() = id);

-- 3. Automatic Profile Creation Trigger on User Signup / OAuth Login
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.PROFILES (id, email, full_name, avatar_url, github_username, role)
    VALUES (
        NEW.id,
        NEW.email,
        COALESCE(NEW.raw_user_meta_data->>'full_name', NEW.raw_user_meta_data->>'name', split_part(NEW.email, '@', 1)),
        COALESCE(NEW.raw_user_meta_data->>'avatar_url', ''),
        COALESCE(NEW.raw_user_meta_data->>'user_name', NEW.raw_user_meta_data->>'preferred_username', ''),
        COALESCE(NEW.raw_user_meta_data->>'role', 'auditor')
    )
    ON CONFLICT (id) DO UPDATE
    SET 
        email = EXCLUDED.email,
        full_name = EXCLUDED.full_name,
        avatar_url = EXCLUDED.avatar_url,
        updated_at = timezone('utc'::text, now());
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- 4. RAG Vector Permissions Grant (Requirement 9)
GRANT ALL ON TABLE THREAT_INTELLIGENCE TO service_role, anon, authenticated;
```

---

## 🚀 Step 5: How Frontend Initiates GitHub Login

In the frontend React/Next.js application, users can authenticate via GitHub using either of these methods:

### Method A: Via AURIX Backend API Gateway
```javascript
// 1. Fetch GitHub OAuth URL from backend
const response = await fetch('http://localhost:3000/api/auth/github');
const { url } = await response.json();

// 2. Redirect user to GitHub consent screen
window.location.href = url;
```

### Method B: Directly via Supabase JS SDK
```javascript
import { createClient } from '@supabase/supabase-js';
const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

const { data, error } = await supabase.auth.signInWithOAuth({
  provider: 'github',
  options: {
    redirectTo: `${window.location.origin}/auth/callback`,
    scopes: 'repo read:user user:email'
  }
});
```

When GitHub redirects back to `/auth/callback`, the Supabase client automatically captures the JWT session token, which you attach to backend API requests in the `Authorization: Bearer <token>` header.
