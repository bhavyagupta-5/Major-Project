CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS PROFILES (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT,
    full_name TEXT,
    avatar_url TEXT,
    role TEXT DEFAULT 'auditor',
    github_username TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE IF NOT EXISTS PROJECTS (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scan_status') THEN
        CREATE TYPE scan_status AS ENUM ('PENDING', 'SCANNING', 'COMPLETED', 'FAILED');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS SCANS (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID REFERENCES PROJECTS(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    status scan_status DEFAULT 'PENDING',
    storage_path TEXT,
    total_findings INTEGER DEFAULT 0,
    neutralized_count INTEGER DEFAULT 0,
    progress INTEGER DEFAULT 0,
    current_step TEXT DEFAULT 'Pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE IF NOT EXISTS VERIFIED_VULNERABILITIES (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    scan_id UUID REFERENCES SCANS(id) ON DELETE CASCADE,
    rule_id TEXT,
    tool TEXT,
    category TEXT,
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss FLOAT,
    file_path TEXT,
    line_number INTEGER,
    evidence TEXT,
    fix TEXT,
    verified BOOLEAN DEFAULT false,
    wargame_status TEXT,
    ai_reasoning TEXT,
    poc_script TEXT,
    patch_code TEXT,
    is_resolved BOOLEAN DEFAULT false,
    pr_url TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE IF NOT EXISTS THREAT_INTELLIGENCE (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title TEXT,
    content TEXT,
    metadata JSONB,
    embedding VECTOR(384)
);

ALTER TABLE PROFILES ENABLE ROW LEVEL SECURITY;
ALTER TABLE PROJECTS ENABLE ROW LEVEL SECURITY;
ALTER TABLE SCANS ENABLE ROW LEVEL SECURITY;
ALTER TABLE VERIFIED_VULNERABILITIES ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view their own profile" ON PROFILES;
CREATE POLICY "Users can view their own profile" ON PROFILES
    FOR SELECT USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can update their own profile" ON PROFILES;
CREATE POLICY "Users can update their own profile" ON PROFILES
    FOR UPDATE USING (auth.uid() = id);

DROP POLICY IF EXISTS "Users can insert their own profile" ON PROFILES;
CREATE POLICY "Users can insert their own profile" ON PROFILES
    FOR INSERT WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "Users can view their own projects" ON PROJECTS;
CREATE POLICY "Users can view their own projects" ON PROJECTS
    FOR SELECT USING (auth.uid() = user_id);
    
DROP POLICY IF EXISTS "Users can insert their own projects" ON PROJECTS;
CREATE POLICY "Users can insert their own projects" ON PROJECTS
    FOR INSERT WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can update their own projects" ON PROJECTS;
CREATE POLICY "Users can update their own projects" ON PROJECTS
    FOR UPDATE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can delete their own projects" ON PROJECTS;
CREATE POLICY "Users can delete their own projects" ON PROJECTS
    FOR DELETE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view their own scans" ON SCANS;
CREATE POLICY "Users can view their own scans" ON SCANS
    FOR SELECT USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can insert their own scans" ON SCANS;
CREATE POLICY "Users can insert their own scans" ON SCANS
    FOR INSERT WITH CHECK (auth.uid() = user_id);
    
DROP POLICY IF EXISTS "Users can update their own scans" ON SCANS;
CREATE POLICY "Users can update their own scans" ON SCANS
    FOR UPDATE USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can view their own vulnerabilities" ON VERIFIED_VULNERABILITIES;
CREATE POLICY "Users can view their own vulnerabilities" ON VERIFIED_VULNERABILITIES
    FOR SELECT USING (
        scan_id IN (SELECT id FROM SCANS WHERE user_id = auth.uid())
    );

DROP POLICY IF EXISTS "Users can update their own vulnerabilities" ON VERIFIED_VULNERABILITIES;
CREATE POLICY "Users can update their own vulnerabilities" ON VERIFIED_VULNERABILITIES
    FOR UPDATE USING (
        scan_id IN (SELECT id FROM SCANS WHERE user_id = auth.uid())
    );

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

CREATE OR REPLACE FUNCTION match_threat_intel (
  query_embedding vector(384),
  match_threshold float,
  match_count int
)
RETURNS TABLE (
  id uuid,
  title text,
  content text,
  metadata jsonb,
  similarity float
)
LANGUAGE plpgsql
AS $$
BEGIN
  RETURN QUERY
  SELECT
    ti.id,
    ti.title,
    ti.content,
    ti.metadata,
    1 - (ti.embedding <=> query_embedding) AS similarity
  FROM THREAT_INTELLIGENCE ti
  WHERE 1 - (ti.embedding <=> query_embedding) > match_threshold
  ORDER BY ti.embedding <=> query_embedding
  LIMIT match_count;
END;
$$;

GRANT ALL ON TABLE THREAT_INTELLIGENCE TO service_role, anon, authenticated;
