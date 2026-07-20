CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE PROJECTS (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    repository_url TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TYPE scan_status AS ENUM ('PENDING', 'SCANNING', 'COMPLETED', 'FAILED');

CREATE TABLE SCANS (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    project_id UUID REFERENCES PROJECTS(id) ON DELETE CASCADE,
    user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    status scan_status DEFAULT 'PENDING',
    storage_path TEXT,
    total_findings INTEGER DEFAULT 0,
    neutralized_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

CREATE TABLE VERIFIED_VULNERABILITIES (
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
    is_resolved BOOLEAN DEFAULT false
);

CREATE TABLE THREAT_INTELLIGENCE (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    title TEXT,
    content TEXT,
    metadata JSONB,
    embedding VECTOR(384)
);

ALTER TABLE PROJECTS ENABLE ROW LEVEL SECURITY;
ALTER TABLE SCANS ENABLE ROW LEVEL SECURITY;
ALTER TABLE VERIFIED_VULNERABILITIES ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own projects" ON PROJECTS
    FOR SELECT USING (auth.uid() = user_id);
    
CREATE POLICY "Users can insert their own projects" ON PROJECTS
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can view their own scans" ON SCANS
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY "Users can insert their own scans" ON SCANS
    FOR INSERT WITH CHECK (auth.uid() = user_id);
    
CREATE POLICY "Users can update their own scans" ON SCANS
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY "Users can view their own vulnerabilities" ON VERIFIED_VULNERABILITIES
    FOR SELECT USING (
        scan_id IN (SELECT id FROM SCANS WHERE user_id = auth.uid())
    );

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
