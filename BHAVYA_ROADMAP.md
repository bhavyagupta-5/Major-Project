# AURIX Backend & Infrastructure Engineer (Bhavya) - Workflow & Roadmap

Welcome to your role as the "Traffic Cop", "Vault", and Nervous System of the AURIX platform. Based on the documentation, you are building a Node.js/Express backend that sits between the Frontend (Bhumika), the VS Code Extension (Divyanshi), and the AI Worker Node (Divyansh).

Here is your comprehensive step-by-step workflow. 

---

## 🚨 IMMEDIATE PRIORITY: Unblock Your Teammates (The "Mock" Endpoints)
Your teammates cannot build their interfaces without your API endpoints. 

**Task:** Deploy a mock Node.js/Express server to Render/Railway immediately.
1. `POST /api/scans/github` - Return `202 Accepted` with a fake `scan_id`.
2. `POST /api/scans/upload` - Return `202 Accepted` with a fake `scan_id`.
3. `GET /api/scans/{scan_id}` - Return a hardcoded JSON response matching the **API Contract** (e.g., using the `verified_report.json` structure).
4. **Deploy** and share the URL.

---

## Phase 1: Infrastructure Provisioning & Database Schema
Once teammates are unblocked, set up the real infrastructure.

1. **Cloud Services Setup:**
   - **Supabase (Free Tier):** Create a project for PostgreSQL, Storage (S3-compatible), and Auth.
   - **Upstash (Serverless Redis):** Create a Redis database for task queuing and rate limiting.
2. **Database Schema (PostgreSQL):**
   - Create tables matching the ERD and API Contract:
     - `USERS` (linked to Supabase Auth UUIDs)
     - `PROJECTS` (`id`, `user_id`, `name`, `repository_url`, `created_at`)
     - `SCANS` (`id`, `project_id`, `status`, `storage_path`, `total_findings`, etc.)
     - `VERIFIED_VULNERABILITIES` (Detailed findings fields: `rule_id`, `severity`, `ai_reasoning`, `poc_script`, `patch_code`, etc.)

---

## Phase 2: Core API Gateway Implementation
Replace the mock endpoints with real business logic.

1. **Authentication ("The Vault"):**
   - Configure Supabase Auth (Email/Password or GitHub OAuth).
   - Implement JWT validation middleware in Express to protect endpoints.
   - Enforce Row Level Security (RLS) or backend validation so users only see their own scans.
2. **Core Ingestion Routes:**
   - `POST /api/scans/github`: Save project to DB, set status to `PENDING`, push GitHub URL and `scan_id` to Upstash Redis queue, return `202 Accepted`.
   - `POST /api/scans/upload`: Safely stream `.zip` files (~10MB limit) directly to Supabase Storage using `multer`, save record, push storage link to Redis, return `202 Accepted`.
   - `GET /api/scans/{scan_id}`: Fetch real scan status and vulnerabilities from the DB.
   - **Constraint:** *Asynchronous Processing.* Never make the POST requests wait for the AI scan to finish.

---

## Phase 3: Webhook & AI Worker Integration
The AI Worker (AWS EC2) will pull from Redis, run the scan, and send results back to you.

1. **The Webhook Receiver:**
   - Create `POST /api/v1/scans/webhook` (or `/api/internal/webhook/scan-complete`).
   - Validate the `Authorization: Bearer aurix-dev-token` header to prevent fake reports.
   - Receive the massive JSON payload (scan ID, summary, and findings array).
   - Update `SCANS` table status to `COMPLETED`.
   - Save the `findings` array into the `VERIFIED_VULNERABILITIES` table (or a JSONB column).
   - Return `200 OK`.

---

## Phase 4: RAG Vector Infrastructure (The AI Upgrade)
You must build the retrieval system for the LangGraph AI agents to query OWASP guidelines and CVE templates.

1. **Vector Database Setup:**
   - Enable `pgvector` in Supabase (`CREATE EXTENSION vector;`).
   - Create a `knowledge_base` table with a `vector` column.
2. **Data Seeding Script (`seed_rag.js`):**
   - Write a Node.js script to ingest security docs (OWASP, Python/JS PoC templates).
   - Use an embedding model API (e.g., OpenAI `text-embedding-3-small`) to convert markdown chunks to vectors.
   - Push text and embeddings to Supabase.
3. **Similarity Search API (Threat Intel Endpoint):**
   - Create an internal API endpoint (or Supabase RPC) taking a search query (e.g., `rule_id`, `title`).
   - Perform cosine similarity search using `pgvector`.
   - Return the top 2-3 most relevant markdown chunks in **under 500ms**.

---

## Phase 5: Security & Optimization Constraints
Ensure the system is secure, compliant, and cost-effective.

1. **Rate Limiting:** Implement Redis-backed rate limiting (`express-rate-limit` + `rate-limit-redis`) to block runaway scripts from exhausting AI resources (Return `429 Too Many Requests`).
2. **Automated Data Sanitization:** Implement a cron job (`node-cron`) or Supabase Storage TTL to automatically **delete the `.zip` source code payload** once a scan is `COMPLETED` or `FAILED`. Keep only the vulnerability metadata.
