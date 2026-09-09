# Final Year Project - PROGRESS DIARY (BCS-753)

**Project Title:** AURIX: An Agentic Unified Risk Intelligence Platform with Autonomous Detection and Remediation
**Role:** Backend & Infrastructure Engineer (Layer 2 & RAG Vector Infrastructure)
**Student Name:** Bhavya Gupta
**Roll Number:** 2301641520064
**Branch & Section:** CS AI 3-A
**Supervisor Name:** Dr. Sunil Kumar Vishwakarma

---

## Week 1
**Work done in current Week:**
Provisioned the foundational cloud infrastructure using Supabase (Free Tier) and Upstash (Serverless Redis). Designed and executed the SQL schemas to create the core relational tables (`USERS`, `PROJECTS`, `SCANS`, and `VERIFIED_VULNERABILITIES`) mapping the ER diagram securely via Foreign Keys.
**Work to be done in next Week:** 
Configure Supabase Authentication and implement JWT validation middleware.

---

## Week 2
**Work done in current Week:**
Configured Supabase Authentication ("The Vault") using Email/Password and GitHub OAuth integrations. Implemented JWT validation middleware in the Node.js backend and enforced Row Level Security (RLS) policies in Supabase to ensure users can query and view only their own scan reports.
**Work to be done in next Week:** 
Initialize the Node.js Express API Gateway and deploy mock API endpoints.

---

## Week 3
**Work done in current Week:**
Initialized the Node.js Express server framework. Created mock API endpoints (`POST /api/scans/github` and `POST /api/scans/upload`) returning fake `scan_id`s and `202 Accepted` status codes to immediately unblock the frontend and VS Code extension teams. 
**Work to be done in next Week:** 
Implement the mock GET status endpoint and deploy the server publicly.

---

## Week 4
**Work done in current Week:**
Implemented the mock `GET /api/scans/{scan_id}` endpoint, configuring it to return a hardcoded JSON of vulnerabilities based precisely on the `verified_report.json` schema contract. Deployed this mock Express server to Render/Railway free tier to provide a live public URL for teammates.
**Work to be done in next Week:** 
Replace the mock GitHub ingestion route with real database and Redis logic.

---

## Week 5
**Work done in current Week:**
Replaced the mock `POST /api/scans/github` endpoint with real backend logic. Added functionality to save the project metadata to the Supabase DB with a `PENDING` status, push the GitHub URL job ticket into the Upstash Redis Queue (`LPUSH`), and instantly return a `202 Accepted` response to ensure asynchronous processing without HTTP timeouts.
**Work to be done in next Week:** 
Implement real multipart/form-data upload logic with Supabase Storage.

---

## Week 6
**Work done in current Week:**
Replaced the mock `POST /api/scans/upload` endpoint. Integrated the `multer` package to safely handle `multipart/form-data` streams and implemented the `@supabase/supabase-js` SDK to stream `.zip` source code payloads (~10MB limits) directly into Supabase Storage buckets without crashing the lightweight Render memory. Queued the storage link to Redis.
**Work to be done in next Week:** 
Implement the real database polling logic for the GET scan route.

---

## Week 7
**Work done in current Week:**
Replaced the mock `GET /api/scans/{scan_id}` endpoint. Added database queries to look up the scan in Supabase and return the current runtime status (e.g., `SCANNING`) or the final structured `VERIFIED_VULNERABILITIES` payload if the scan is `COMPLETED`.
**Work to be done in next Week:** 
Setup the `pgvector` database extension for the RAG infrastructure.

---

## Week 8
**Work done in current Week:**
Transitioned to Phase 3 (The AI Upgrade). Enabled the `pgvector` extension within the Supabase PostgreSQL database (`CREATE EXTENSION vector;`). Designed and created the `knowledge_base` table with a high-dimensional `vector` column to store embeddings for the RAG pipeline.
**Work to be done in next Week:** 
Develop the data seeding script (`seed_rag.js`) for OWASP security guidelines.

---

## Week 9
**Work done in current Week:**
Developed a standalone Node.js script (`seed_rag.js`) responsible for ingesting raw security documentation. Parsed various formats including OWASP Cheat Sheets, Vulnerability PoC templates for Python/JS, and Patch Code templates.
**Work to be done in next Week:** 
Integrate Hugging Face inference to convert the ingested docs into vector embeddings.

---

## Week 10
**Work done in current Week:**
Integrated free Hugging Face models (`all-MiniLM-L6-v2` via `Transformers.js`) into the `seed_rag.js` script. Successfully converted the raw markdown security chunks into vector embeddings and executed the script to push the text and their embeddings into the Supabase `knowledge_base` vector table.
**Work to be done in next Week:** 
Build the Similarity Search API (Threat Intel Endpoint) for the LangGraph node.

---

## Week 11
**Work done in current Week:**
Developed the Threat Intel Similarity Search API for the AI engine. Wrote a Supabase RPC function (Remote Procedure Call) that takes a vulnerability search query, converts it to an embedding, and performs a cosine similarity search against `pgvector`, returning the top 3 most relevant markdown chunks in under 500ms.
**Work to be done in next Week:** 
Create the internal webhook route to receive final payloads from the AI Worker.

---

## Week 12
**Work done in current Week:**
Transitioned to Phase 4 (Orchestration & Security). Created the internal `POST /api/internal/webhook/scan-complete` route. This webhook acts as the catch mechanism for the massive JSON payload generated and POSTed by the AWS AI Worker node upon completing a LangGraph execution.
**Work to be done in next Week:** 
Add database parsing and update logic within the webhook handler.

---

## Week 13
**Work done in current Week:**
Finalized the webhook parsing logic. Programmed the backend to extract the verified bugs payload, update the `SCANS` table status to `COMPLETED` or `FAILED`, and iterate through the findings to populate the `VERIFIED_VULNERABILITIES` table accurately.
**Work to be done in next Week:** 
Implement API rate limiting to protect the expensive AI compute resources.

---

## Week 14
**Work done in current Week:**
Implemented Redis-backed API Rate Limiting using the `express-rate-limit` and `rate-limit-redis` packages. Configured the middleware to restrict users to a maximum number of scans per hour, protecting against queue flooding and returning `429 Too Many Requests` when quotas are exceeded.
**Work to be done in next Week:** 
Implement automated data sanitization via background cron jobs.

---

## Week 15
**Work done in current Week:**
Implemented automated data sanitization using a `node-cron` scheduled job running on the server. The job queries for scans with `COMPLETED` or `FAILED` statuses and automatically deletes their uploaded `.zip` payload from Supabase Storage, preventing storage bloat and securing user code privacy.
**Work to be done in next Week:** 
Perform final end-to-end integration testing and platform optimizations.

---

## Week 16
**Work done in current Week:**
Conducted comprehensive end-to-end integration testing across the decoupled microservice architecture. Verified the asynchronous Redis queuing flow, the webhook handshakes with the AWS EC2 worker, and ensured the RAG vector retrieval latency remained under 500ms. Finalized the API Gateway deployment on the production host.
**Work to be done in next Week:** 
Compile the final project report and prepare the architecture presentation.
