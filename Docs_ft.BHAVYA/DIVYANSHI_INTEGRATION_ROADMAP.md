# 🔌 VS Code Extension Integration Roadmap for Divyanshi

Welcome to the IDE-Backend Integration Guide! This document is prepared by Bhavya (Backend) to help you (Divyanshi) seamlessly connect your TypeScript VS Code Extension to the AURIX Backend API.

Because we are using a **Decoupled Microservice Architecture**, you do not need to worry about the AI worker, Docker, or PostgreSQL databases. You will solely interact with my API endpoints using standard HTTP requests.

Here is your exact integration roadmap:

---

## 🔐 Phase 1: Authentication (SecretStorage)

Every request to the backend must be authenticated. Since I have configured Supabase Auth in the backend, you will need to handle user logins and pass the Session Token (JWT).

1. **User Login**: You will build an `Aurix: Login` command that prompts the user for their credentials, hits Supabase/my backend to get an `access_token` (JWT).
2. **Store the Token**: Save this token securely using VS Code's native `SecretStorage` API so the user stays logged in across sessions.
3. **Attach to Headers**: For every API call you make to the backend, you must attach this token:
   ```json
   {
     "Authorization": "Bearer <YOUR_JWT_TOKEN>"
   }
   ```

---

## 📦 Phase 2: Zip & Ship Ingestion (The Hard Part)

When a developer clicks "Scan Workspace" (after your AI-Powered Secret Guard verifies no `.env` files are leaking), you will zip the local code and stream it to my backend.

**Endpoint**: `POST /api/scans/upload`
**Headers**: `Authorization: Bearer <JWT>`
**Content-Type**: `multipart/form-data`

**Form Data Requirements**:
- `source_code`: The `.zip` file buffer.
- `project_id`: The `<uuid-of-project>` string.

**What you will receive**:
The backend will stream the zip directly to Supabase Object Storage and return a `202 Accepted` response.
```json
{
  "scan_id": "a1b2c3d4-...",
  "status": "PENDING",
  "message": "Zip uploaded and scan queued successfully"
}
```
*Save the `scan_id`—you need it for the polling loop!*

---

## ⏳ Phase 3: The Polling Mechanism (VS Code Progress UI)

The AI takes 2-3 minutes to securely execute exploits and write patches. While the user waits, you need to show a dynamic progress bar in the bottom right corner of VS Code using `vscode.window.withProgress`.

**Endpoint**: `GET /api/scans/<scan_id>`
**Headers**: `Authorization: Bearer <JWT>`

**Your Task**: Write an async `setInterval` loop to hit this endpoint **every 5 seconds**.

**While Scanning (Keep Polling):**
```json
{
  "scan_id": "a1b2c3d4-...",
  "status": "PENDING" // (or SCANNING)
}
```

**When Finished (Stop Polling!):**
```json
{
  "scan_id": "a1b2c3d4-...",
  "status": "COMPLETED",
  "summary": { ... },
  "findings": [
    {
      "rule_id": "OWASP-A01",
      "severity": "CRITICAL",
      "category": "Authentication",
      "title": "Hardcoded Secret",
      "file_path": "src/auth.js",
      "line_number": 14,
      "ai_reasoning": "The secret is exposed in plaintext...",
      "patch_code": "const jwt_secret = process.env.JWT_SECRET;",
      "is_resolved": false
    }
  ]
}
```

---

## 👻 Phase 4: IDE Rendering & AI Upgrades

Once you receive the `COMPLETED` response with the `findings` array, you will inject this directly into the developer's editor:

1. **Diagnostics UI**: Use the `vscode.languages.createDiagnosticCollection` API to draw red squiggly lines on the exact `file_path` and `line_number` specified in the JSON.
2. **Attack Path Webview**: Build an HTML Webview Panel that triggers on hover to show the detailed `ai_reasoning`.
3. **"Ghost-Text" Inline Patching (Your AI Upgrade)**: 
   Instead of just blindly pasting code, use VS Code's **Inline Completion API** to stream the `patch_code` string directly into the developer's editor as grey "ghost text". The user can interactively review and accept the fix with the `Tab` key!

---

### 🛑 Critical Error Handling & Constraints
- **The Node_Modules Nuke**: Ensure you strictly parse `.gitignore` before zipping. If you upload a 500MB `node_modules` folder, my backend `multer` middleware will reject the file (I have a 10MB limit enforced) and crash your extension!
- **Preserve Paths**: If your zip logic flattens the file structure, the AI worker will return incorrect `file_path` variables, and your diagnostics will underline the wrong files.
- **Backend Failures**: If my API returns `status: "FAILED"`, gracefully kill your `withProgress` UI and show a standard VS Code Error Notification (`vscode.window.showErrorMessage`).

If you need any adjustments to the `multipart/form-data` setup or the JSON structure, just let me know!
- Bhavya
