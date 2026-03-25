# 🛡️ AI Secure Data Intelligence Platform

> **AI Gateway + Scanner + Log Analyzer + Risk Engine**  
> Built with FastAPI · Claude AI · Postman-ready API

---

## 📁 Project Structure

```
ai-secure-platform/
│
├── backend/
│   ├── __init__.py
│   ├── main.py              ← FastAPI app (all API logic here)
│   └── requirements.txt
│
├── frontend/
│   └── index.html           ← UI (open in browser — no build needed)
│
├── tests/
│   ├── test_main.py         ← Pytest suite (37 tests)
│   └── sample.log           ← Sample log file for Postman upload test
│
├── .vscode/
│   ├── launch.json          ← Press F5 to run server or tests
│   ├── settings.json
│   └── extensions.json
│
├── postman_collection.json  ← Import this into Postman
└── README.md
```

---

## ⚙️ Setup in VS Code (Step by Step)

### Step 1 — Open the project

```
File → Open Folder → select ai-secure-platform/
```

### Step 2 — Create virtual environment

Open the **VS Code Terminal** (`Ctrl + ~`) and run:

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r backend/requirements.txt
```

### Step 4 — Set your Anthropic API key

```bash
# Windows Command Prompt
set ANTHROPIC_API_KEY=sk-ant-your-key-here

# Windows PowerShell
$env:ANTHROPIC_API_KEY="sk-ant-your-key-here"

# macOS / Linux
export ANTHROPIC_API_KEY=sk-ant-your-key-here
```

> Or edit `.vscode/launch.json` and replace `PUT_YOUR_KEY_HERE` with your key.

### Step 5 — Run the server

**Option A — Terminal:**
```bash
uvicorn backend.main:app --reload --port 8000
```

**Option B — Press F5** in VS Code (select "▶ Run FastAPI Server" from dropdown)

✅ Server is running when you see:
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
```

### Step 6 — Open the frontend

Double-click `frontend/index.html` to open in your browser.  
The server URL is pre-filled as `http://127.0.0.1:8000` — click **Ping** to confirm connection.

---

## 🔌 Swagger UI (Auto-generated API Docs)

Open in browser: **http://127.0.0.1:8000/docs**

- All endpoints listed with request/response schemas
- Click **"Try it out"** on any endpoint to test directly in browser
- No Postman needed for quick tests

---

## 📮 Postman Setup

### Import the collection:
1. Open Postman
2. Click **Import** (top left)
3. Select `postman_collection.json`
4. The collection **"AI Secure Data Intelligence Platform"** will appear

### The collection includes:

| Folder | Requests |
|--------|----------|
| Status | Root info, Health check, List patterns |
| Analyze - Text | Clean text, PII-heavy text, SQL, Chat |
| Analyze - Logs | Full log (all risk types), Brute force, AWS+JWT |
| Analyze - Options | Test mask=false, block_high_risk=true, 400 error |
| Analyze - File Upload | Upload .log file via form-data |
| Analyze - Batch | 2-item batch, 3-type batch |

### Quick test in Postman:
1. Make sure the server is running on port 8000
2. Open **"Analyze Logs → Analyze Log - Credentials Exposed"**
3. Hit **Send**
4. You should get a `risk_level: "critical"` response

---

## 🌐 API Reference

### `POST /analyze`

**URL:** `http://127.0.0.1:8000/analyze`  
**Headers:** `Content-Type: application/json`

**Request body:**
```json
{
  "input_type": "log",
  "content": "password=admin123\napi_key=sk-prod-xyz\nFailed login attempt",
  "options": {
    "mask": true,
    "block_high_risk": false,
    "log_analysis": true
  }
}
```

**Response:**
```json
{
  "summary": "Log contains hardcoded credentials and brute force indicators.",
  "content_type": "log",
  "findings": [
    { "type": "password",  "label": "Password / Secret", "risk": "critical", "line": 1, "masked_value": "pa****23" },
    { "type": "api_key",   "label": "API Key",           "risk": "high",     "line": 2, "masked_value": "sk****yz" },
    { "type": "brute_force","label": "Brute Force Pattern","risk": "high",    "line": 3, "masked_value": null }
  ],
  "risk_score": 22,
  "risk_level": "critical",
  "action": "masked",
  "insights": [
    "Hardcoded password in log line 1 — rotate credentials immediately.",
    "API key exposed in plaintext — revoke and regenerate.",
    "Failed login pattern on line 3 suggests brute force activity."
  ],
  "masked_content": "pa****23\nsk****yz\nFailed login attempt",
  "processing_time_ms": 834,
  "total_lines_scanned": 3
}
```

---

### `POST /analyze/upload`

**URL:** `http://127.0.0.1:8000/analyze/upload`  
**Body:** `form-data`

| Key | Type | Value |
|-----|------|-------|
| `file` | File | select `tests/sample.log` |
| `mask` | Text | `true` |
| `block_high_risk` | Text | `false` |

---

### `GET /health`

Returns server status and configuration:
```json
{
  "status": "ok",
  "api_key_set": true,
  "ai_insights": "enabled",
  "detection_types": 12,
  "total_patterns": 20
}
```

---

### `GET /patterns`

Lists all detection categories with risk levels.

---

### `POST /analyze/batch`

Analyze up to 10 items in one request (array body).

---

## 🛡️ Detection Capabilities

| Type | Label | Risk Score |
|------|-------|-----------|
| `api_key` | API Key | High (6) |
| `password` | Password / Secret | Critical (10) |
| `jwt_token` | JWT Token | High (6) |
| `aws_credential` | AWS Credential | Critical (10) |
| `email` | Email Address | Low (1) |
| `phone` | Phone Number | Low (1) |
| `ip_address` | IP Address | Medium (3) |
| `credit_card` | Credit Card Number | Critical (10) |
| `ssn` | Social Security Number | Critical (10) |
| `stack_trace` | Stack Trace / Error Leak | Medium (3) |
| `brute_force` | Brute Force Pattern | High (6) |
| `debug_leak` | Debug Mode Leak | Medium (3) |

---

## 🧪 Running Tests

```bash
# From project root (with venv activated)
pytest tests/ -v

# With coverage report
pytest tests/ -v --tb=short
```

Expected: **37 tests pass**

---

## 🧱 Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend Framework | Python 3.11+, FastAPI, Pydantic v2 |
| AI Engine | Anthropic Claude Sonnet |
| Pattern Detection | Python `re` — 20+ regex patterns |
| Server | Uvicorn (ASGI) |
| Frontend | HTML5, CSS3, Vanilla JS — no framework, no build step |
| Testing | Pytest, HTTPX (FastAPI TestClient) |
| Dev Environment | VS Code + virtual environment |
| API Testing | Postman (collection included) |

---

## 🎯 Domain

**AI & Automation Testing + Software Development**

---

## 📋 Hackathon Submission Checklist

- ✅ Repository with complete source code
- ✅ README with clear setup instructions
- ✅ Working FastAPI backend (`/analyze`, `/analyze/upload`, `/analyze/batch`)
- ✅ Swagger UI auto-generated at `/docs`
- ✅ Postman collection (`postman_collection.json`) with 12 pre-built requests
- ✅ Frontend UI (single HTML file, no build needed)
- ✅ 37 automated tests
- ✅ Log analysis with line-level annotation
- ✅ AI insights via Claude
- ✅ Risk scoring engine
- ✅ Policy engine (mask / block / allow)
- ✅ Multi-input handling (text, log, SQL, chat, file upload)
- ✅ Batch endpoint
- ✅ VS Code launch configs (F5 to run)
