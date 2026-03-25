"""
AI Secure Data Intelligence Platform  v2.0
==========================================
FastAPI Backend — AI Gateway + Scanner + Log Analyzer + Risk Engine

HOW TO RUN (from project root):
    uvicorn backend.main:app --reload --port 8000

SWAGGER DOCS (auto-generated, open in browser):
    http://127.0.0.1:8000/docs

POSTMAN: Import the collection from  postman_collection.json
"""

import re
import os
import json
import time
import logging
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import anthropic

# ──────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ai-secure")

# ──────────────────────────────────────────────────────────────
# App
# ──────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI Secure Data Intelligence Platform",
    description=(
        "### AI Gateway · Scanner · Log Analyzer · Risk Engine\n\n"
        "Detects secrets, PII, and security anomalies in text, logs, SQL, "
        "and uploaded files — powered by Claude AI.\n\n"
        "**All endpoints can be tested here or via Postman.**"
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allows frontend at any localhost port
    allow_methods=["*"],
    allow_headers=["*"],
)

# Anthropic client — reads ANTHROPIC_API_KEY from environment
_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
client = anthropic.Anthropic(api_key=_api_key) if _api_key else None


# ──────────────────────────────────────────────────────────────
# Detection Pattern Library
# ──────────────────────────────────────────────────────────────
RISK_PATTERNS: Dict[str, Dict] = {
    "api_key": {
        "label": "API Key",
        "risk": "high",
        "patterns": [
            r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\w\-\.]{16,}",
            r"sk-[a-zA-Z0-9]{20,}",
            r"ghp_[a-zA-Z0-9]{36}",
            r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
        ],
    },
    "password": {
        "label": "Password / Secret",
        "risk": "critical",
        "patterns": [
            r"(?i)password\s*[=:]\s*\S+",
            r"(?i)passwd\s*[=:]\s*\S+",
            r"(?i)pwd\s*[=:]\s*\S+",
            r"(?i)secret\s*[=:]\s*\S+",
        ],
    },
    "jwt_token": {
        "label": "JWT Token",
        "risk": "high",
        "patterns": [r"eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"],
    },
    "aws_credential": {
        "label": "AWS Credential",
        "risk": "critical",
        "patterns": [
            r"AKIA[0-9A-Z]{16}",
            r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*\S+",
        ],
    },
    "email": {
        "label": "Email Address",
        "risk": "low",
        "patterns": [r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"],
    },
    "phone": {
        "label": "Phone Number",
        "risk": "low",
        "patterns": [r"\b(\d{3}[-.\s]?)(\d{3}[-.\s]?)(\d{4})\b"],
    },
    "ip_address": {
        "label": "IP Address",
        "risk": "medium",
        "patterns": [
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ],
    },
    "credit_card": {
        "label": "Credit Card Number",
        "risk": "critical",
        "patterns": [r"\b(?:\d[ -]?){13,19}\b"],
    },
    "ssn": {
        "label": "Social Security Number",
        "risk": "critical",
        "patterns": [r"\b\d{3}-\d{2}-\d{4}\b"],
    },
    "stack_trace": {
        "label": "Stack Trace / Error Leak",
        "risk": "medium",
        "patterns": [
            r"(?i)(exception|traceback|stack\s*trace)",
            r"at\s+[\w\.]+\([\w\.]+:\d+\)",
        ],
    },
    "brute_force": {
        "label": "Brute Force Pattern",
        "risk": "high",
        "patterns": [
            r"(?i)(failed login|authentication failed|invalid password|unauthorized)"
        ],
    },
    "debug_leak": {
        "label": "Debug Mode Leak",
        "risk": "medium",
        "patterns": [r"(?i)(debug\s*=\s*true|verbose[_\-]?logging\s*=\s*true)"],
    },
}

SCORE = {"low": 1, "medium": 3, "high": 6, "critical": 10}


# ──────────────────────────────────────────────────────────────
# Pydantic Models
# ──────────────────────────────────────────────────────────────
class AnalysisOptions(BaseModel):
    mask: bool = Field(True, description="Mask sensitive values in output")
    block_high_risk: bool = Field(False, description="Block content if risk is high/critical")
    log_analysis: bool = Field(True, description="Enable log-specific detection")


class AnalyzeRequest(BaseModel):
    input_type: str = Field(..., examples=["log"], description="text | log | sql | chat | file")
    content: str = Field(..., description="Raw content to analyze")
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)

    model_config = {
        "json_schema_extra": {
            "examples": [{
                "input_type": "log",
                "content": "2026-03-10 INFO email=admin@corp.com\npassword=admin123\napi_key=sk-prod-xyz123456789012345678\nERROR NullPointerException at service.java:45\nFailed login attempt for user root",
                "options": {"mask": True, "block_high_risk": False}
            }]
        }
    }


class Finding(BaseModel):
    type: str
    label: str
    risk: str
    line: Optional[int] = None
    masked_value: Optional[str] = None


class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: str
    action: str
    insights: List[str]
    masked_content: Optional[str] = None
    processing_time_ms: int
    total_lines_scanned: int


# ──────────────────────────────────────────────────────────────
# Engine
# ──────────────────────────────────────────────────────────────
def mask_value(v: str) -> str:
    if len(v) <= 4:
        return "****"
    return v[:2] + "*" * max(4, len(v) - 4) + v[-2:]


def classify_risk(score: int) -> str:
    if score == 0:  return "safe"
    if score <= 3:  return "low"
    if score <= 8:  return "medium"
    if score <= 15: return "high"
    return "critical"


def detect(content: str, mask: bool = True):
    lines = content.split("\n")
    findings: List[Finding] = []
    total = 0
    masked = content

    for key, info in RISK_PATTERNS.items():
        for pattern in info["patterns"]:
            for ln, line in enumerate(lines, 1):
                for m in re.finditer(pattern, line):
                    raw = m.group(0)
                    mv  = mask_value(raw)
                    if not any(f.type == key and f.line == ln for f in findings):
                        findings.append(Finding(type=key, label=info["label"],
                                                 risk=info["risk"], line=ln, masked_value=mv))
                        total += SCORE[info["risk"]]
                    if mask:
                        masked = masked.replace(raw, mv, 1)

    return findings, masked, total, len(lines)


def ai_insights(content: str, findings: List[Finding], itype: str):
    if not client:
        return _fallback(findings)

    summary_list = "\n".join(
        f"- {f.label} ({f.risk}) line {f.line}" for f in findings[:20]
    ) or "None detected."

    prompt = f"""You are a senior cybersecurity analyst.
Analyze this {itype} content and its detected findings.

CONTENT (first 3000 chars):
{content[:3000]}

DETECTED FINDINGS:
{summary_list}

Respond ONLY with valid JSON — no markdown fences, no extra text:
{{"summary": "One factual sentence.", "insights": ["Insight 1", "Insight 2"]}}

Rules:
- summary: 1-2 sentences, security-focused, references actual content
- insights: 2-5 specific, actionable observations — not generic boilerplate
"""
    try:
        r = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        txt = r.content[0].text.strip()
        txt = re.sub(r"^```json\s*", "", txt)
        txt = re.sub(r"\s*```$", "", txt)
        p = json.loads(txt)
        return p.get("summary", "Done."), p.get("insights", [])
    except Exception as e:
        log.error(f"Claude error: {e}")
        return _fallback(findings)


def _fallback(findings):
    if not findings:
        return "No significant security issues detected.", ["Content appears clean."]
    top = sorted(findings, key=lambda f: SCORE[f.risk], reverse=True)
    return (
        f"{len(findings)} finding(s) detected. Top risk: {top[0].label} ({top[0].risk}).",
        [f"{f.label} at line {f.line} — {f.risk} risk." for f in top[:4]],
    )


# ──────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────
@app.get("/", tags=["Status"], summary="Service info")
def root():
    return {
        "service": "AI Secure Data Intelligence Platform",
        "version": "2.0.0",
        "swagger_ui": "http://127.0.0.1:8000/docs",
        "endpoints": {
            "GET  /health":          "Health + config check",
            "GET  /patterns":        "All detection patterns",
            "POST /analyze":         "Analyze text / log / SQL / chat",
            "POST /analyze/upload":  "Upload a file",
            "POST /analyze/batch":   "Analyze up to 10 items at once",
        },
    }


@app.get("/health", tags=["Status"], summary="Health check")
def health():
    return {
        "status": "ok",
        "api_key_set": bool(_api_key),
        "ai_insights": "enabled" if _api_key else "disabled — set ANTHROPIC_API_KEY",
        "detection_types": len(RISK_PATTERNS),
        "total_patterns": sum(len(v["patterns"]) for v in RISK_PATTERNS.values()),
    }


@app.get("/patterns", tags=["Config"], summary="All detection patterns")
def patterns():
    return {
        k: {"label": v["label"], "risk": v["risk"], "score": SCORE[v["risk"]]}
        for k, v in RISK_PATTERNS.items()
    }


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["Analysis"],
    summary="Analyze text, log, SQL, or chat content",
)
def analyze(req: AnalyzeRequest):
    """
    ## Main Analysis Endpoint

    Send any text-based content and get back:
    - Detected findings with line numbers
    - Risk score and level
    - Masked content (if `mask: true`)
    - AI-generated security insights

    ### Postman — Body (raw JSON):
    ```json
    {
      "input_type": "log",
      "content": "password=admin123\\napi_key=sk-prod-xyz\\nFailed login",
      "options": { "mask": true, "block_high_risk": false }
    }
    ```
    """
    t0 = time.time()

    content = req.content.strip()
    if not content:
        raise HTTPException(400, "'content' must not be empty.")
    if len(content) > 500_000:
        raise HTTPException(413, "Content exceeds 500 KB limit.")

    findings, masked, score, lines = detect(content, mask=req.options.mask)
    risk_level = classify_risk(score)

    if req.options.block_high_risk and risk_level in ("high", "critical"):
        action = "blocked"
    elif req.options.mask and findings:
        action = "masked"
    else:
        action = "allowed"

    summary, insights = ai_insights(content, findings, req.input_type)
    ms = int((time.time() - t0) * 1000)

    log.info(f"[{req.input_type.upper()}] score={score} level={risk_level} "
             f"findings={len(findings)} action={action} ms={ms}")

    return AnalyzeResponse(
        summary=summary,
        content_type=req.input_type,
        findings=findings,
        risk_score=score,
        risk_level=risk_level,
        action=action,
        insights=insights,
        masked_content=masked if req.options.mask else None,
        processing_time_ms=ms,
        total_lines_scanned=lines,
    )


@app.post("/analyze/upload", tags=["Analysis"], summary="Upload a file for analysis")
async def analyze_upload(
    file: UploadFile = File(..., description=".log / .txt / .sql / .csv / .json"),
    mask: bool = Form(True),
    block_high_risk: bool = Form(False),
):
    """
    ## File Upload Analysis

    ### How to test in Postman:
    1. Method: **POST**
    2. URL: `http://127.0.0.1:8000/analyze/upload`
    3. Body → **form-data**
       - Key `file` → Type: **File** → select your `.log` file
       - Key `mask` → Type: **Text** → `true`
       - Key `block_high_risk` → Type: **Text** → `false`
    4. Hit **Send**
    """
    import os as _os
    t0 = time.time()

    ext = _os.path.splitext(file.filename or "")[1].lower()
    if ext and ext not in {".log", ".txt", ".sql", ".csv", ".json"}:
        raise HTTPException(415, f"Unsupported file type: {ext}")

    raw = await file.read()
    if len(raw) > 500_000:
        raise HTTPException(413, "File exceeds 500 KB limit.")

    content = raw.decode("utf-8", errors="replace")
    itype   = "log" if ext == ".log" else "file"

    findings, masked, score, lines = detect(content, mask=mask)
    risk_level = classify_risk(score)
    action = (
        "blocked" if block_high_risk and risk_level in ("high", "critical")
        else ("masked" if mask and findings else "allowed")
    )
    summary, insights = ai_insights(content, findings, itype)
    ms = int((time.time() - t0) * 1000)

    log.info(f"[UPLOAD:{file.filename}] score={score} findings={len(findings)} ms={ms}")

    return {
        "filename": file.filename,
        "summary": summary,
        "content_type": itype,
        "findings": [f.model_dump() for f in findings],
        "risk_score": score,
        "risk_level": risk_level,
        "action": action,
        "insights": insights,
        "masked_content": masked if mask else None,
        "processing_time_ms": ms,
        "total_lines_scanned": lines,
    }


@app.post("/analyze/batch", tags=["Analysis"], summary="Analyze up to 10 items at once")
def analyze_batch(items: List[AnalyzeRequest]):
    """
    ## Batch Analysis

    Send an array of up to 10 items in one request.

    ### Postman — Body (raw JSON):
    ```json
    [
      { "input_type": "text", "content": "password=secret", "options": {"mask": true} },
      { "input_type": "log",  "content": "api_key=sk-prod-xyz123456789", "options": {"mask": true} }
    ]
    ```
    """
    if len(items) > 10:
        raise HTTPException(400, "Max 10 items per batch.")
    results = []
    for item in items:
        try:
            results.append({"status": "ok", "result": analyze(item).model_dump()})
        except HTTPException as e:
            results.append({"status": "error", "detail": e.detail})
    return {"batch_size": len(items), "results": results}