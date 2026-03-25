"""
AI Secure Data Intelligence Platform — Test Suite
Run from project root:  pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import pytest
from unittest.mock import patch, MagicMock

# Mock anthropic before importing backend
mock_msg = MagicMock()
mock_msg.content = [MagicMock(text='{"summary":"Test summary.","insights":["Test insight."]}')]
mock_client = MagicMock()
mock_client.messages.create.return_value = mock_msg

with patch("anthropic.Anthropic", return_value=mock_client):
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-fake"}):
        from fastapi.testclient import TestClient
        from backend.main import app, detect, classify_risk, mask_value, RISK_PATTERNS

client = TestClient(app)


# ─────────────────────────────────────────────────────────────
# Unit Tests — Pattern Detection
# ─────────────────────────────────────────────────────────────
class TestPatternDetection:

    def test_detects_api_key(self):
        findings, _, score, _ = detect("api_key=sk-prod-abcdefghijklmnopqrstuvwxyz")
        assert any(f.type == "api_key" for f in findings)

    def test_detects_sk_prefix(self):
        findings, _, _, _ = detect("token: sk-my-secret-key-abcdefghijklmnopqrs")
        assert any(f.type == "api_key" for f in findings)

    def test_detects_password(self):
        findings, _, score, _ = detect("password=SuperSecret123")
        assert any(f.type == "password" for f in findings)
        assert score >= 10  # critical

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123def456"
        findings, _, _, _ = detect(jwt)
        assert any(f.type == "jwt_token" for f in findings)

    def test_detects_aws_key(self):
        findings, _, _, _ = detect("AKIAIOSFODNN7EXAMPLE")
        assert any(f.type == "aws_credential" for f in findings)

    def test_detects_email(self):
        findings, _, _, _ = detect("contact admin@company.com for help")
        assert any(f.type == "email" for f in findings)

    def test_detects_ip_address(self):
        findings, _, _, _ = detect("Connection from 192.168.1.100")
        assert any(f.type == "ip_address" for f in findings)

    def test_detects_stack_trace(self):
        findings, _, _, _ = detect("ERROR NullPointerException at service.java:45")
        assert any(f.type == "stack_trace" for f in findings)

    def test_detects_brute_force(self):
        content = "Failed login attempt\nFailed login attempt\nAuthentication failed"
        findings, _, _, _ = detect(content)
        assert any(f.type == "brute_force" for f in findings)

    def test_detects_debug_leak(self):
        findings, _, _, _ = detect("debug=true verbose_logging=true")
        assert any(f.type == "debug_leak" for f in findings)

    def test_detects_ssn(self):
        findings, _, _, _ = detect("SSN: 123-45-6789")
        assert any(f.type == "ssn" for f in findings)

    def test_clean_content_zero_score(self):
        _, _, score, _ = detect("User dashboard loaded. Request OK in 120ms.")
        assert score == 0

    def test_correct_line_numbers(self):
        content = "safe line\npassword=secret\nsafe line"
        findings, _, _, _ = detect(content)
        pw = next((f for f in findings if f.type == "password"), None)
        assert pw is not None
        assert pw.line == 2

    def test_deduplication_same_type_same_line(self):
        # Same pattern matched twice on same line should only produce 1 finding
        content = "password=abc password=abc"
        findings, _, _, _ = detect(content)
        pw_findings = [f for f in findings if f.type == "password"]
        assert len(pw_findings) == 1

    def test_masking_applied_to_content(self):
        content = "api_key=sk-prod-abcdefghijklmnopqrstuvwxyz"
        _, masked, _, _ = detect(content, mask=True)
        assert "sk-prod-abcdefghijklmnopqrstuvwxyz" not in masked
        assert "**" in masked

    def test_no_masking_when_disabled(self):
        content = "password=plain123"
        _, masked, _, _ = detect(content, mask=False)
        assert "plain123" in masked

    def test_line_count_returned(self):
        content = "line1\nline2\nline3"
        _, _, _, lines = detect(content)
        assert lines == 3

    def test_multiple_types_one_block(self):
        content = "email=admin@corp.com\npassword=abc\napi_key=sk-prod-xyz123456789012345678"
        findings, _, score, _ = detect(content)
        types = {f.type for f in findings}
        assert "email" in types
        assert "password" in types
        assert "api_key" in types
        assert score >= 10


# ─────────────────────────────────────────────────────────────
# Unit Tests — Risk Classification
# ─────────────────────────────────────────────────────────────
class TestRiskClassification:

    def test_score_0_safe(self):     assert classify_risk(0)  == "safe"
    def test_score_1_low(self):      assert classify_risk(1)  == "low"
    def test_score_3_low(self):      assert classify_risk(3)  == "low"
    def test_score_4_medium(self):   assert classify_risk(4)  == "medium"
    def test_score_8_medium(self):   assert classify_risk(8)  == "medium"
    def test_score_9_high(self):     assert classify_risk(9)  == "high"
    def test_score_15_high(self):    assert classify_risk(15) == "high"
    def test_score_16_critical(self):assert classify_risk(16) == "critical"
    def test_score_100_critical(self):assert classify_risk(100)== "critical"


# ─────────────────────────────────────────────────────────────
# Unit Tests — Masking
# ─────────────────────────────────────────────────────────────
class TestMasking:

    def test_short_value(self):
        assert mask_value("abc") == "****"

    def test_exactly_4_chars(self):
        assert mask_value("abcd") == "****"

    def test_long_value_keeps_first_and_last_2(self):
        result = mask_value("sk-myapikey12345")
        assert result.startswith("sk")
        assert result.endswith("45")
        assert "****" in result or result[2:-2].count("*") >= 4

    def test_empty_string(self):
        assert mask_value("") == "****"


# ─────────────────────────────────────────────────────────────
# Integration Tests — API Endpoints
# ─────────────────────────────────────────────────────────────
class TestAPIHealth:

    def test_root(self):
        r = client.get("/")
        assert r.status_code == 200
        assert "endpoints" in r.json()

    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_patterns_list(self):
        r = client.get("/patterns")
        assert r.status_code == 200
        data = r.json()
        assert "password" in data
        assert "api_key" in data
        assert "email" in data


class TestAnalyzeEndpoint:

    def _post(self, content, input_type="text", mask=True, block=False):
        return client.post("/analyze", json={
            "input_type": input_type,
            "content": content,
            "options": {"mask": mask, "block_high_risk": block}
        })

    def test_clean_text_safe(self):
        r = self._post("User dashboard loaded OK.")
        assert r.status_code == 200
        assert r.json()["risk_level"] == "safe"
        assert r.json()["findings"] == []

    def test_password_detected(self):
        r = self._post("password=hunter2", "log")
        assert r.status_code == 200
        data = r.json()
        assert any(f["type"] == "password" for f in data["findings"])
        assert data["risk_level"] in ("high", "critical")

    def test_action_masked(self):
        r = self._post("password=abc123 api_key=sk-xyz12345678901234567890", mask=True)
        assert r.json()["action"] == "masked"
        assert r.json()["masked_content"] is not None

    def test_action_blocked(self):
        r = self._post("password=abc123 api_key=sk-xyz12345678901234567890", mask=True, block=True)
        assert r.json()["action"] == "blocked"

    def test_action_allowed_no_findings(self):
        r = self._post("Everything looks fine.", mask=True)
        assert r.json()["action"] == "allowed"

    def test_empty_content_400(self):
        r = self._post("")
        assert r.status_code == 400

    def test_response_has_all_fields(self):
        r = self._post("test content")
        assert r.status_code == 200
        data = r.json()
        for field in ["summary", "content_type", "findings", "risk_score",
                      "risk_level", "action", "insights", "processing_time_ms",
                      "total_lines_scanned"]:
            assert field in data, f"Missing field: {field}"

    def test_findings_have_line_numbers(self):
        r = self._post("safe\npassword=secret\nsafe", "log")
        findings = r.json()["findings"]
        pw = next((f for f in findings if f["type"] == "password"), None)
        assert pw is not None
        assert pw["line"] == 2

    def test_log_input_type(self):
        r = self._post("2026-03-10 api_key=sk-test-abc123456789012345", "log")
        assert r.json()["content_type"] == "log"

    def test_sql_input_type(self):
        r = self._post("SELECT * FROM users WHERE email='x@y.com'", "sql")
        assert r.json()["content_type"] == "sql"

    def test_processing_time_positive(self):
        r = self._post("hello world")
        assert r.json()["processing_time_ms"] >= 0

    def test_full_log_critical(self):
        log_content = (
            "email=admin@company.com\n"
            "password=admin123\n"
            "api_key=sk-prod-xyz123456789012345678901\n"
            "AKIAIOSFODNN7EXAMPLE\n"
            "Failed login attempt for user root\n"
            "NullPointerException at service.java:45"
        )
        r = self._post(log_content, "log")
        data = r.json()
        assert data["risk_level"] in ("high", "critical")
        assert len(data["findings"]) >= 5


class TestBatchEndpoint:

    def test_batch_two_items(self):
        r = client.post("/analyze/batch", json=[
            {"input_type": "text", "content": "hello world"},
            {"input_type": "log",  "content": "password=secret123", "options": {"mask": True}},
        ])
        assert r.status_code == 200
        data = r.json()
        assert data["batch_size"] == 2
        assert len(data["results"]) == 2

    def test_batch_too_many_items(self):
        items = [{"input_type": "text", "content": "x"} for _ in range(11)]
        r = client.post("/analyze/batch", json=items)
        assert r.status_code == 400


class TestUploadEndpoint:

    def test_upload_text_file(self):
        content = b"password=admin123\napi_key=sk-prod-xyz123456789012345678\n"
        r = client.post(
            "/analyze/upload",
            files={"file": ("test.log", content, "text/plain")},
            data={"mask": "true", "block_high_risk": "false"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["filename"] == "test.log"
        assert len(data["findings"]) >= 2

    def test_upload_unsupported_type(self):
        r = client.post(
            "/analyze/upload",
            files={"file": ("image.png", b"fake", "image/png")},
            data={"mask": "true"},
        )
        assert r.status_code == 415
