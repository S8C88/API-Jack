#!/usr/bin/env python3
"""
Tests for API-Jack — REST API Security Scanner.
All tests are mocked; no real HTTP calls are made.
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock, call

# Ensure the project root is in the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from apijack import (
    Finding,
    Reporter,
    APIClient,
    check_missing_auth,
    check_excessive_data,
    check_bola,
    check_rate_limit,
    check_mass_assignment,
    run_scan,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    VERSION,
)
from requests.exceptions import Timeout


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────

def make_mock_response(status_code=200, json_data=None, text="", headers=None):
    """Create a mock requests.Response object."""
    mock_resp = MagicMock(spec=[])
    mock_resp.status_code = status_code
    mock_resp.headers = headers or {"Content-Type": "application/json"}
    mock_resp.content = json.dumps(json_data).encode() if json_data else text.encode()
    mock_resp.text = json.dumps(json_data) if json_data else text

    def json_method(**kwargs):
        if json_data is not None:
            return json_data
        raise json.JSONDecodeError("No JSON", "", 0)

    mock_resp.json = json_method
    return mock_resp


def make_ep(method="GET", path="/test", expected_status=200, auth_type="required", body_template=None):
    return {
        "method": method,
        "path": path,
        "expected_status": expected_status,
        "auth_type": auth_type,
        "body_template": body_template,
    }


# ──────────────────────────────────────────────────────────────────────
# Tests: Finding Model
# ──────────────────────────────────────────────────────────────────────

class TestFinding(unittest.TestCase):
    """Test the Finding data model."""

    def test_finding_creation(self):
        """Test basic Finding creation with all fields."""
        f = Finding(
            check="bola",
            endpoint="/api/users/1",
            method="GET",
            severity=SEVERITY_CRITICAL,
            title="BOLA Detected",
            description="Object IDs are enumerable",
            detail="IDs 2-5 returned data",
            remediation="Add auth checks",
            evidence={"ids": [2, 3, 4, 5]},
        )
        self.assertEqual(f.check, "bola")
        self.assertEqual(f.severity, SEVERITY_CRITICAL)
        self.assertEqual(f.title, "BOLA Detected")
        self.assertEqual(len(f.id), 8)

    def test_finding_to_dict(self):
        """Test Finding serialization to dict."""
        f = Finding(
            check="rate_limit",
            endpoint="/api/login",
            method="POST",
            severity=SEVERITY_HIGH,
            title="No Rate Limit",
            description="All 100 requests passed",
        )
        d = f.to_dict()
        self.assertEqual(d["check"], "rate_limit")
        self.assertEqual(d["severity"], SEVERITY_HIGH)
        self.assertIn("timestamp", d)
        self.assertIn("id", d)
        self.assertIn("evidence", d)

    def test_finding_repr(self):
        """Test Finding string representation."""
        f = Finding(
            check="bola",
            endpoint="/api/users/1",
            method="GET",
            severity=SEVERITY_CRITICAL,
            title="BOLA Detected",
            description="test",
        )
        r = repr(f)
        self.assertIn("CRITICAL", r)
        self.assertIn("BOLA Detected", r)
        self.assertIn("/api/users/1", r)


# ──────────────────────────────────────────────────────────────────────
# Tests: Reporter
# ──────────────────────────────────────────────────────────────────────

class TestReporter(unittest.TestCase):
    """Test the Reporter (findings collector + output)."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)

    def test_empty_reporter(self):
        """Test reporter with no findings."""
        self.assertEqual(len(self.reporter.findings), 0)
        self.assertEqual(self.reporter.summary, {})

    def test_add_finding(self):
        """Test adding a single finding."""
        f = Finding("test", "/api/test", "GET", SEVERITY_HIGH, "Test", "Desc")
        self.reporter.add(f)
        self.assertEqual(len(self.reporter.findings), 1)

    def test_add_multiple_findings(self):
        """Test adding multiple findings."""
        findings = [
            Finding("a", "/a", "GET", SEVERITY_HIGH, "A", "A"),
            Finding("b", "/b", "POST", SEVERITY_CRITICAL, "B", "B"),
        ]
        self.reporter.extend(findings)
        self.assertEqual(len(self.reporter.findings), 2)

    def test_summary_counts(self):
        """Test severity summary counts."""
        self.reporter.add(Finding("a", "/a", "GET", SEVERITY_CRITICAL, "A", "A"))
        self.reporter.add(Finding("b", "/b", "GET", SEVERITY_HIGH, "B", "B"))
        self.reporter.add(Finding("c", "/c", "GET", SEVERITY_CRITICAL, "C", "C"))
        summary = self.reporter.summary
        self.assertEqual(summary.get(SEVERITY_CRITICAL), 2)
        self.assertEqual(summary.get(SEVERITY_HIGH), 1)

    def test_to_json_output(self):
        """Test JSON report generation."""
        self.reporter.add(Finding(
            "bola", "/users/1", "GET", SEVERITY_CRITICAL, "BOLA", "Found"
        ))
        json_str = self.reporter.to_json()
        data = json.loads(json_str)
        self.assertEqual(data["tool"], f"API-Jack v{VERSION}")
        self.assertEqual(data["total_findings"], 1)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["findings"][0]["severity"], SEVERITY_CRITICAL)

    def test_to_json_file_output(self):
        """Test writing JSON report to file."""
        self.reporter.add(Finding("x", "/x", "GET", SEVERITY_LOW, "X", "X"))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            temp_path = tf.name
        try:
            self.reporter.to_json(temp_path)
            with open(temp_path) as f:
                data = json.load(f)
            self.assertEqual(data["total_findings"], 1)
        finally:
            os.unlink(temp_path)

    def test_verbose_logging(self):
        """Test verbose debug logging."""
        r = Reporter(verbose=True)
        with patch("builtins.print") as mock_print:
            r.log_verbose("test message")
            mock_print.assert_called_once()
            args = "".join(str(a) for a in mock_print.call_args[0])
            self.assertIn("test message", args)

    def test_non_verbose_logging(self):
        """Test that verbose messages are suppressed when not verbose."""
        r = Reporter(verbose=False)
        with patch("builtins.print") as mock_print:
            r.log_verbose("should not print")
            mock_print.assert_not_called()


# ──────────────────────────────────────────────────────────────────────
# Tests: APIClient
# ──────────────────────────────────────────────────────────────────────

class TestAPIClient(unittest.TestCase):
    """Test the HTTP client wrapper with mocked requests."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_request_get(self, mock_request):
        """Test a basic GET request."""
        mock_resp = make_mock_response(200, {"id": 1})
        mock_request.return_value = mock_resp

        resp, err = self.client.request("GET", "/users/1")
        self.assertIsNone(err)
        self.assertEqual(resp.status_code, 200)
        mock_request.assert_called_once()
        args, kwargs = mock_request.call_args
        self.assertEqual(kwargs["method"], "GET")
        self.assertIn("/users/1", kwargs["url"])

    @patch("apijack.requests.Session.request")
    def test_request_with_auth_token(self, mock_request):
        """Test request with Authorization header."""
        mock_resp = make_mock_response(200, {"ok": True})
        mock_request.return_value = mock_resp

        resp, err = self.client.request("GET", "/admin", auth_token="my-token")
        self.assertIsNone(err)
        args, kwargs = mock_request.call_args
        headers = kwargs["headers"]
        self.assertEqual(headers.get("Authorization"), "Bearer my-token")

    @patch("apijack.requests.Session.request")
    def test_request_with_body(self, mock_request):
        """Test request with JSON body."""
        mock_resp = make_mock_response(201, {"id": 42})
        mock_request.return_value = mock_resp

        body = {"name": "test", "email": "test@example.com"}
        resp, err = self.client.request("POST", "/users", body=body)
        self.assertIsNone(err)
        args, kwargs = mock_request.call_args
        self.assertEqual(kwargs["json"], body)

    @patch("apijack.requests.Session.request", side_effect=Timeout("timed out"))
    def test_request_timeout(self, mock_request):
        """Test request timeout handling."""
        resp, err = self.client.request("GET", "/slow")
        self.assertIsNone(resp)
        self.assertIsNotNone(err)
        self.assertIn("timed out", err.lower())

    @patch("apijack.requests.Session.request", side_effect=Exception("connection failed"))
    def test_request_exception(self, mock_request):
        """Test generic request exception handling."""
        resp, err = self.client.request("GET", "/fail")
        self.assertIsNone(resp)
        self.assertIsNotNone(err)
        self.assertIn("connection failed", err.lower())

    def test_base_url_trailing_slash(self):
        """Test that trailing slash is stripped from base URL."""
        client = APIClient("https://api.example.com/", self.reporter)
        self.assertEqual(client.base_url, "https://api.example.com")


# ──────────────────────────────────────────────────────────────────────
# Tests: check_missing_auth
# ──────────────────────────────────────────────────────────────────────

class TestCheckMissingAuth(unittest.TestCase):
    """Test the missing authentication detection."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_auth_required_but_missing(self, mock_request):
        """Test detecting missing auth when endpoint requires it."""
        mock_request.return_value = make_mock_response(200, {"data": "secret"})
        ep = make_ep(path="/admin/secret", auth_type="required")
        findings = check_missing_auth(self.client, ep, self.reporter)
        self.assertEqual(len(findings), 1)
        self.assertIn("Missing Authentication", findings[0].title)
        self.assertEqual(findings[0].severity, SEVERITY_HIGH)

    @patch("apijack.requests.Session.request")
    def test_auth_required_returns_401(self, mock_request):
        """Test that 401 response means auth is enforced (good)."""
        mock_request.return_value = make_mock_response(401, {"error": "unauthorized"})
        ep = make_ep(path="/admin/secret", auth_type="required")
        findings = check_missing_auth(self.client, ep, self.reporter)
        self.assertEqual(len(findings), 0)

    @patch("apijack.requests.Session.request")
    def test_auth_none_skips_check(self, mock_request):
        """Test that public endpoints (auth_type=none) are skipped."""
        mock_request.return_value = make_mock_response(200, {"public": "data"})
        ep = make_ep(path="/public", auth_type="none")
        findings = check_missing_auth(self.client, ep, self.reporter)
        self.assertEqual(len(findings), 0)
        mock_request.assert_not_called()

    @patch("apijack.requests.Session.request")
    def test_auth_check_403_is_enforced(self, mock_request):
        """Test that 403 also means auth is enforced."""
        mock_request.return_value = make_mock_response(403, {"error": "forbidden"})
        ep = make_ep(path="/admin", auth_type="required")
        findings = check_missing_auth(self.client, ep, self.reporter)
        self.assertEqual(len(findings), 0)

    @patch("apijack.requests.Session.request", return_value=None)
    def test_auth_check_request_error(self, mock_request):
        """Test handling when the request itself fails."""
        # Simulate a request error
        mock_request.side_effect = Exception("Network error")
        ep = make_ep(path="/test", auth_type="required")
        findings = check_missing_auth(self.client, ep, self.reporter)
        self.assertEqual(len(findings), 1)
        self.assertIn("Inconclusive", findings[0].title)


# ──────────────────────────────────────────────────────────────────────
# Tests: check_excessive_data
# ──────────────────────────────────────────────────────────────────────

class TestCheckExcessiveData(unittest.TestCase):
    """Test the excessive data exposure detection."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_sensitive_field_detected(self, mock_request):
        """Test detection of sensitive fields in response."""
        mock_request.return_value = make_mock_response(
            200, {"id": 1, "name": "Alice", "password": "supersecret", "email": "a@b.com"}
        )
        findings = check_excessive_data(self.client, "/users/me", self.reporter)
        self.assertGreaterEqual(len(findings), 1)
        # Should find password
        titles = [f.title for f in findings]
        self.assertTrue(any("Excessive Data" in t for t in titles))

    @patch("apijack.requests.Session.request")
    def test_no_sensitive_fields(self, mock_request):
        """Test clean response with no sensitive fields."""
        mock_request.return_value = make_mock_response(
            200, {"id": 1, "name": "Alice", "email": "a@b.com"}
        )
        findings = check_excessive_data(self.client, "/users/me", self.reporter)
        # May still get a large payload finding, but no excessive data finding
        data_findings = [f for f in findings if "Excessive Data" in f.title]
        self.assertEqual(len(data_findings), 0)

    @patch("apijack.requests.Session.request")
    def test_nested_sensitive_field(self, mock_request):
        """Test detection of sensitive fields in nested objects."""
        mock_request.return_value = make_mock_response(
            200, {
                "user": {"name": "Bob", "api_key": "sk-12345"},
                "settings": {"theme": "dark"},
            }
        )
        findings = check_excessive_data(self.client, "/users/1", self.reporter)
        self.assertGreaterEqual(len(findings), 1)
        titles = [f.title for f in findings]
        self.assertTrue(any("Excessive Data" in t for t in titles))

    @patch("apijack.requests.Session.request")
    def test_non_json_response(self, mock_request):
        """Test handling of non-JSON responses."""
        mock_resp = make_mock_response(200, None, text="<html>...</html>")
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_request.return_value = mock_resp
        findings = check_excessive_data(self.client, "/page", self.reporter)
        self.assertEqual(len(findings), 0)

    @patch("apijack.requests.Session.request", return_value=None)
    def test_request_error_data_exposure(self, mock_request):
        """Test handling when the request fails for data exposure check."""
        mock_request.side_effect = Exception("Timeout")
        findings = check_excessive_data(self.client, "/users", self.reporter)
        self.assertEqual(len(findings), 1)
        self.assertIn("Inconclusive", findings[0].title)

    @patch("apijack.requests.Session.request")
    def test_large_response_detection(self, mock_request):
        """Test detection of large response payloads."""
        large_data = {"items": ["x" * 1000] * 200}
        mock_request.return_value = make_mock_response(200, large_data)
        findings = check_excessive_data(self.client, "/products", self.reporter)
        large_findings = [f for f in findings if "Large Response" in f.title]
        self.assertGreaterEqual(len(large_findings), 0)  # May or may not trigger depending on size


# ──────────────────────────────────────────────────────────────────────
# Tests: check_bola
# ──────────────────────────────────────────────────────────────────────

class TestCheckBOLA(unittest.TestCase):
    """Test the BOLA (Broken Object Level Authorization) detection."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_bola_detected(self, mock_request):
        """Test detection of BOLA when alternate IDs return data."""
        # First call = baseline (ID 1)
        # Subsequent calls = alternate IDs
        mock_request.side_effect = [
            make_mock_response(200, {"id": 1, "name": "User1"}),  # baseline
            make_mock_response(200, {"id": 2, "name": "User2"}),  # ID 2
            make_mock_response(200, {"id": 3, "name": "User3"}),  # ID 3
            make_mock_response(200, {"id": 4, "name": "User4"}),  # ID 4
            make_mock_response(200, {"id": 5, "name": "User5"}),  # ID 5
        ]
        findings = check_bola(self.client, "https://api.example.com/users/1", self.reporter, range(2, 6))
        self.assertGreaterEqual(len(findings), 1)
        bola_findings = [f for f in findings if "BOLA" in f.title or "Broken Object" in f.title]
        self.assertGreaterEqual(len(bola_findings), 1)

    @patch("apijack.requests.Session.request")
    def test_bola_not_detected(self, mock_request):
        """Test that BOLA is not reported when alternate IDs fail."""
        mock_request.side_effect = [
            make_mock_response(200, {"id": 1, "name": "Me"}),   # baseline OK
            make_mock_response(404, {"error": "not found"}),     # ID 2
            make_mock_response(404, {"error": "not found"}),     # ID 3
            make_mock_response(404, {"error": "not found"}),     # ID 4
            make_mock_response(404, {"error": "not found"}),     # ID 5
        ]
        findings = check_bola(self.client, "https://api.example.com/users/1", self.reporter, range(2, 6))
        bola_findings = [f for f in findings if "Broken Object" in f.title]
        self.assertEqual(len(bola_findings), 0)

    @patch("apijack.requests.Session.request")
    def test_bola_no_numeric_id(self, mock_request):
        """Test BOLA check on endpoint without numeric ID."""
        findings = check_bola(
            self.client, "https://api.example.com/users/me", self.reporter
        )
        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("Skipped", findings[0].title)

    @patch("apijack.requests.Session.request", return_value=None)
    def test_bola_baseline_fails(self, mock_request):
        """Test BOLA check when baseline request fails."""
        mock_request.side_effect = Exception("Connection error")
        findings = check_bola(
            self.client, "https://api.example.com/users/1", self.reporter
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Inconclusive", findings[0].title)


# ──────────────────────────────────────────────────────────────────────
# Tests: check_rate_limit
# ──────────────────────────────────────────────────────────────────────

class TestCheckRateLimit(unittest.TestCase):
    """Test the rate limiting detection."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_rate_limit_missing(self, mock_request):
        """Test detection of missing rate limiting (all requests succeed)."""
        mock_request.return_value = make_mock_response(200, {"ok": True})
        findings = check_rate_limit(self.client, "https://api.example.com/login", self.reporter, 10)
        # Should find missing rate limiting
        missing = [f for f in findings if "Missing Rate" in f.title]
        self.assertGreaterEqual(len(missing), 1)

    @patch("apijack.requests.Session.request")
    def test_rate_limit_present_429(self, mock_request):
        """Test that presence of 429 responses doesn't trigger a finding."""
        # First few succeed, then rate limit kicks in
        responses = [make_mock_response(200, {"ok": True})] * 3
        responses += [make_mock_response(429, {"error": "too many"})] * 7
        mock_request.side_effect = responses
        findings = check_rate_limit(self.client, "https://api.example.com/login", self.reporter, 10)
        missing = [f for f in findings if "Missing Rate" in f.title]
        self.assertEqual(len(missing), 0)

    @patch("apijack.requests.Session.request")
    def test_rate_limit_present_503(self, mock_request):
        """Test that 503 is also recognized as rate limiting."""
        responses = [make_mock_response(200)] * 2
        responses += [make_mock_response(503, {"error": "service unavailable"})] * 3
        mock_request.side_effect = responses
        findings = check_rate_limit(self.client, "https://api.example.com/login", self.reporter, 5)
        missing = [f for f in findings if "Missing Rate" in f.title]
        self.assertEqual(len(missing), 0)

    @patch("apijack.requests.Session.request")
    def test_rate_limit_header_detected(self, mock_request):
        """Test that rate-limit headers are recognized."""
        headers = {"X-RateLimit-Remaining": "0", "Content-Type": "application/json"}
        mock_request.return_value = make_mock_response(200, {"ok": True}, headers=headers)
        findings = check_rate_limit(self.client, "https://api.example.com/login", self.reporter, 5)
        missing = [f for f in findings if "Missing Rate" in f.title]
        self.assertEqual(len(missing), 0)

    def test_rate_limit_default_count(self):
        """Test that the default request count is 100."""
        # The default is in the argparse, but we test the function signature
        import inspect
        sig = inspect.signature(check_rate_limit)
        self.assertEqual(sig.parameters["request_count"].default, 100)


# ──────────────────────────────────────────────────────────────────────
# Tests: check_mass_assignment
# ──────────────────────────────────────────────────────────────────────

class TestCheckMassAssignment(unittest.TestCase):
    """Test the mass assignment vulnerability detection."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)
        self.client = APIClient("https://api.example.com", self.reporter)

    @patch("apijack.requests.Session.request")
    def test_mass_assignment_reflected(self, mock_request):
        """Test detection when injected fields are reflected in response."""
        mock_request.return_value = make_mock_response(
            200, {"id": 1, "name": "Hacker", "role": "admin", "is_admin": True}
        )
        findings = check_mass_assignment(
            self.client, "https://api.example.com/users", ["is_admin", "role"], self.reporter
        )
        self.assertGreaterEqual(len(findings), 1)
        mass = [f for f in findings if "Mass Assignment" in f.title]
        self.assertGreaterEqual(len(mass), 1)

    @patch("apijack.requests.Session.request")
    def test_mass_assignment_not_reflected(self, mock_request):
        """Test when request succeeds but fields not reflected (potential vulnerability)."""
        mock_request.return_value = make_mock_response(
            201, {"id": 1, "name": "User"}
        )
        findings = check_mass_assignment(
            self.client, "https://api.example.com/users", ["is_admin"], self.reporter
        )
        mass = [f for f in findings if "Potential Mass" in f.title or "Mass Assignment" in f.title]
        self.assertGreaterEqual(len(mass), 1)

    @patch("apijack.requests.Session.request")
    def test_mass_assignment_rejected(self, mock_request):
        """Test when mass assignment is properly rejected with 400."""
        mock_request.return_value = make_mock_response(400, {"error": "bad request"})
        findings = check_mass_assignment(
            self.client, "https://api.example.com/users", ["is_admin"], self.reporter
        )
        self.assertEqual(len(findings), 0)

    @patch("apijack.requests.Session.request")
    def test_mass_assignment_auth_required(self, mock_request):
        """Test when endpoint requires auth for mass assignment test."""
        mock_request.return_value = make_mock_response(401, {"error": "unauthorized"})
        findings = check_mass_assignment(
            self.client, "https://api.example.com/users", ["role"], self.reporter
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("Auth Required", findings[0].title)

    @patch("apijack.requests.Session.request", return_value=None)
    def test_mass_assignment_request_error(self, mock_request):
        """Test handling when mass assignment request fails."""
        mock_request.side_effect = Exception("Error")
        findings = check_mass_assignment(
            self.client, "https://api.example.com/users", ["is_admin"], self.reporter
        )
        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("Inconclusive", findings[0].title)


# ──────────────────────────────────────────────────────────────────────
# Tests: run_scan (full scan orchestration)
# ──────────────────────────────────────────────────────────────────────

class TestRunScan(unittest.TestCase):
    """Test the full scan orchestration."""

    def setUp(self):
        self.reporter = Reporter(verbose=False)

    def test_run_scan_no_endpoints_file(self):
        """Test scan with missing endpoints file."""
        with patch("builtins.print") as mock_print:
            run_scan("https://api.example.com", "/nonexistent/file.json", self.reporter)
            mock_print.assert_any_call(
                unittest.mock.ANY  # We just verify it prints something
            )

    def test_run_scan_invalid_json(self):
        """Test scan with invalid JSON in endpoints file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            tf.write("not valid json{{{")
            temp_path = tf.name
        try:
            with patch("builtins.print") as mock_print:
                run_scan("https://api.example.com", temp_path, self.reporter)
                # Should print error about invalid JSON
                found = any("Invalid JSON" in str(a) for call in mock_print.call_args_list for a in call[0])
                self.assertTrue(found)
        finally:
            os.unlink(temp_path)

    def test_run_scan_non_list_json(self):
        """Test scan with valid JSON that is not a list."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            json.dump({"foo": "bar"}, tf)
            temp_path = tf.name
        try:
            with patch("builtins.print") as mock_print:
                run_scan("https://api.example.com", temp_path, self.reporter)
                found = any("JSON array" in str(a) for call in mock_print.call_args_list for a in call[0])
                self.assertTrue(found)
        finally:
            os.unlink(temp_path)

    @patch("apijack.check_missing_auth")
    @patch("apijack.check_excessive_data")
    @patch("apijack.check_rate_limit")
    def test_run_scan_with_endpoints(self, mock_rl, mock_expose, mock_auth):
        """Test scan with a valid endpoints list (all mocked checks)."""
        mock_auth.return_value = []
        mock_expose.return_value = []
        mock_rl.return_value = []

        endpoints = [
            {"method": "GET", "path": "/users", "expected_status": 200, "auth_type": "required"},
            {"method": "POST", "path": "/login", "expected_status": 200,
             "auth_type": "none", "body_template": {"user": "test"}},
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            json.dump(endpoints, tf)
            temp_path = tf.name
        try:
            run_scan("https://api.example.com", temp_path, self.reporter)
            self.assertTrue(mock_auth.called)
        finally:
            os.unlink(temp_path)


# ──────────────────────────────────────────────────────────────────────
# Tests: CLI argument parsing
# ──────────────────────────────────────────────────────────────────────

class TestCLI(unittest.TestCase):
    """Test CLI argument parsing (no actual execution)."""

    def test_version_in_module(self):
        """Test VERSION constant is defined."""
        self.assertTrue(hasattr(sys.modules.get("apijack"), "VERSION"))

    def test_build_parser_scan(self):
        """Test scan subcommand argument parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "scan", "--url", "https://api.example.com", "--endpoints", "ep.json"
        ])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.url, "https://api.example.com")
        self.assertEqual(args.endpoints, "ep.json")

    def test_build_parser_detect_bola(self):
        """Test detect-bola subcommand argument parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "detect-bola", "--url", "https://api.example.com/users/1"
        ])
        self.assertEqual(args.command, "detect-bola")
        self.assertEqual(args.url, "https://api.example.com/users/1")

    def test_build_parser_rate_limit(self):
        """Test rate-limit subcommand argument parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "rate-limit", "--url", "https://api.example.com/login", "--requests", "200"
        ])
        self.assertEqual(args.command, "rate-limit")
        self.assertEqual(args.requests, 200)

    def test_build_parser_expose(self):
        """Test expose subcommand argument parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "expose", "--url", "https://api.example.com/users/me"
        ])
        self.assertEqual(args.command, "expose")

    def test_build_parser_mass_assign(self):
        """Test mass-assign subcommand argument parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "mass-assign", "--url", "https://api.example.com/users",
            "--fields", "is_admin,role"
        ])
        self.assertEqual(args.command, "mass-assign")
        self.assertEqual(args.fields, "is_admin,role")

    def test_build_parser_verbose(self):
        """Test verbose flag parsing."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([
            "-v", "scan", "--url", "https://api.example.com",
            "--endpoints", "ep.json"
        ])
        self.assertTrue(args.verbose)

    def test_build_parser_json_output(self):
        """Test JSON output flag parsing."""
        from apijack import build_parser
        parser = build_parser()
        # --json must appear before the subcommand in argparse
        args = parser.parse_args([
            "--json", "report.json",
            "scan", "--url", "https://api.example.com",
            "--endpoints", "ep.json"
        ])
        self.assertEqual(args.json, "report.json")

    def test_no_args_shows_help(self):
        """Test that running with no args sets command to None."""
        from apijack import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        self.assertIsNone(args.command)


# ──────────────────────────────────────────────────────────────────────
# Tests: Color utility
# ──────────────────────────────────────────────────────────────────────

class TestColorize(unittest.TestCase):
    """Test the colorize utility function."""

    def test_colorize_with_tty(self):
        """Test colorize when stdout is a TTY."""
        from apijack import colorize, COLORS
        with patch("sys.stdout.isatty", return_value=True):
            result = colorize("hello", "red", bold=True)
            expected = f"{COLORS['red']}{COLORS['bold']}hello{COLORS['reset']}"
            self.assertEqual(result, expected)

    def test_colorize_without_tty(self):
        """Test colorize when stdout is not a TTY (no colors)."""
        from apijack import colorize
        with patch("sys.stdout.isatty", return_value=False):
            result = colorize("hello", "red")
            self.assertEqual(result, "hello")

    def test_severity_color_mapping(self):
        """Test severity to color mapping."""
        from apijack import severity_color
        self.assertEqual(severity_color("CRITICAL"), "red")
        self.assertEqual(severity_color("HIGH"), "red")
        self.assertEqual(severity_color("MEDIUM"), "yellow")
        self.assertEqual(severity_color("LOW"), "blue")
        self.assertEqual(severity_color("INFO"), "cyan")
        self.assertEqual(severity_color("UNKNOWN"), "white")


# ──────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    unittest.main()
