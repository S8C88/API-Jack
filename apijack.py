#!/usr/bin/env python3
"""
API-Jack — REST API Security Scanner
A CLI tool that tests REST APIs for common vulnerabilities from the
OWASP API Security Top 10.

Usage:
    apijack.py scan --url BASE_URL --endpoints ENDPOINTS_JSON
    apijack.py detect-bola --url URL
    apijack.py rate-limit --url URL [--requests N]
    apijack.py expose --url URL
    apijack.py mass-assign --url URL --fields FIELD1,FIELD2,...
"""

import argparse
import json
import os
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    from requests.exceptions import RequestException, Timeout
except ImportError:
    print("[!] Missing 'requests' library. Install with: pip install requests")
    sys.exit(1)


# Constants




VERSION = "1.0.0"
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 0,
    SEVERITY_HIGH: 1,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 3,
    SEVERITY_INFO: 4,
}

# Color codes
COLORS = {
    "reset": "\033[0m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


# Utility functions

def colorize(text: str, color: str, bold: bool = False) -> str:
    """Wrap text in ANSI color codes."""
    if not sys.stdout.isatty():
        return text
    prefix = COLORS.get(color, "")
    if bold:
        prefix += COLORS["bold"]
    reset = COLORS["reset"]
    return f"{prefix}{text}{reset}"


def severity_color(severity: str) -> str:
    """Map severity level to a display color."""
    mapping = {
        SEVERITY_CRITICAL: "red",
        SEVERITY_HIGH: "red",
        SEVERITY_MEDIUM: "yellow",
        SEVERITY_LOW: "blue",
        SEVERITY_INFO: "cyan",
    }
    return mapping.get(severity, "white")


def ensure_dir(path: str) -> None:
    """Create directory if it doesn't exist."""
    os.makedirs(path, exist_ok=True)


# Finding model

class Finding:
    """Represents a single security finding."""

    def __init__(
        self,
        check: str,
        endpoint: str,
        method: str,
        severity: str,
        title: str,
        description: str,
        detail: Optional[str] = None,
        remediation: Optional[str] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.check = check
        self.endpoint = endpoint
        self.method = method
        self.severity = severity
        self.title = title
        self.description = description
        self.detail = detail
        self.remediation = remediation
        self.evidence = evidence or {}
        self.timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "check": self.check,
            "endpoint": self.endpoint,
            "method": self.method,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "detail": self.detail,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
        }

    def __repr__(self) -> str:
        return (
            f"[{self.severity}] {self.title} | {self.method} {self.endpoint}"
        )


# Reporter

class Reporter:
    """Collects findings and outputs results as a colorized table + JSON."""

    def __init__(self, verbose: bool = False):
        self.findings: List[Finding] = []
        self._verbose = verbose

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: List[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1
        return dict(counts)

    def print_table(self) -> None:
        """Print findings as a colorized ASCII table."""
        if not self.findings:
            print(colorize("\n  ✓ No findings detected.", "green", bold=True))
            return

        # Sort by severity (most critical first)
        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity, 99),
                f.endpoint,
                f.check,
            ),
        )

        print("\n" + colorize("  ╔══════════════════════════════════════════════════════════════════╗", "bold"))
        print(colorize("  ║                       API-Jack Scan Results                        ║", "bold"))
        print(colorize("  ╚══════════════════════════════════════════════════════════════════╝\n", "bold"))

        for f in sorted_findings:
            sev_colored = colorize(
                f"{f.severity:8}", severity_color(f.severity), bold=True
            )
            print(f"  {sev_colored} │ {colorize(f.title, 'white', bold=True)}")
            print(f"            ├─ {colorize('Endpoint:', 'dim')} {f.method} {f.endpoint}")
            print(f"            ├─ {colorize('Detail:', 'dim')}   {f.description}")
            if f.detail:
                print(f"            ├─ {colorize('Info:', 'dim')}    {f.detail}")
            if f.remediation:
                print(f"            └─ {colorize('Fix:', 'dim')}     {f.remediation}")
            print()

        # Summary line
        summary_parts = []
        for sev in [SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO]:
            count = self.summary.get(sev, 0)
            if count:
                summary_parts.append(
                    f"{colorize(str(count), severity_color(sev), bold=True)} {sev}"
                )
        print(f"  Summary: {', '.join(summary_parts)}")
        print(f"  Total:   {colorize(str(len(self.findings)), 'white', bold=True)} finding(s)\n")

    def to_json(self, path: Optional[str] = None) -> str:
        """Export findings as JSON. Optionally write to file."""
        report = {
            "tool": "API-Jack v" + VERSION,
            "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "summary": self.summary,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in sorted(
                self.findings,
                key=lambda f: (
                    SEVERITY_ORDER.get(f.severity, 99),
                    f.endpoint,
                    f.check,
                ),
            )],
        }
        output = json.dumps(report, indent=2)
        if path:
            ensure_dir(os.path.dirname(path) or ".")
            with open(path, "w") as f:
                f.write(output)
            print(colorize(f"  [i] JSON report written to: {path}", "cyan"))
        return output

    def log_verbose(self, msg: str) -> None:
        """Log a verbose/debug message."""
        if self._verbose:
            print(colorize(f"  [DEBUG] {msg}", "dim"))


# HTTP Client wrapper


class APIClient:

    def __init__(self, base_url: str, reporter: Reporter, timeout: int = 15):
        self.base_url = base_url.rstrip("/")
        self.reporter = reporter
        self.timeout = timeout
        self.session = requests.Session()
        # Default headers
        self.session.headers.update({
            "User-Agent": f"API-Jack/{VERSION}",
            "Accept": "application/json, */*",
        })

    def request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
        auth_token: Optional[str] = None,
    ) -> Tuple[Optional[requests.Response], Optional[str]]:
        """Make an HTTP request and return (response, error_string)."""
        url = self.base_url + path
        req_headers = dict(self.session.headers)
        if headers:
            req_headers.update(headers)
        if auth_token:
            req_headers["Authorization"] = f"Bearer {auth_token}"

        # Convert body to JSON if it's a dict
        json_body = body if isinstance(body, (dict, list)) else None
        data_body = body if not isinstance(body, (dict, list)) and body is not None else None

        self.reporter.log_verbose(
            f"{method.upper()} {url}"
            + (f" | headers: {dict(req_headers)}" if self.reporter._verbose else "")
            + (f" | body: {json.dumps(json_body or data_body)[:200]}" if self.reporter._verbose else "")
        )

        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                json=json_body,
                data=data_body,
                timeout=self.timeout,
                allow_redirects=False,
            )
            self.reporter.log_verbose(
                f"→ {resp.status_code} ({len(resp.content)} bytes)"
            )
            return resp, None
        except Timeout:
            return None, f"Request timed out after {self.timeout}s"
        except RequestException as e:
            return None, f"Request failed: {str(e)[:200]}"
        except Exception as e:
            return None, f"Unexpected error: {str(e)[:200]}"


# ──────────────────────────────────────────────────────────────────────
# Check implementations
# ──────────────────────────────────────────────────────────────────────

def check_missing_auth(
    client: APIClient,
    endpoint: dict,
    reporter: Reporter,
) -> List[Finding]:
    """
    Check if an endpoint is accessible without authentication.
    OWASP API1: Broken Object Level Authorization (no-auth variant)
    OWASP API2: Broken Authentication
    """
    findings = []
    path = endpoint.get("path", "")
    method = endpoint.get("method", "GET")
    expected_status = endpoint.get("expected_status", 200)
    auth_type = endpoint.get("auth_type", "required")

    if auth_type == "none":
        return findings  # Public endpoint, skip

    path_display = path
    body_template = endpoint.get("body_template")

    resp, err = client.request(method, path, body=body_template, auth_token=None)

    if err:
        findings.append(Finding(
            check="missing_auth",
            endpoint=path_display,
            method=method,
            severity=SEVERITY_MEDIUM,
            title="Auth Check Inconclusive",
            description=f"Could not reach endpoint to verify auth: {err}",
            remediation="Ensure the API is reachable and network/firewall rules allow scanning.",
        ))
        return findings

    if resp is not None and resp.status_code not in (401, 403):
        # Endpoint responded without auth — potential issue
        sev = SEVERITY_HIGH if resp.status_code == expected_status else SEVERITY_MEDIUM
        title = "Missing Authentication"
        desc = (
            f"Endpoint returned {resp.status_code} without authentication token. "
            f"Expected 401/403 if auth is required."
        )
        if resp.status_code == expected_status:
            desc += " Response status matches the authorized status, suggesting full access without auth."

        findings.append(Finding(
            check="missing_auth",
            endpoint=path_display,
            method=method,
            severity=sev,
            title=title,
            description=desc,
            detail=f"Got HTTP {resp.status_code} — expected 401 or 403 for unauthenticated request",
            remediation="Ensure the endpoint enforces authentication via middleware/annotations.",
            evidence={
                "request": {"method": method, "path": path, "auth": "none"},
                "response": {"status_code": resp.status_code},
            },
        ))

    return findings


def check_excessive_data(
    client: APIClient,
    url: str,
    reporter: Reporter,
) -> List[Finding]:
    """
    Check for excessive data exposure in API responses.
    OWASP API3: Excessive Data Exposure
    Looks for sensitive fields returned when not expected.
    """
    findings = []
    sensitive_patterns = [
        "password", "secret", "token", "credit_card", "ssn",
        "social_security", "api_key", "api-key", "apikey",
        "private_key", "passphrase", "pin", "cvv", "cvc",
        "authorization", "access_token", "refresh_token",
        "session_id", "cookie", "jwt", "bearer",
    ]

    resp, err = client.request("GET", url)

    if err:
        findings.append(Finding(
            check="excessive_data",
            endpoint=url,
            method="GET",
            severity=SEVERITY_MEDIUM,
            title="Data Exposure Check Inconclusive",
            description=f"Could not fetch endpoint: {err}",
        ))
        return findings

    if resp is None:
        return findings

    try:
        data = resp.json()
    except (json.JSONDecodeError, ValueError):
        # Non-JSON response — check content-type header
        content_type = resp.headers.get("Content-Type", "")
        if "json" not in content_type.lower():
            reporter.log_verbose(f"Response is not JSON (Content-Type: {content_type})")
        return findings

    # Recursively look for sensitive keys in the response
    exposed_fields = []

    def _scan(obj, path_prefix="", depth=0):
        # CWE-674: limit recursion depth to prevent stack overflow
        MAX_DEPTH = 20
        if depth > MAX_DEPTH:
            return
        if isinstance(obj, dict):
            for key, value in obj.items():
                full_path = f"{path_prefix}.{key}" if path_prefix else key
                key_lower = key.lower()
                # Check if key matches sensitive patterns
                for pat in sensitive_patterns:
                    if pat in key_lower:
                        exposed_fields.append((full_path, type(value).__name__))
                        break
                # Recurse into nested objects/arrays
                if isinstance(value, (dict, list)):
                    _scan(value, full_path, depth + 1)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                full_path = f"{path_prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    _scan(item, full_path, depth + 1)

    _scan(data)

    if exposed_fields:
        # Determine severity based on field sensitivity
        found_keys = [x[0] for x in exposed_fields]
        has_critical = any(
            any(kw in fk.lower() for kw in ["password", "secret", "token", "credit", "ssn"])
            for fk in found_keys
        )

        exposed_list = []
        for field_path, field_type in exposed_fields:
            exposed_list.append({"field": field_path, "type": field_type})

        detail_msg = "Exposed fields: " + ", ".join(found_keys[:15])
        if len(found_keys) > 15:
            detail_msg += "..."

        findings.append(Finding(
            check="excessive_data",
            endpoint=url,
            method="GET",
            severity=SEVERITY_HIGH if has_critical else SEVERITY_MEDIUM,
            title="Excessive Data Exposure",
            description=(
                "Response exposes " + str(len(exposed_fields))
                + " potentially sensitive field(s) that could leak internal data."
            ),
            detail=detail_msg,
            remediation=(
                "Use API response DTOs to return only the fields the client needs. "
                "Apply @JsonIgnore or equivalent annotations on sensitive fields. "
                "Consider GraphQL or sparse field-sets for fine-grained control."
            ),
            evidence={
                "exposed_fields": exposed_list,
                "response_status": resp.status_code,
            },
        ))
    else:
        reporter.log_verbose("No sensitive fields detected in response data.")

    # Check for response size anomaly
    content_length = len(resp.content)
    if content_length > 100_000:  # > 100KB
        findings.append(Finding(
            check="excessive_data",
            endpoint=url,
            method="GET",
            severity=SEVERITY_LOW,
            title="Large Response Payload",
            description=(
                f"Response body is {content_length:,} bytes, which may indicate "
                f"excessive data exposure or lack of pagination."
            ),
            detail=f"Content-Length: {content_length} bytes",
            remediation="Consider pagination, field filtering, or compression.",
            evidence={
                "content_length": content_length,
                "response_status": resp.status_code,
            },
        ))

    return findings


def check_bola(
    client: APIClient,
    url: str,
    reporter: Reporter,
    id_range: range = range(1, 6),
) -> List[Finding]:
    """
    Test for Broken Object Level Authorization (BOLA) by incrementing IDs.
    OWASP API1: Broken Object Level Authorization
    """
    findings = []
    # Parse the URL to find a numeric ID segment
    # Try to extract the last numeric segment as the target ID
    path_part = url.replace(client.base_url, "")

    import re
    id_match = re.search(r"/(\d+)(/|$)", path_part)
    if not id_match:
        findings.append(Finding(
            check="bola",
            endpoint=url,
            method="GET",
            severity=SEVERITY_INFO,
            title="BOLA Test Skipped",
            description="No numeric ID pattern found in URL path. Cannot test BOLA by ID enumeration.",
            detail=f"URL path: {path_part}",
        ))
        return findings

    original_id = id_match.group(1)
    original_path = path_part

    # First, get a baseline response with the original ID
    baseline_resp, baseline_err = client.request("GET", original_path)
    if baseline_err or baseline_resp is None:
        findings.append(Finding(
            check="bola",
            endpoint=url,
            method="GET",
            severity=SEVERITY_MEDIUM,
            title="BOLA Test Inconclusive",
            description=f"Could not reach baseline endpoint: {baseline_err or 'No response'}",
        ))
        return findings

    baseline_status = baseline_resp.status_code

    accessible_ids = []
    for test_id in id_range:
        test_path = original_path.replace(original_id, str(test_id), 1)
        resp, err = client.request("GET", test_path)

        if err:
            reporter.log_verbose(f"BOLA test for ID {test_id}: {err}")
            continue
        if resp is None:
            continue

        # If response is similar to baseline (same status, non-empty body),
        # the object might be accessible without authorization
        if resp.status_code == baseline_status and resp.status_code == 200:
            try:
                resp_body = resp.text[:500]
                # Check if we got actual data (not just a generic error)
                if len(resp_body) > 20:  # Meaningful response
                    accessible_ids.append(test_id)
            except Exception:
                pass
        elif resp.status_code == 200 and baseline_status != 200:
            # Even if baseline failed, if a different ID returns 200, that's suspicious
            accessible_ids.append(test_id)

    if accessible_ids:
        findings.append(Finding(
            check="bola",
            endpoint=url,
            method="GET",
            severity=SEVERITY_CRITICAL,
            title="Broken Object Level Authorization (BOLA)",
            description=(
                f"{len(accessible_ids)} alternate object ID(s) returned accessible data "
                f"without proper authorization checks."
            ),
            detail=f"Accessible IDs: {accessible_ids}",
            remediation=(
                "Implement server-side authorization checks for every object access. "
                "Verify the authenticated user has permission to access the requested resource. "
                "Use UUIDs or non-sequential IDs as a defense-in-depth measure."
            ),
            evidence={
                "original_id": original_id,
                "accessible_ids": accessible_ids,
                "tested_range": f"{id_range.start}-{id_range.stop - 1}",
                "baseline_status": baseline_status,
            },
        ))
    else:
        reporter.log_verbose("BOLA check: no accessible alternate IDs found (good).")

    return findings


def check_rate_limit(
    client: APIClient,
    url: str,
    reporter: Reporter,
    request_count: int = 100,
) -> List[Finding]:
    """
    Test for missing or insufficient rate limiting.
    OWASP API4: Lack of Resources & Rate Limiting
    """
    findings = []
    path_part = url.replace(client.base_url, "")

    responses = []
    start = time.time()

    for i in range(request_count):
        resp, err = client.request("POST" if "login" in path_part.lower() else "GET", path_part)
        if err:
            reporter.log_verbose(f"Request {i+1}: error — {err}")
            responses.append({"status": 0, "error": err})
        elif resp is not None:
            responses.append({"status": resp.status_code, "headers": dict(resp.headers)})
        if err:
            # If we can't connect, no point continuing
            if i < 5:
                continue
            break

    elapsed = time.time() - start

    # Analyze responses
    status_counts: Dict[int, int] = defaultdict(int)
    rate_limited = False
    rate_limit_header = None

    for r in responses:
        status = r.get("status", 0)
        status_counts[status] += 1
        if status in (429, 503):
            rate_limited = True
        # Check for rate-limit headers
        headers = r.get("headers", {})
        if not rate_limit_header:
            for hdr in headers:
                if "rate" in hdr.lower() or "retry" in hdr.lower() or "limit" in hdr.lower():
                    rate_limit_header = hdr
                    rate_limited = True

    requests_per_second = request_count / elapsed if elapsed > 0 else float("inf")

    # Determine if rate limiting is missing
    if not rate_limited:
        rps_str = f"{requests_per_second:.1f}"
        findings.append(Finding(
            check="rate_limit",
            endpoint=url,
            method="POST" if "login" in path_part.lower() else "GET",
            severity=SEVERITY_HIGH,
            title="Missing Rate Limiting",
            description=(
                f"All {request_count} requests were accepted without rate limiting. "
                f"Average rate: {rps_str} req/s."
            ),
            detail=(
                f"Sent {request_count} requests in {elapsed:.2f}s ({rps_str} req/s). "
                f"No 429/503 responses received. No rate-limit headers detected."
            ),
            remediation=(
                "Implement rate limiting via a middleware (e.g., token bucket, leaky bucket). "
                "Return 429 Too Many Requests with Retry-After headers when limits are exceeded. "
                "Consider per-IP and per-user rate limits."
            ),
            evidence={
                "request_count": request_count,
                "elapsed_seconds": round(elapsed, 2),
                "requests_per_second": round(requests_per_second, 1),
                "status_distribution": dict(status_counts),
                "rate_limited_detected": False,
            },
        ))
    else:
        reporter.log_verbose(
            f"Rate limiting detected (status 429/503 or rate-limit headers found). "
            f"Headers: {rate_limit_header}"
        )

    # Check overall RPS for info
    if requests_per_second > 50:
        findings.append(Finding(
            check="rate_limit",
            endpoint=url,
            method="POST" if "login" in path_part.lower() else "GET",
            severity=SEVERITY_LOW,
            title="High Request Throughput",
            description=(
                f"Achieved {requests_per_second:.0f} requests/second against this endpoint. "
                f"May indicate weak or absent throttling."
            ),
            detail=f"{request_count} requests in {elapsed:.2f}s = {requests_per_second:.0f} req/s",
            evidence={
                "requests_per_second": round(requests_per_second, 1),
                "elapsed_seconds": round(elapsed, 2),
            },
        ))

    return findings


def check_mass_assignment(
    client: APIClient,
    url: str,
    fields: List[str],
    reporter: Reporter,
) -> List[Finding]:
    """
    Test for Mass Assignment vulnerabilities.
    OWASP API6: Mass Assignment
    Attempts to inject privileged fields into a request body.
    """
    findings = []
    path_part = url.replace(client.base_url, "")

    # Build a body with the provided fields set to privileged values
    try_body = {}
    for field in fields:
        if field.lower() in ("is_admin", "admin", "role", "isadmin"):
            try_body[field] = True if field.lower() != "role" else "admin"
        elif field.lower() in ("balance", "credit", "score", "points"):
            try_body[field] = 999999
        else:
            try_body[field] = "injected"

    resp, err = client.request("POST" if path_part.endswith("/users") else "PATCH", path_part, body=try_body)

    if err:
        findings.append(Finding(
            check="mass_assignment",
            endpoint=url,
            method="POST",
            severity=SEVERITY_MEDIUM,
            title="Mass Assignment Test Inconclusive",
            description=f"Could not reach endpoint: {err}",
        ))
        return findings

    if resp is None:
        return findings

    # Check if the request succeeded (2xx) — might indicate mass assignment
    if 200 <= resp.status_code < 300:
        # Try to see if our injected values were reflected
        reflected = []
        try:
            resp_data = resp.json()
            for field in fields:
                if field in resp_data or field.lower() in str(resp_data).lower():
                    reflected.append(field)
        except (json.JSONDecodeError, ValueError):
            pass

        if reflected:
            findings.append(Finding(
                check="mass_assignment",
                endpoint=url,
                method="POST" if path_part.endswith("/users") else "PATCH",
                severity=SEVERITY_CRITICAL,
                title="Mass Assignment Vulnerability",
                description=(
                    f"Successfully injected {len(reflected)} privileged field(s) "
                    f"in the request body and got HTTP {resp.status_code}."
                ),
                detail=f"Injected fields reflected in response: {', '.join(reflected)}",
                remediation=(
                    "Use DTOs (Data Transfer Objects) instead of binding request "
                    "bodies directly to entity models. Maintain an allow-list of "
                    "modifiable fields. Never auto-bind 'role', 'isAdmin', or "
                    "similar privileged properties from user input."
                ),
                evidence={
                    "injected_fields": fields,
                    "reflected_fields": reflected,
                    "response_status": resp.status_code,
                    "payload_sent": try_body,
                },
            ))
        else:
            # Request succeeded but fields not reflected — might still be vulnerable
            findings.append(Finding(
                check="mass_assignment",
                endpoint=url,
                method="POST" if path_part.endswith("/users") else "PATCH",
                severity=SEVERITY_MEDIUM,
                title="Potential Mass Assignment",
                description=(
                    f"Request with privileged fields succeeded (HTTP {resp.status_code}) "
                    f"but injected values were not reflected in the response."
                ),
                detail=f"Sent fields: {', '.join(fields)}. Response: {resp.status_code}",
                remediation=(
                    "Review API endpoints to ensure they use DTOs and do not bind "
                    "request bodies directly to internal models."
                ),
                evidence={
                    "injected_fields": fields,
                    "response_status": resp.status_code,
                    "payload_sent": try_body,
                },
            ))
    elif resp.status_code in (400, 422):
        reporter.log_verbose("Mass assignment test: request rejected with 400/422 (good).")
    elif resp.status_code in (401, 403):
        findings.append(Finding(
            check="mass_assignment",
            endpoint=url,
            method="POST" if path_part.endswith("/users") else "PATCH",
            severity=SEVERITY_INFO,
            title="Mass Assignment: Auth Required",
            description="Endpoint requires authentication. Cannot test mass assignment without auth.",
            detail=f"Got HTTP {resp.status_code} when trying to modify resources.",
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────
# Scan command
# ──────────────────────────────────────────────────────────────────────

def run_scan(
    base_url: str,
    endpoints_path: str,
    reporter: Reporter,
    bola_range: range = range(1, 6),
    rate_limit_count: int = 50,
) -> None:
    """Execute a full scan from an endpoints definition file."""
    if not os.path.isfile(endpoints_path):
        reporter.log_verbose(f"Endpoints file not found: {endpoints_path}")
        print(colorize(f"  [!] Endpoints file not found: {endpoints_path}", "red"))
        return

    with open(endpoints_path) as f:
        try:
            endpoints = json.load(f)
        except json.JSONDecodeError as e:
            print(colorize(f"  [!] Invalid JSON in endpoints file: {e}", "red"))
            return

    if isinstance(endpoints, dict):
        # Could be wrapped in a key like "endpoints"
        endpoints = endpoints.get("endpoints", endpoints)
    if not isinstance(endpoints, list):
        print(colorize("  [!] Endpoints must be a JSON array of endpoint objects.", "red"))
        return

    client = APIClient(base_url, reporter)
    print(colorize(f"\n  {colorize('»', 'cyan')} Starting scan against {base_url}", "bold"))
    print(colorize(f"  {colorize('»', 'cyan')} Loaded {len(endpoints)} endpoint(s) from {endpoints_path}\n", "bold"))

    total_findings = 0
    for i, ep in enumerate(endpoints, 1):
        method = ep.get("method", "GET").upper()
        path = ep.get("path", "/")

        print(colorize(f"  [{i}/{len(endpoints)}] Testing {method} {path}", "cyan"))

        # 1. Missing auth check
        findings_miss = check_missing_auth(client, ep, reporter)
        reporter.extend(findings_miss)
        for f in findings_miss:
            print(colorize(f"    └─ {f.severity}: {f.title}", severity_color(f.severity)))

        # 2. Excessive data check (GET/READ endpoints)
        if method in ("GET", "POST") and "expected_status" in ep:
            findings_data = check_excessive_data(
                client, path, reporter
            )
            reporter.extend(findings_data)
            for f in findings_data:
                print(colorize(f"    └─ {f.severity}: {f.title}", severity_color(f.severity)))

        # 3. BOLA check for endpoints with numeric IDs
        if method in ("GET", "PUT", "DELETE", "PATCH") and "{id}" in path:
            # Resolve template to actual ID for BOLA testing
            actual_path = path.replace("{id}", "1")
            findings_bola = check_bola(client, base_url + actual_path, reporter, bola_range)
            reporter.extend(findings_bola)
            for f in findings_bola:
                print(colorize(f"    └─ {f.severity}: {f.title}", severity_color(f.severity)))

        total_findings += len(findings_miss) + len(findings_data)

    # 4. Rate limit check — on first available endpoint
    if endpoints:
        ep0 = endpoints[0]
        rate_path = ep0.get("path", "/")
        print(colorize(f"\n  [{len(endpoints)+1}/?] Rate limit testing on {rate_path}", "cyan"))
        findings_rl = check_rate_limit(client, base_url + rate_path, reporter, rate_limit_count)
        reporter.extend(findings_rl)
        for f in findings_rl:
            print(colorize(f"    └─ {f.severity}: {f.title}", severity_color(f.severity)))

    reporter.print_table()


# ──────────────────────────────────────────────────────────────────────
# CLI argument parsing
# ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apijack.py",
        description="API-Jack: REST API Security Scanner — OWASP API Security Top 10",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  apijack.py scan --url https://api.example.com --endpoints endpoints.json
  apijack.py detect-bola --url https://api.example.com/users/1
  apijack.py rate-limit --url https://api.example.com/login --requests 100
  apijack.py expose --url https://api.example.com/users/me
  apijack.py mass-assign --url https://api.example.com/users --fields is_admin,role

Report formats:
  All commands output a colorized findings table to stdout.
  Use --json to save a JSON report to file.
  Use -v for verbose/debug output.
        """,
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output showing requests and responses",
    )
    parser.add_argument(
        "--json",
        type=str,
        default=None,
        metavar="FILE",
        help="Save findings as JSON report to FILE",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Full scan from endpoints definition file")
    scan_parser.add_argument("--url", required=True, help="Base URL of the API (e.g., https://api.example.com)")
    scan_parser.add_argument("--endpoints", required=True, help="Path to JSON file with endpoint definitions")
    scan_parser.add_argument("--bola-range", default="1-5", help="ID range for BOLA testing (default: 1-5)")
    scan_parser.add_argument("--rate-limit-count", type=int, default=50, help="Number of requests for rate limit test (default: 50)")

    # detect-bola
    bola_parser = subparsers.add_parser("detect-bola", help="Test for Broken Object Level Authorization")
    bola_parser.add_argument("--url", required=True, help="Full URL to test (e.g., https://api.example.com/users/1)")
    bola_parser.add_argument("--range", default="1-5", help="ID range to test (default: 1-5)")

    # rate-limit
    rl_parser = subparsers.add_parser("rate-limit", help="Test rate limiting on an endpoint")
    rl_parser.add_argument("--url", required=True, help="Full URL to test (e.g., https://api.example.com/login)")
    rl_parser.add_argument("--requests", type=int, default=100, help="Number of requests to send (default: 100)")

    # expose
    expose_parser = subparsers.add_parser("expose", help="Check for excessive data exposure")
    expose_parser.add_argument("--url", required=True, help="Full URL to check (e.g., https://api.example.com/users/me)")

    # mass-assign
    mass_parser = subparsers.add_parser("mass-assign", help="Test for mass assignment vulnerability")
    mass_parser.add_argument("--url", required=True, help="Target URL (e.g., https://api.example.com/users)")
    mass_parser.add_argument("--fields", required=True, help="Comma-separated field names (e.g., is_admin,role)")

    return parser


# ──────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    reporter = Reporter(verbose=args.verbose)
    base_url = args.url if hasattr(args, "url") else ""

    try:
        if args.command == "scan":
            bola_range_parts = args.bola_range.split("-")
            bola_start = int(bola_range_parts[0]) if len(bola_range_parts) > 0 else 1
            bola_end = int(bola_range_parts[1]) + 1 if len(bola_range_parts) > 1 else 6
            bola_range = range(bola_start, bola_end)
            run_scan(args.url, args.endpoints, reporter, bola_range, args.rate_limit_count)

        elif args.command == "detect-bola":
            client = APIClient(args.url, reporter)
            findings = check_bola(client, args.url, reporter)
            reporter.extend(findings)
            reporter.print_table()

        elif args.command == "rate-limit":
            client = APIClient(args.url, reporter)
            findings = check_rate_limit(client, args.url, reporter, args.requests)
            reporter.extend(findings)
            reporter.print_table()

        elif args.command == "expose":
            client = APIClient(args.url, reporter)
            findings = check_excessive_data(client, args.url, reporter)
            reporter.extend(findings)
            reporter.print_table()

        elif args.command == "mass-assign":
            client = APIClient(args.url, reporter)
            fields = [f.strip() for f in args.fields.split(",") if f.strip()]
            findings = check_mass_assignment(client, args.url, fields, reporter)
            reporter.extend(findings)
            reporter.print_table()

    except KeyboardInterrupt:
        print(colorize("\n  [!] Scan interrupted by user.", "yellow"))
        return 130

    # Write JSON report if requested
    if args.json:
        reporter.to_json(args.json)

    return 1 if reporter.findings else 0


if __name__ == "__main__":
    sys.exit(main())
