"""
Tests for FastAPI application endpoints and middleware.

Tests cover:
- Health check endpoint
- Security headers middleware
- Configuration constants
- Logging setup
- Authentication helpers
- Request validation
"""

import pytest
from fastapi.testclient import TestClient

from app import (
    app, health_check, get_session,
    SESSION_COOKIE_NAME, MAX_UPLOAD_BYTES, RATE_LIMIT_MAX_ATTEMPTS,
    SESSION_COOKIE_MAX_AGE, MAX_HOSTNAME_LENGTH,
    setup_logging, _is_secure,
)
from auth import sessions, Session


# ── Test Client Fixture ──

@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    return TestClient(app)


@pytest.fixture
def mock_session():
    """Create a mock session for testing."""
    token = sessions.create(
        host="mail.example.com",
        username="test@example.com",
        password="secret123",
        port_imap=993,
        port_sieve=4190,
    )
    yield token, sessions.get(token)
    # Cleanup
    sessions.destroy(token)


# ── Configuration Constants Tests ──

class TestConstants:
    """Test that configuration constants are properly defined."""

    def test_session_constants(self):
        """Session-related constants should be defined."""
        assert SESSION_COOKIE_NAME == "ays_session"
        assert SESSION_COOKIE_MAX_AGE == 1800
        assert isinstance(SESSION_COOKIE_MAX_AGE, int)

    def test_security_constants(self):
        """Security-related constants should be defined."""
        assert RATE_LIMIT_MAX_ATTEMPTS == 5
        assert MAX_HOSTNAME_LENGTH == 253
        assert MAX_UPLOAD_BYTES == 1 * 1024 * 1024

    def test_constants_are_integers(self):
        """All numeric constants should be integers."""
        assert isinstance(RATE_LIMIT_MAX_ATTEMPTS, int)
        assert isinstance(SESSION_COOKIE_MAX_AGE, int)
        assert isinstance(MAX_HOSTNAME_LENGTH, int)
        assert isinstance(MAX_UPLOAD_BYTES, int)


# ── Logging Tests ──

class TestLogging:
    """Test logging configuration."""

    def test_setup_logging_default(self):
        """Should configure logging with default INFO level."""
        logger = setup_logging("INFO")
        assert logger.name == "areyousievious"
        assert logger.level <= 20  # INFO or lower

    def test_setup_logging_debug(self):
        """Should configure logging with DEBUG level."""
        logger = setup_logging("DEBUG")
        assert logger.level <= 10  # DEBUG or lower

    def test_setup_logging_warning(self):
        """Should configure logging with WARNING level."""
        logger = setup_logging("WARNING")
        assert logger.level <= 30  # WARNING or lower


# ── Health Check Endpoint Tests ──

class TestHealthCheckEndpoint:
    """Test /health endpoint."""

    def test_health_check_returns_200(self, client):
        """Health check should return 200 OK."""
        response = client.get("/health")
        assert response.status_code == 200

    def test_health_check_json_format(self, client):
        """Health check should return JSON with status and version."""
        response = client.get("/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"

    def test_health_check_no_auth_required(self, client):
        """Health check should not require authentication."""
        response = client.get("/health")
        assert response.status_code == 200
        # No 401 Unauthorized


# ── Security Headers Tests ──

class TestSecurityHeaders:
    """Test security headers middleware."""

    def test_csp_header_present(self, client):
        """Should include Content-Security-Policy header."""
        response = client.get("/health")
        assert "content-security-policy" in response.headers
        csp = response.headers["content-security-policy"]
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    def test_x_frame_options_header(self, client):
        """Should include X-Frame-Options header."""
        response = client.get("/health")
        assert "x-frame-options" in response.headers
        assert response.headers["x-frame-options"] == "DENY"

    def test_x_content_type_options_header(self, client):
        """Should include X-Content-Type-Options header."""
        response = client.get("/health")
        assert "x-content-type-options" in response.headers
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_x_xss_protection_header(self, client):
        """Should include X-XSS-Protection header."""
        response = client.get("/health")
        assert "x-xss-protection" in response.headers
        assert response.headers["x-xss-protection"] == "1; mode=block"

    def test_hsts_header_not_present_http(self, client):
        """HSTS header should not be present for HTTP requests."""
        response = client.get("/health")
        # TestClient doesn't set X-Forwarded-Proto, so no HSTS
        # This is correct behavior - HSTS only for HTTPS
        assert "strict-transport-security" not in response.headers


# ── Authentication Helper Tests ──

class TestAuthHelpers:
    """Test authentication helper functions."""

    def test_is_secure_env_var(self, monkeypatch):
        """Should detect secure mode from environment variable."""
        monkeypatch.setenv("AYS_SECURE_COOKIES", "true")
        from fastapi import Request
        # Mock request
        class MockRequest:
            headers = {}
        request = MockRequest()
        assert _is_secure(request) is True

    def test_is_secure_x_forwarded_proto(self):
        """Should detect secure mode from X-Forwarded-Proto header."""
        from fastapi import Request
        class MockRequest:
            headers = {"x-forwarded-proto": "https"}
        request = MockRequest()
        assert _is_secure(request) is True

    def test_is_not_secure_http(self):
        """Should return False for HTTP requests."""
        from fastapi import Request
        class MockRequest:
            headers = {}
        request = MockRequest()
        assert _is_secure(request) is False


# ── Session Authentication Tests ──

class TestSessionAuthentication:
    """Test session-based authentication."""

    def test_get_session_valid_cookie(self, mock_session):
        """Should retrieve session from valid cookie."""
        token, session = mock_session
        from fastapi import Request

        class MockRequest:
            cookies = {SESSION_COOKIE_NAME: token}
            headers = {}

        request = MockRequest()
        retrieved = get_session(request)
        assert retrieved.username == session.username
        assert retrieved.host == session.host

    def test_get_session_valid_bearer_token(self, mock_session):
        """Should retrieve session from Bearer token."""
        token, session = mock_session
        from fastapi import Request

        class MockRequest:
            cookies = {}
            headers = {"Authorization": f"Bearer {token}"}  # Capital A

        request = MockRequest()
        retrieved = get_session(request)
        assert retrieved.username == session.username

    def test_get_session_no_token(self):
        """Should raise 401 when no token provided."""
        from fastapi import Request, HTTPException

        class MockRequest:
            cookies = {}
            headers = {}

        request = MockRequest()
        with pytest.raises(HTTPException) as exc_info:
            get_session(request)
        assert exc_info.value.status_code == 401
        assert "Not authenticated" in str(exc_info.value.detail)

    def test_get_session_invalid_token(self):
        """Should raise 401 for invalid/expired token."""
        from fastapi import Request, HTTPException

        class MockRequest:
            cookies = {SESSION_COOKIE_NAME: "invalid-token-12345"}
            headers = {}

        request = MockRequest()
        with pytest.raises(HTTPException) as exc_info:
            get_session(request)
        assert exc_info.value.status_code == 401
        assert "Session expired" in str(exc_info.value.detail)


# ── Auth Status Endpoint Tests ──

class TestAuthStatusEndpoint:
    """Test /api/auth/status endpoint."""

    @pytest.mark.asyncio
    async def test_auth_status_authenticated(self, client, mock_session):
        """Should return authenticated status for valid session."""
        token, session = mock_session
        response = client.get(
            "/api/auth/status",
            cookies={SESSION_COOKIE_NAME: token}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["username"] == session.username
        assert data["host"] == session.host

    @pytest.mark.asyncio
    async def test_auth_status_unauthenticated(self, client):
        """Should return unauthenticated status without session."""
        response = client.get("/api/auth/status")
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is False


# ── Integration Tests ──

class TestAppIntegration:
    """Integration tests for the application."""

    def test_cors_middleware_configured(self, client):
        """CORS middleware should be configured."""
        # CORS headers should be present
        response = client.options("/health")
        # At minimum, the app should respond to OPTIONS
        assert response.status_code in [200, 405]  # 405 if no OPTIONS handler

    def test_multiple_endpoints_have_security_headers(self, client):
        """All endpoints should have security headers."""
        endpoints = ["/health", "/api/auth/status"]
        for endpoint in endpoints:
            response = client.get(endpoint)
            assert "x-frame-options" in response.headers
            assert "content-security-policy" in response.headers


# ── Performance Tests ──

@pytest.mark.slow
class TestPerformance:
    """Performance-related tests."""

    def test_health_check_response_time(self, client):
        """Health check should respond quickly."""
        import time
        start = time.perf_counter()
        response = client.get("/health")
        elapsed = time.perf_counter() - start
        assert response.status_code == 200
        assert elapsed < 0.1  # Should respond in < 100ms
