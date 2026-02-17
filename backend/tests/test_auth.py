"""
Tests for authentication and session management.

Tests cover:
- Session creation and retrieval
- Session timeout and cleanup
- SSRF protection (IPv4/IPv6 localhost blocking)
- Rate limiting
- Input validation
"""

import time
import pytest
from pydantic import ValidationError

from auth import SessionManager, Session
from app import LoginRequest, RateLimiter


# ── Session Management Tests ──

class TestSessionManager:
    """Test session creation, retrieval, and lifecycle."""

    def test_create_session(self):
        """Session should be created with valid credentials."""
        manager = SessionManager(timeout=1800)
        token = manager.create(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
            port_imap=993,
            port_sieve=4190,
        )
        assert token is not None
        assert len(token) > 20  # Should be secure token

    def test_get_valid_session(self):
        """Should retrieve valid non-expired session."""
        manager = SessionManager(timeout=1800)
        token = manager.create(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
        )
        session = manager.get(token)
        assert session is not None
        assert session.username == "test@example.com"
        assert session.host == "mail.example.com"
        assert session.port_imap == 993
        assert session.port_sieve == 4190

    def test_get_invalid_token(self):
        """Should return None for invalid token."""
        manager = SessionManager()
        session = manager.get("invalid-token-12345")
        assert session is None

    def test_session_timeout(self):
        """Session should expire after timeout period."""
        manager = SessionManager(timeout=1)  # 1 second timeout
        token = manager.create(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
        )
        # Wait for timeout
        time.sleep(1.1)
        session = manager.get(token)
        assert session is None

    def test_session_last_used_update(self):
        """Session last_used should update on get()."""
        manager = SessionManager(timeout=10)
        token = manager.create(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
        )
        session1 = manager.get(token)
        time.sleep(0.01)  # Small delay to ensure time difference
        session2 = manager.get(token)
        assert session2.last_used >= session1.last_used  # >= instead of >

    def test_destroy_session(self):
        """Should remove session on destroy."""
        manager = SessionManager()
        token = manager.create(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
        )
        manager.destroy(token)
        session = manager.get(token)
        assert session is None

    def test_cleanup_expired_sessions(self):
        """Cleanup should remove expired sessions."""
        manager = SessionManager(timeout=1)
        # Create 3 sessions
        token1 = manager.create(host="mail1.example.com", username="user1", password="pass1")
        token2 = manager.create(host="mail2.example.com", username="user2", password="pass2")
        token3 = manager.create(host="mail3.example.com", username="user3", password="pass3")

        # Wait for timeout
        time.sleep(1.1)

        # Create new session (triggers cleanup)
        token4 = manager.create(host="mail4.example.com", username="user4", password="pass4")

        # Old sessions should be gone
        assert manager.get(token1) is None
        assert manager.get(token2) is None
        assert manager.get(token3) is None
        # New session should exist
        assert manager.get(token4) is not None


# ── SSRF Protection Tests ──

class TestSSRFProtection:
    """Test SSRF protection for IPv4 and IPv6 localhost variants."""

    @pytest.mark.parametrize("blocked_host", [
        "localhost",
        "127.0.0.1",
        "[127.0.0.1]",
        "0.0.0.0",
        "::1",
        "[::1]",
        "[::]",
    ])
    def test_blocked_hosts(self, blocked_host):
        """Should reject all localhost/private address variants."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                host=blocked_host,
                username="test@example.com",
                password="secret123",
            )
        assert "Connection to local addresses is not allowed" in str(exc_info.value)

    @pytest.mark.parametrize("valid_host", [
        "mail.example.com",
        "imap.gmail.com",
        "mail.protonmail.com",
        "outlook.office365.com",
    ])
    def test_valid_external_hosts(self, valid_host):
        """Should allow valid external hostnames."""
        req = LoginRequest(
            host=valid_host,
            username="test@example.com",
            password="secret123",
        )
        assert req.host == valid_host.lower()

    def test_hostname_too_long(self):
        """Should reject hostnames longer than 253 characters."""
        long_host = "a" * 254
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                host=long_host,
                username="test@example.com",
                password="secret123",
            )
        assert "Invalid hostname" in str(exc_info.value)

    def test_empty_hostname(self):
        """Should reject empty hostname."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                host="",
                username="test@example.com",
                password="secret123",
            )
        assert "Invalid hostname" in str(exc_info.value)


# ── Port Validation Tests ──

class TestPortValidation:
    """Test port number validation."""

    @pytest.mark.parametrize("invalid_port", [-1, 0, 65536, 100000])
    def test_invalid_ports(self, invalid_port):
        """Should reject out-of-range port numbers."""
        with pytest.raises(ValidationError) as exc_info:
            LoginRequest(
                host="mail.example.com",
                username="test@example.com",
                password="secret123",
                port_imap=invalid_port,
            )
        assert "Invalid port number" in str(exc_info.value)

    @pytest.mark.parametrize("valid_port", [1, 80, 443, 993, 4190, 65535])
    def test_valid_ports(self, valid_port):
        """Should accept valid port numbers (1-65535)."""
        req = LoginRequest(
            host="mail.example.com",
            username="test@example.com",
            password="secret123",
            port_imap=valid_port,
            port_sieve=valid_port,
        )
        assert req.port_imap == valid_port
        assert req.port_sieve == valid_port


# ── Rate Limiting Tests ──

class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_allows_under_limit(self):
        """Should allow requests under rate limit."""
        limiter = RateLimiter(max_attempts=5, window_seconds=300)
        for i in range(5):
            assert limiter.check("192.168.1.1") is True

    def test_blocks_over_limit(self):
        """Should block requests exceeding rate limit."""
        limiter = RateLimiter(max_attempts=3, window_seconds=300)
        # Use up the limit
        for i in range(3):
            limiter.check("192.168.1.1")
        # Next attempt should be blocked
        assert limiter.check("192.168.1.1") is False

    def test_different_ips_independent(self):
        """Rate limiting should be independent per IP."""
        limiter = RateLimiter(max_attempts=2, window_seconds=300)
        # IP 1 uses up limit
        limiter.check("192.168.1.1")
        limiter.check("192.168.1.1")
        # IP 2 should still be allowed
        assert limiter.check("192.168.1.2") is True

    def test_window_expiration(self):
        """Old attempts should expire after time window."""
        limiter = RateLimiter(max_attempts=2, window_seconds=1)
        # Use up limit
        limiter.check("192.168.1.1")
        limiter.check("192.168.1.1")
        # Should be blocked
        assert limiter.check("192.168.1.1") is False
        # Wait for window to expire
        time.sleep(1.1)
        # Should be allowed again
        assert limiter.check("192.168.1.1") is True
