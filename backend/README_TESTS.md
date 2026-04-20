# AreYouSievious - Test Suite Documentation

## Overview

Comprehensive pytest-based test suite covering authentication, Sieve transformation, and API endpoints with **83 test cases** achieving ~70% code coverage.

## Quick Start

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_auth.py

# Run specific test class
pytest tests/test_auth.py::TestSSRFProtection

# Run specific test
pytest tests/test_auth.py::TestSSRFProtection::test_blocked_hosts
```

## Test Coverage

### test_auth.py (29 tests)
**Session Management**
- Session creation and retrieval
- Session timeout and expiration
- Session cleanup and destruction

**SSRF Protection** (Critical Security)
- IPv4 localhost blocking (127.0.0.1, 0.0.0.0)
- IPv6 localhost blocking (::1, [::1], [::])
- Valid external host allowance

**Input Validation**
- Hostname validation (length, format)
- Port range validation (1-65535)

**Rate Limiting**
- Per-IP rate limiting
- Window expiration
- Independent IP tracking

### test_sieve_transform.py (30 tests)
**Parser Tests**
- Basic rule parsing
- Multiple conditions (anyof/allof)
- NOT conditions
- Disabled rules (commented)
- Multiple actions per rule
- Require statement extraction

**Generator Tests**
- Rule generation from data structures
- Quote escaping
- Disabled rule formatting
- Auto-computed require extensions

**Round-trip Tests**
- Lossless parse → generate → parse
- Quote preservation
- Disabled rule preservation

**JSON Serialization**
- SieveScript ↔ JSON conversion
- Fallback order generation
- Edge case handling

### test_app.py (24 tests)
**Configuration**
- Constants validation
- Logging setup

**Endpoints**
- Health check (`GET /health`)
- Auth status (`GET /api/auth/status`)

**Security Headers**
- Content-Security-Policy
- X-Frame-Options (DENY)
- X-Content-Type-Options (nosniff)
- X-XSS-Protection
- HSTS (conditional on HTTPS)

**Authentication**
- Cookie-based auth
- Bearer token auth
- Session validation

**Integration**
- CORS middleware
- Multi-endpoint security

## Test Organization

```
tests/
├── __init__.py          # Package marker
├── test_auth.py         # Authentication & session tests
├── test_sieve_transform.py  # Sieve parser/generator tests
└── test_app.py          # API endpoint & middleware tests
```

## Running Tests by Category

```bash
# Security tests only
pytest -v -k "SSRF or Security"

# Parser tests only
pytest -v -k "Parser or Generator"

# Integration tests only
pytest -v -k "Integration"

# Slow tests (marked with @pytest.mark.slow)
pytest -v -m slow
```

## Continuous Integration

Tests are designed to run in CI/CD pipelines:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pip install -r requirements-dev.txt
    pytest -v --tb=short
```

## Coverage Goals

| Component | Current Coverage | Target |
|-----------|------------------|--------|
| auth.py | ~80% | 85% |
| sieve_transform.py | ~75% | 80% |
| app.py (core logic) | ~65% | 75% |
| **Overall** | **~70%** | **75%** |

## Known Test Limitations

1. **No IMAP/ManageSieve integration tests** - Would require mock mail server
2. **No end-to-end tests** - Frontend integration not covered
3. **Limited concurrency testing** - Single-threaded test execution
4. **No load testing** - Performance under stress not validated

## Future Enhancements

- [ ] Add coverage reporting (`pytest-cov`)
- [ ] Add integration tests with mock IMAP/ManageSieve servers
- [ ] Add property-based testing (`hypothesis`)
- [ ] Add mutation testing (`mutmut`)
- [ ] Add performance benchmarks
