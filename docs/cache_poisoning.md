# Cache Poisoning Detection

## Overview

Cache poisoning occurs when an attacker can manipulate a cache key or inject malicious content that gets stored in a shared cache, serving the malicious content to other users.

Chaos Kitten detects potential cache poisoning vulnerabilities by validating:
1.  **Cache Configuration**: Checking `Cache-Control` headers for public caching of potentially private or sensitive data.
2.  **Header Reflection**: Checking if injected headers (like `X-Forwarded-Host`) are reflected in the response headers or body.
3.  **Vary Header**: Ensuring that responses varying based on inputs includes the appropriate `Vary` header.

## Attack Scenarios

### 1. Unkeyed Input Reflection
The attacker injects a header (e.g., `X-Forwarded-Host: evil.com`) that is not part of the cache key but is reflected in the response (e.g., `Location: http://evil.com/login`).
If the response is cached, subsequent users are redirected to the attacker's domain.

**Detection:**
- Inject `X-Forwarded-Host`, `X-Host`, etc.
- Check if reflected in headers/body.
- Check if `Cache-Control` permits caching (`public`, `max-age > 0`).
- Check if `Vary` is missing the injected header.

### 2. Cacheable Sensitive Data
Sensitive responses (e.g., containing CSRF tokens or user info) are cached publicly.

**Detection:**
- Analyze `Cache-Control` header.
- Detect "public" directive on potentially sensitive endpoints.
- (Context-aware analysis required for "sensitive" determination).

## Remediation

1.  **Restrict Caching**: Use `Cache-Control: private, no-store` for sensitive pages.
2.  **Use Vary Header**: If a header influences the response, include it in the `Vary` header (e.g., `Vary: X-Forwarded-Host`).
3.  **Validate Inputs**: Do not trust `X-Forwarded-Host` or other headers blindly.

## Configuration

The Cache Poisoning attack profile is defined in `toys/cache_poisoning.yaml`.
Shared capabilities are implemented in `chaos_kitten/paws/analyzer.py` inside `check_cache_poisoning` method.
