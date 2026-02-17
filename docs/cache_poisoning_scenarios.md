# Cache Poisoning Attack Scenarios

## Overview

Cache poisoning (also known as HTTP cache poisoning or web cache poisoning) is a powerful vulnerability that allows attackers to inject malicious content into cached HTTP responses. When an HTTP response is cached and served to subsequent users, all of them receive the poisoned content, making it a high-impact attack.

## How Cache Poisoning Works

### cache Key Construction
HTTP caches use a "cache key" to store and retrieve cached responses. The cache key typically includes:
- Request method (GET, POST, etc.)
- Request URL
- Sometimes certain headers (defined by the `Vary` header)

The vulnerability occurs when the cache key is poorly constructed and doesn't include all user-controllable parameters.

### Attack Flow

```
1. Attacker sends HTTP request with malicious input
2. Request passes through cache (proxy/CDN)
3. Response is cached using incomplete cache key
4. Legitimate user sends similar request (without the malicious input)
5. Server retrieves cached response (that includes attacker's payload)
6. Legitimate user receives poisoned response
```

## Common Cache Poisoning Vectors

### 1. Host Header Injection

**Vulnerability**: Host header not included in cache key

**Attack Example**:
```http
GET / HTTP/1.1
Host: legitimate.com
```

Attacker request:
```http
GET / HTTP/1.1
Host: attacker.com
```

If the origin server reflects the Host header in the response (e.g., in links or redirects), and this response is cached without including the Host header in the cache key, all subsequent users receive content pointing to attacker.com.

**Remediation**:
- Validate Host header against whitelist
- Include Host header in Vary header: `Vary: Host`
- Set `Cache-Control: private` for responses using Host header

### 2. X-Forwarded-Host Header Injection

**Vulnerability**: X-Forwarded-Host used to determine application origin but not in cache key

**Attack Example**:
```http
GET /api/data HTTP/1.1
Host: legitimate.com
X-Forwarded-Host: attacker.com
```

**Detection**: The endpoint may redirect or serve content from `attacker.com` instead of `legitimate.com`.

**Remediation**:
- Only trust X-Forwarded-Host from trusted proxy sources
- Include in Vary header: `Vary: X-Forwarded-Host`
- Set Cache-Control: private for sensitive endpoints

### 3. Unkeyed Request Parameters

**Vulnerability**: Query parameters or request values not included in cache key

**Attack Example**:
```
GET /search?q=calculator&utm_source=attacker.com HTTP/1.1
GET /search?q=calculator HTTP/1.1
```

Both requests might return the same cached response, even though the utm_source differs.

**Impact**: Attackers can inject tracking pixels, malicious scripts, or redirect URLs via unkeyed parameters.

**Remediation**:
- Ensure all meaningful parameters are included in cache key
- Use proper Vary header: `Vary: Accept-Encoding, User-Agent`
- Consider `Cache-Control: private` for dynamic content

### 4. Accept-Language Header Poisoning

**Vulnerability**: Accept-Language not properly considered in cache normalization

**Attack Example**:
```http
GET /page HTTP/1.1
Accept-Language: en-US,en;q=0.9,../../../etc/passwd
```

The malicious Accept-Language header might be:
- Reflected in the response
- Cause different behavior on backend
- Not properly normalized by cache layer

**Remediation**:
- Include `Vary: Accept-Language` when providing language-specific content
- Validate and sanitize Accept-Language header
- Implement proper cache key construction

### 5. Character Encoding/Normalization Attacks

**Vulnerability**: Cache layer doesn't normalize URL encoding

**Attack Example**:
```
GET /page HTTP/1.1          (Cache key)
GET /page%20 HTTP/1.1       (Different encoding, same cached response)
GET /page%00.html HTTP/1.1  (Null byte, cache bypass)
```

Attackers exploit inconsistent normalization between cache and application.

**Remediation**:
- Implement consistent URL normalization
- Validate request paths
- Configure cache to normalize URLs

### 6. User-Agent Poisoning

**Vulnerability**: User-Agent reflected in response but not in cache key

**Attack Example**:
```http
GET /app HTTP/1.1
User-Agent: <script>alert('cached')</script>
```

If reflected in response and cached, all users receive XSS payload.

**Remediation**:
- Include `Vary: User-Agent` if User-Agent affects response
- Never trust User-Agent for cache differentiation
- Set Cache-Control: private for dynamic content

## Chaos Kitten Detection Methods

### Method 1: Weak Cache Headers Detection

Chaos Kitten identifies weak cache configuration:

```python
# Detects responses with:
- Cache-Control: public (without private)
- Cache-Control: max-age > 300 seconds
- Cache-Control: s-maxage (shared cache extension)
```

**Severity**: HIGH  
**Confidence**: 0.6 - 0.8

### Method 2: Missing Vary Header

Chaos Kitten checks for missing Vary header when headers are manipulated:

```python
# Payload includes: X-Forwarded-Host, Host, X-Forwarded-For
# But Vary header doesn't include these
# Result: Potential cache poisoning
```

**Severity**: HIGH  
**Confidence**: 0.75

### Method 3: Payload in Body + Weak Caching

Chaos Kitten combines multiple signals:

```python
# If:
# 1. Payload appears in response body (reflected)
# 2. Response is marked cacheable (Cache-Control: public, max-age)
# 3. Cache is weak (no private, no no-cache)
# Then: Cache Poisoning vulnerability
```

**Severity**: HIGH  
**Confidence**: 0.9

## Testing with Chaos Kitten

### Basic Cache Poisoning Test

```bash
# Using the cache_poisoning.yaml profile
chaos-kitten scan --spec=openapi.json --profile=toys/cache_poisoning.yaml
```

### Test Specific Scenarios

1. **Host Header Injection**:
   - Payload: `attacker.com`
   - Check if reflected in response with Cache-Control: public

2. **X-Forwarded-Host Injection**:
   - Payload: `X-Forwarded-Host: attacker.com`
   - Check Vary header configuration

3. **Unkeyed Parameters**:
   - Payload: `?utm_source=attacker&utm_medium=cache`
   - Monitor cache hits for different parameter values

## Real-World Examples

### Example 1: Stored XSS via Cache Poisoning

```
1. Attacker: GET /page?ref=<script>fetch('/steal?c='+document.cookie)</script>
2. Cache key includes only URL, not ref parameter
3. Response (with script) is cached
4. Legitimate users receive XSS payload in cached response
5. All users' cookies are stolen
```

### Example 2: Redirect Loop with Host Header

```
1. Attacker: GET / HTTP/1.1 with Host: attacker-phishing.com
2. Application redirects to https://[Host header]/login
3. Response cached with Host header reflected
4. Legitimate users get redirected to attacker-phishing.com
5. Phishing attack succeeds on all users
```

### Example 3: Cache Bypass with Encoded Parameters

```
1. Attacker discovers: GET /admin
2. Cache key = "/admin", no query string included
3. Attacker requests: GET /admin?bypass=true&role=admin
4. Different response, same cache key
5. Cache layer now returns admin panel to all users
```

## Mitigation Strategies

### 1. Proper Cache Key Construction
```http
Vary: X-Forwarded-Host, X-Forwarded-For, Host, User-Agent
```

### 2. Mark Sensitive Responses
```http
Cache-Control: private, no-cache
```

### 3. Short TTL for Dynamic Content
```http
Cache-Control: public, max-age=60
```

### 4. Input Validation
- Validate Host header against whitelist
- Reject suspicious Accept-Language values
- Normalize URLs consistently

### 5. Monitoring
- Log cache hits per endpoint
- Alert on unusual cache patterns
- Monitor for high cache hit ratios on dynamic content

## OWASP References

- **CWE-444**: Inconsistent Handling of HTTP Request (HTTP Response Splitting)
- **OWASP A06:2021** - Vulnerable and Outdated Components
- **CAPEC-141**: Cache Poisoning

## Additional Resources

- [PortSwigger: Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning)
- [OWASP Cache Poisoning](https://owasp.org/www-community/attacks/Cache_Poisoning)
- [Detectify: Web Cache Poisoning 101](https://labs.detectify.com/web-cache-poisoning-101/)

## Testing Checklist

- [ ] Identify all HTTP headers reflected in response
- [ ] Check Vary header for completeness
- [ ] Test Host header injection
- [ ] Test X-Forwarded-Host injection
- [ ] Test unkeyed query parameters
- [ ] Verify Cache-Control configuration
- [ ] Test URL encoding normalization
- [ ] Test Accept-Language header injection
- [ ] Test User-Agent header injection
- [ ] Validate cache invalidation mechanisms

## Summary Table

| Vector | Cache Key Impact | Easy to Exploit | Severity |
|--------|------------------|-----------------|----------|
| Host Header | High Risk | Medium | CRITICAL |
| X-Forwarded-Host | High Risk | Medium | CRITICAL |
| Unkeyed Parameters | High Risk | Easy | HIGH |
| Accept-Language | Medium Risk | Medium | HIGH |
| User-Agent | Medium Risk | Medium | HIGH |
| Character Encoding | Medium Risk | Hard | MEDIUM |
