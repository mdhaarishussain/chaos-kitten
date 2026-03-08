# Remaining Bugs to Fix in Chaos-Kitten

Based on my analysis of the `main` branch, here are 4 medium to hard bugs you can open as Pull Requests.

## 1. [Medium] `ChainExecutor.execute_attack` Causes Double Base URL (`attack_chainer.py`)

**Description:**
In `chaos_kitten/brain/attack_chainer.py`, the `execute_chain` method attempts to resolve the URL for the next step by prepending the `base_url`:
```python
if base_url and path.startswith("/"):
    full_url = f"{base_url.rstrip('/')}{path}"
```
It then passes `full_url` into `self.executor.execute_attack(method, full_url, payload)`. 
However, the `Executor` class (`paws/executor.py`) *automatically* prepends the base URL in its `execute_attack` method via `self._client.build_request(method, path, ...)`. Passing `full_url` as the `path` argument results in the base URL being prepended twice (e.g., `http://example.com/http://example.com/api/v1/users`), causing chain execution to fail with HTTP 404 or Invalid URL formatting.

**Expected Behavior:**
`ChainExecutor` should pass the relative `path` directly to the executor if the executor is already configured with the base URL, or the executor should be smart enough not to double-prepend the base URL if an absolute URL is passed.

**Fix Guidance:**
- Simply pass `path` instead of constructing `full_url` locally in `attack_chainer.py`.
- Or, use HTTPX's absolute URL detection in `Executor.execute_attack` to avoid adding the base URL if it's already an absolute URL.

---

## 2. [Medium] `BrowserExecutor.test_xss` False Negatives on Immediate Alerts (`browser.py`)

**Description:**
In `chaos_kitten/paws/browser.py`, the `test_xss()` method navigates to a URL (`await page.goto(url)`) and then waits for an input selector to inject the payload:
```python
await page.wait_for_selector(input_selector, state="visible", timeout=self.timeout / 2)
```
If an injected XSS payload triggers *immediately* upon page load (e.g., a reflected XSS in the URL parameters), the Playwright `dialog` event handler fires, setting `triggered_alert = True`. 
However, if the injection somehow breaks the DOM layout or causes the page to blank out, `wait_for_selector` throws an exception, and the `except Exception:` block catches it and returns `{"is_vulnerable": False, ...}`. This blindly overrides the fact that `triggered_alert` is `True`, causing a false negative.

**Expected Behavior:**
The script should check if `triggered_alert` is `True` inside the `except` block before returning a negative result.

**Fix Guidance:**
Update the exception handler for `wait_for_selector`:
```python
except Exception:
    if triggered_alert:
        # Proceed to the success logic or return True immediately
        ...
    return {"is_vulnerable": False, "error": ...}
```

---

## 3. [Medium] Swagger 2.0 Parsing Creates Invalid URLs If `host` Is Missing (`openapi_parser.py`)

**Description:**
In `chaos_kitten/brain/openapi_parser.py`, the `get_servers()` method extracts server URLs. For Swagger 2.0 specs, the `host` key is officially *optional*. If `host` is omitted, the spec relies on the host of the API being served.
The parser does:
```python
host = self.spec.get('host')
for scheme in schemes:
    servers.append(f"{scheme}://{host}{base_path}")
```
If `host` is missing, `host` is `None`. This causes the parser to emit malformed URLs like `"https://None/api/v1"`, which breaks reconnaissance, crawling, and executor steps downstream.

**Expected Behavior:**
If `host` is omitted from a Swagger 2.0 spec, the parser should not inject `"None"` into the URL string. It should either omit the host part entirely (defaulting to relative paths), or fallback to a default/placeholder `localhost`. 

**Fix Guidance:**
- Check `if host:` before appending the scheme and host. If missing, simply append `base_path` as a relative server, or drop the `scheme://host` portion entirely.

---

## 4. [Hard] Async Event Loop Blocked by `fingerprint_tech` and `scan_ports` (`recon.py`)

**Description:**
In `chaos_kitten/brain/recon.py`, the `run` method is declared `async def run(self)` and executes concurrently in the orchestrator. However, step 2 (Port Scanning) and step 3 (Tech Fingerprinting) call synchronous blocking functions:
- `self.scan_ports` invokes `subprocess.run(cmd, ... timeout=300)` which is a synchronous, blocking shell execution.
- `self.fingerprint_tech` opens a synchronous `httpx.Client` and blocks on `client.get(url)`.
Because these are executed directly inside the async `run` method without `run_in_executor`, they completely block the main asyncio event loop for up to 5 minutes per target.

**Expected Behavior:**
Long-running synchronous I/O or shell commands within an `async` function must be offloaded to a thread pool so they don't block the rest of the application's event loop.

**Fix Guidance:**
1. Wrap synchronous operations in `await asyncio.get_running_loop().run_in_executor(None, func, *args)`.
2. Alternatively, rewrite `fingerprint_tech` to use `httpx.AsyncClient` and `await client.get(url)`.
3. Rewrite `scan_ports` to use `asyncio.create_subprocess_exec` instead of the blocking `subprocess.run`.
