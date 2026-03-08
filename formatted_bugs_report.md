# Bug Report 1: ChainExecutor.execute_attack Causes Double Base URL

## 🐛 Bug Description
In `chaos_kitten/brain/attack_chainer.py`, the `execute_chain` method attempts to resolve the URL for the next step by prepending the `base_url`. It then passes this constructed `full_url` into the executor (`self.executor.execute_attack(method, full_url, payload)`). However, the `Executor` class (`paws/executor.py`) automatically prepends the base URL in its `execute_attack` method. Passing `full_url` as the `path` argument results in the base URL being prepended twice (e.g., `http://example.com/http://example.com/api/v1/users`).

## 🔄 Steps to Reproduce
1. Run `chaos-kitten` command using the attack chainer.
2. With config targeting any valid base URL.
3. See error indicating that the HTTP request failed due to an invalid or unresolvable URL (e.g., `http://example.com/http://example.com/...`).

## ✅ Expected Behavior
The `ChainExecutor` should pass the relative path directly to the `executor` if the executor is already configured with the base URL. The request should hit `http://example.com/api/v1/users`.

## ❌ Actual Behavior
The base URL is prepended twice, resulting in a malformed URL, causing chain execution steps to fail with HTTP 404s or Invalid URL exceptions.

## 📋 Environment
- OS: Windows
- Python version: 3.8+
- Chaos Kitten version: Main Branch (Latest)

## 📸 Screenshots/Logs
```text
httpx.ConnectError: [Errno 11001] getaddrinfo failed for http://example.com/http://example.com/...
```

## 💡 Possible Solution
Modify `ChainExecutor.execute_chain()` to simply pass `path` instead of constructing `full_url` locally. Alternatively, update `Executor.execute_attack` to check if `path.startswith('http')` and skip prepending the base URL if true.

## 📝 Additional Context
This bug breaks multi-step attack chains entirely when the target requires a base URL.

---

# Bug Report 2: BrowserExecutor.test_xss False Negatives on Immediate Alerts

## 🐛 Bug Description
In `chaos_kitten/paws/browser.py`, the `test_xss()` method navigates to a URL and then waits for an input selector to inject the payload. If an injected XSS payload triggers *immediately* upon page load (e.g., a reflected XSS in the URL parameters), the Playwright `dialog` event handler fires, setting `triggered_alert = True`. However, if the XSS payload injection breaks the DOM layout, `wait_for_selector` throws a `TimeoutError`. A broad `except Exception:` block catches this and returns `{"is_vulnerable": False}`, blindly overriding the fact that an alert actually triggered.

## 🔄 Steps to Reproduce
1. Run command targeting a URL containing a reflected XSS payload that triggers on load but breaks the page layout (hiding the target `input_selector`).
2. With config enabling the browser engine.
3. See error/logs showing `is_vulnerable: False` even though an alert was caught internally.

## ✅ Expected Behavior
If an alert was triggered during the page load or execution phase (`triggered_alert == True`), the function should return `is_vulnerable: True` regardless of whether subsequent element selectors could be found.

## ❌ Actual Behavior
The Playwright `TimeoutError` from `wait_for_selector` gets caught and returns `is_vulnerable: False`, causing a false negative.

## 📋 Environment
- OS: Windows
- Python version: 3.8+
- Chaos Kitten version: Main Branch (Latest)

## 📸 Screenshots/Logs
N/A

## 💡 Possible Solution
Update the exception handler for `wait_for_selector` (or the broad exception handler) to check `if triggered_alert: return is_vulnerable=True` before returning a generalized false outcome.

## 📝 Additional Context
This reduces the reliability of the automated XSS detection module.

---

# Bug Report 3: Swagger 2.0 Parsing Creates Invalid URLs If host Is Missing

## 🐛 Bug Description
In `chaos_kitten/brain/openapi_parser.py`, the `get_servers()` method extracts server URLs. For Swagger 2.0 specs, the `host` key is officially optional. If `host` is omitted, the spec relies on the host of the API being served. Because the code unconditionally strings together `f"{scheme}://{host}{base_path}"`, it interpolates the Python `None` object into the string if `host` is missing.

## 🔄 Steps to Reproduce
1. Run `chaos-kitten recon` or `scan`.
2. With config targeting a Swagger 2.0 specification file (JSON/YAML) that does not contain a `host` field.
3. See error during URL construction or downstream fetching where the target URL resolves to `https://None/api/...`.

## ✅ Expected Behavior
If `host` is omitted, the parser should process it gracefully—either by omitting the host portion entirely (defaulting to relative paths) or by applying a sensible fallback mechanism instead of using the literal string `"None"`.

## ❌ Actual Behavior
The parser emits malformed URLs like `"https://None/api/v1"`, breaking all downstream requests.

## 📋 Environment
- OS: Windows
- Python version: 3.8+
- Chaos Kitten version: Main Branch (Latest)

## 📸 Screenshots/Logs
N/A

## 💡 Possible Solution
Add a conditional block `if host:` before appending the scheme and host in `get_servers()`. If missing, simply append `base_path` as a relative server context, or omit the scheme://host portion entirely.

## 📝 Additional Context
N/A

---

# Bug Report 4: Async Event Loop Blocked by fingerprint_tech and scan_ports

## 🐛 Bug Description
In `chaos_kitten/brain/recon.py`, the `run` method is declared as `async def run(self)` and executes concurrently. However, it calls fully synchronous, blocking functions directly inside the async loop. Specifically, `self.scan_ports` invokes `subprocess.run(cmd, ... timeout=300)` and `self.fingerprint_tech` blocks on a synchronous `httpx.Client.get()`. This completely freezes the application's async event loop for the duration of the Nmap scan (up to 5 minutes) or the HTTP request limit.

## 🔄 Steps to Reproduce
1. Run `chaos-kitten recon` targeting a remote server.
2. With Nmap installed and enabled.
3. Notice that the entire CLI application hangs and no other concurrent tasks process until the Nmap scan completely finishes.

## ✅ Expected Behavior
Long-running synchronous I/O or shell commands inside an `async` function should be offloaded to a thread pool or converted to async equivalents, allowing the event loop to continue processing other concurrent tasks.

## ❌ Actual Behavior
The entire Python `asyncio` event loop is blocked.

## 📋 Environment
- OS: Windows
- Python version: 3.8+
- Chaos Kitten version: Main Branch (Latest)

## 📸 Screenshots/Logs
N/A

## 💡 Possible Solution
1. Wrap synchronous operations inside `await asyncio.get_running_loop().run_in_executor(None, func, *args)`.
2. Rewrite `fingerprint_tech` to use `httpx.AsyncClient`.
3. Rewrite `scan_ports` to use `asyncio.create_subprocess_exec` instead of `subprocess.run`.

## 📝 Additional Context
This severely degrading the performance benefits of using `asyncio` in the Recon phase.
