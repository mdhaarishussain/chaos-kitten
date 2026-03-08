# Chaos Kitten — 5 Bugs to Contribute

 Bug 1 — `NameError` in `scan` CORS Probe: `target_url` Is Undefined  
Difficulty: Medium  
File: [cli.py](file:///d:/opensource/chaos-kitten/chaos_kitten/cli.py)  
Lines: 232–251

 🐛 Description

When a user runs `chaos-kitten scan --cors -t http://example.com`, the CORS probe block on line 232 references `target_url`, a variable that does not exist in the `scan()` function scope. The CLI parameter is called `target`, not `target_url`. This causes an immediate `NameError`, making the entire `--cors` flag broken.

 Steps to Reproduce
1. Run: `chaos-kitten scan --cors -t http://localhost:5000 -s spec.json`
2. Observe: `NameError: name 'target_url' is not defined`

 Expected Behavior
The CORS probe should use the resolved target URL (the CLI `target` parameter or the value from `app_config["target"]["base_url"]`), send an `Origin: https://evil.example` request, and report any CORS misconfiguration findings.

 Fix Guidance
- Replace `target_url` with the correct variable (e.g. `target` or `app_config.get("target", {}).get("base_url", "")`)
- Add a guard: skip the CORS probe if no target URL is available
- Add a test for `scan --cors` to prevent regression

---

 Bug 2 — Dead Code Block After `preflight()` References Undefined Variables  
Difficulty: Hard  
File: [cli.py](file:///d:/opensource/chaos-kitten/chaos_kitten/cli.py)  
Lines: 444–475

 🐛 Description

After the `preflight()` command finishes printing its dependency table (line 442), there is an orphaned code block (lines 444–475) that:

1. Imports `Orchestrator` and references `app_config` — a variable that does not exist in `preflight()`'s scope (it exists only in `scan()`).
2. References `fail_on_critical` — another variable that belongs to the `diff()` command, not `preflight()`.
3. Runs `orchestrator.run()` and checks for critical vulnerabilities — behavior that makes no sense for a dependency-checking command.

This code appears to have been accidentally copy-pasted from `diff()`. If execution ever reached it (currently it sometimes does, since there's no `return` after line 442), it would crash with a `NameError`.

 Steps to Reproduce
1. Run: `chaos-kitten preflight`
2. If nmap is installed (line 438 condition passes), execution falls through to line 444
3. `NameError: name 'app_config' is not defined`

 Expected Behavior
`preflight` should only display the dependency status table and exit cleanly. The dead code block should be removed entirely.

 Fix Guidance
- Add `return` or remove lines 444–475 entirely
- Ensure `preflight()` ends after printing the table
- Consider adding a test that verifies `preflight` runs without errors

---

 Bug 3 — `ChainExecutor.execute_attack` Receives Full URL as `path`, Causing Double Base URL  
Difficulty: Medium  
File: [attack_chainer.py](file:///d:/opensource/chaos-kitten/chaos_kitten/brain/attack_chainer.py)  
Lines: 188–202

 🐛 Description

In `ChainExecutor.execute_chain`, the code constructs a `full_url` by prepending `base_url` to `path` (line 189):

```python
full_url = f"{base_url.rstrip('/')}{path}"
```

Then passes `full_url` as the second positional argument to `executor.execute_attack(method, full_url, payload)` on line 202. However, `Executor.execute_attack` expects `path` (a relative path), not a full URL — the `Executor` already has `self.base_url` set internally and prepends it via `httpx.AsyncClient(base_url=...)`.

This results in requests being sent to a malformed URL like `http://api.example.comhttp://api.example.com/users`, which always fails with a connection error.

 Steps to Reproduce
1. Use `AttackChainPlanner` to plan a chain, then `ChainExecutor.execute_chain(chain, "http://api.example.com")`
2. Every step fails because `execute_attack` sends to `http://api.example.com` + `http://api.example.com/users`

 Expected Behavior
Either pass just the `path` (without `base_url`) to `execute_attack`, or pass `full_url` as a keyword argument that bypasses the `Executor`'s own `base_url`.

 Fix Guidance
- Change line 202 to pass `path` (the original relative path after variable substitution) instead of `full_url`
- Or update `execute_attack` to detect and handle absolute URLs
- Also note: `execute_attack` uses keyword arguments (`method=`, `path=`), but line 202 passes them positionally — this should also be fixed

---

 Bug 4 — `ReconEngine.fingerprint_tech` and `scan_ports` Block the Async Event Loop  
Difficulty: Hard  
File: [recon.py](file:///d:/opensource/chaos-kitten/chaos_kitten/brain/recon.py)  
Lines: 84–107, 152–193, 195–236

 🐛 Description

`ReconEngine.run()` is an `async` method, but it calls two synchronous methods directly:

1. `scan_ports()` (line 86) — runs `subprocess.run(["nmap", ...])` with `timeout=300` (5 minutes!) synchronously. This completely blocks the event loop for the entire nmap scan duration per target.

2. `fingerprint_tech()` (line 105) — uses a synchronous `httpx.Client` (not `httpx.AsyncClient`) to make HTTP requests. This blocks the event loop for each target URL.

Both are called in a `for target in targets` loop, so the total blocking time multiplies with the number of targets. During this time, no other async tasks (e.g. the rate limiter, concurrent subdomain checks, or any other async feature) can run.

 Steps to Reproduce
1. Configure recon with `enabled: true` and a target that has multiple subdomains
2. Run the scan
3. Observe that the entire process freezes during port scanning and fingerprinting — no concurrent work happens

 Expected Behavior
- `scan_ports` should use `asyncio.create_subprocess_exec` instead of `subprocess.run`
- `fingerprint_tech` should use `httpx.AsyncClient` instead of `httpx.Client`
- Both should be made `async` and called with `await`

 Fix Guidance
- Convert `scan_ports` to async using `asyncio.create_subprocess_exec`
- Convert `fingerprint_tech` to async using `httpx.AsyncClient`
- Optionally, run fingerprinting concurrently with `asyncio.gather` across all target URLs

---

 Bug 5 — `ResponseAnalyzer._check_custom_indicators` Silently Miscompares Timing Units  
Difficulty: Medium  
File: [analyzer.py](file:///d:/opensource/chaos-kitten/chaos_kitten/paws/analyzer.py)  
Lines: 257–298

 🐛 Description

In `_check_custom_indicators`, the code converts `elapsed_ms` to seconds on line 264:

```python
elapsed_ms = response.get("elapsed_ms", 0) / 1000.0   convert to seconds
```

But then on line 291, it compares the now-seconds value against `response_time_gt` from the attack profile:

```python
if elapsed_ms > limit:
```

The problem is `response_time_gt` in the attack profiles is specified in seconds (e.g. `5` meaning 5 seconds). The variable name `elapsed_ms` is misleading — after division it's actually in seconds. While the math technically works out (both sides are in seconds), the variable name creates confusion. More critically, the executor returns `elapsed_ms` in milliseconds, so if any caller passes the raw `elapsed_ms` without converting, or if `response_time_gt` is defined in milliseconds in some profiles, the comparison silently produces wrong results.

Additionally, the `check_timing_anomalies` method on line 318-321 expects `elapsed_ms` and `baseline_ms` in milliseconds (threshold is `> 2000`), creating an inconsistency within the same class — one method works in ms, the other in seconds, with no documentation of which is which.

 Steps to Reproduce
1. Create an attack profile with `success_indicators: { response_time_gt: 5000 }` (intending 5000ms = 5s)
2. Target responds in 3 seconds (3000ms)
3. `_check_custom_indicators` sees: `elapsed_ms = 3000 / 1000 = 3.0`, then `3.0 > 5000` → False — misses the vulnerability
4. The profile author expected `5000ms`, but the code treats it as `5000 seconds`

 Expected Behavior
The timing unit should be consistent and clearly documented. Either:
- Keep everything in milliseconds and remove the `/1000.0` division
- Or document that `response_time_gt` must be in seconds and rename the variable to `elapsed_s`

 Fix Guidance
- Audit all attack profiles to determine whether `response_time_gt` is in seconds or ms
- Pick one unit and be consistent across `_check_custom_indicators` and `check_timing_anomalies`
- Rename variables to match their actual unit (e.g. `elapsed_s` vs `elapsed_ms`)
- Add a docstring clarifying the expected unit for `response_time_gt`
