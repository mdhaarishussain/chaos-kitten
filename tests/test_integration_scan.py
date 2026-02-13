import os
import subprocess
import sys
import time

import pytest
import requests
from typer.testing import CliRunner

from chaos_kitten.cli import app

runner = CliRunner()

DEMO_APP_PATH = os.path.join("examples", "demo_api", "app.py")
DEMO_PORT = 5001
DEMO_URL = f"http://localhost:{DEMO_PORT}"


@pytest.fixture(scope="module")
def demo_server():
    """Start the demo API server for integration tests."""
    # Ensure the demo app file exists
    if not os.path.exists(DEMO_APP_PATH):
        pytest.skip(f"Demo app not found at {DEMO_APP_PATH}")

    # Check if port is already in use
    try:
        requests.get(f"{DEMO_URL}/api/health", timeout=1)
        # Verify it's not a lingering process from a previous run unless we want to reuse it
        # pytest.fail(f"Port {DEMO_PORT} is already in use. Please stop the existing server.")
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        pass

    # Start the server
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["FLASK_APP"] = DEMO_APP_PATH

    # Use flask run to control the port
    process = subprocess.Popen(
        [sys.executable, "-m", "flask", "run", "--port", str(DEMO_PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )

    # Wait for server to start
    max_retries = 20
    for _ in range(max_retries):
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Demo server process exited prematurely.\nStdout: {stdout}\nStderr: {stderr}"
            )

        try:
            response = requests.get(f"{DEMO_URL}/api/health", timeout=1)
            if response.status_code == 200:
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    else:
        process.terminate()
        stdout, stderr = process.communicate()
        pytest.fail(
            f"Demo server failed to start within timeout.\nStdout: {stdout}\nStderr: {stderr}"
        )

    yield process

    # Teardown
    # Use taskkill to ensure entire process tree is killed on Windows
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        process.terminate()

    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


def test_scan_demo_integration(demo_server, tmp_path):
    """
    Test scan --demo command end-to-end.

    Requirements:
    1. Use existing demo API/spec under examples/.
    2. Verify non-zero exit on failure (handled by runner.invoke check).
    3. Validate that a report file is created with expected metadata.
    """
    # Create the output directory
    output_dir = tmp_path / "reports"
    output_dir.mkdir()

    # Run the scan command
    # Use environment variables to force no API key requirement if logic changes
    env = os.environ.copy()

    # Override the default demo target to use our custom port
    result = runner.invoke(
        app,
        ["scan", "--demo", "--target", DEMO_URL, "--output", str(output_dir)],
        env=env,
    )

    # Assertions
    if result.exit_code != 0:
        print(f"Scan failed with exit code {result.exit_code}")
        print(result.stdout)
        # Iterate to show traceback if any

    assert result.exit_code == 0

    # Check for report file
    files = list(output_dir.glob("*.html"))
    if not files:
        files = list(output_dir.glob("*.*"))

    assert len(files) > 0, f"No report files found in {output_dir}. Files: {files}"

    # Check report content (basic check)
    report_content = files[0].read_text(encoding="utf-8")
    assert "Chaos Kitten" in report_content
