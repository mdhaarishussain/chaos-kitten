"""Browser Automation - Playwright integration for XSS detection."""

import logging
import asyncio
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        Dialog,
        Error as PlaywrightError,
        Page,
        Playwright,
        async_playwright,
    )

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    # Define dummy types for type hinting if Playwright is missing
    Playwright = Any
    Browser = Any
    BrowserContext = Any
    Page = Any
    Dialog = Any
    PlaywrightError = Exception

    logger.warning(
        "Playwright not installed. Browser automation features will be disabled."
    )


class BrowserExecutor:
    """Headless browser Executor for exploit validation.

    Uses Playwright to:
    - Perform browser-based authentication
    - Inject XSS/CSRF payloads
    - Detect alert() popups
    - Capture screenshots of successful exploitation
    - Handoff session state to HTTP Executor
    """

    def __init__(self, headless: bool = True, timeout: int = 10000) -> None:
        """Initialize browser executor.

        Args:
            headless: Run browser in headless mode. Default True.
            timeout: Default timeout in milliseconds. Default 10000.
        """
        self.headless = headless
        self.timeout = timeout
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._playwright_available = PLAYWRIGHT_AVAILABLE

    async def __aenter__(self) -> "BrowserExecutor":
        """Context manager entry - launch browser."""
        if not self._playwright_available:
            logger.error("Attempted to launch browser but Playwright is not installed.")
            return self

        try:
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless
            )
            self._context = await self._browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720}
            )
            self._page = await self._context.new_page()
            logger.debug("Browser launched successfully.")
        except Exception as e:
            logger.error(f"Failed to launch browser: {e}")
            if self._playwright:
                await self._playwright.stop()
            raise

        return self

    async def __aexit__(
        self, exc_type: Any, exc_val: Any, exc_tb: Any
    ) -> None:  # type: ignore
        """Context manager exit - close browser."""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.debug("Browser closed.")

    def _check_playwright(self) -> None:
        """Check if Playwright is available and initialized."""
        if not self._playwright_available:
            raise RuntimeError(
                "Playwright is not installed. Install with 'pip install playwright'."
            )
        if not self._browser or not self._context:
            raise RuntimeError(
                "Browser not initialized. Use 'async with BrowserExecutor()' context manager."
            )

    async def login(
        self,
        login_url: str,
        username: str,
        password: str,
        username_selector: str = "input[name='username']",
        password_selector: str = "input[name='password']",
        submit_selector: str = "button[type='submit']",
        wait_for_selector: Optional[str] = None
    ) -> bool:
        """
        Perform browser-based login automation.

        Args:
            login_url: The login page URL
            username: Username credential
            password: Password credential
            username_selector: CSS selector for username field
            password_selector: CSS selector for password field
            submit_selector: CSS selector for submit button
            wait_for_selector: Optional selector to wait for after login (indicates success)

        Returns:
            bool: True if login appears successful
        """
        self._check_playwright()
        page = self._page
        if not page:
            # Should have commonly been created in __aenter__
            # But let's handle if context/page management is different
            page = await self._context.new_page()
            self._page = page

        try:
            logger.info(f"Navigating to login page: {login_url}")
            await page.goto(login_url, timeout=self.timeout)
            
            # Fill credentials
            await page.fill(username_selector, username)
            await page.fill(password_selector, password)
            
            # Click submit
            await page.click(submit_selector)
            
            # Wait for navigation or success/failure indicator
            if wait_for_selector:
                await page.wait_for_selector(wait_for_selector, timeout=self.timeout)
            else:
                await page.wait_for_load_state("networkidle")
            
            logger.info("Login flow completed.")
            return True
        except Exception as e:
            logger.error(f"Login failed: {e}")
            return False

    async def get_session_state(self) -> Dict[str, Any]:
        """
        Export session state (cookies, storage) for use in HTTP Executor.
        
        Returns:
            Dict containing cookies and potential headers.
        """
        self._check_playwright()
        cookies = await self._context.cookies()
        
        # Convert playwright cookies to dict specifically for httpx/requests
        cookie_dict = {c['name']: c['value'] for c in cookies}
        
        # We could also export local storage if needed, via page.evaluate
        return {
            "cookies": cookie_dict,
            "headers": {
                "User-Agent": await self._page.evaluate("navigator.userAgent") 
            }
        }

    async def test_xss(
        self,
        url: str,
        payload: str,
        input_selector: str = "input",
        screenshot_dir: str = "reports/screenshots",
    ) -> Dict[str, Any]:
        """Test for XSS vulnerability by checking for alert dialogs.

        Args:
            url: Page URL to test
            payload: XSS payload to inject
            input_selector: CSS selector for input field
            screenshot_dir: Directory to save screenshots

        Returns:
            Result dict with is_vulnerable, screenshot_path, error.
        """
        try:
            self._check_playwright()
        except RuntimeError as e:
            return {"is_vulnerable": False, "screenshot_path": None, "error": str(e)}

        page: Optional[Page] = None
        triggered_alert = False
        screenshot_path = None

        try:
            page = await self._context.new_page()

            async def handle_dialog(dialog: Dialog) -> None:
                nonlocal triggered_alert
                msg = dialog.message
                logger.info(f"Dialog triggered: {dialog.type} - {msg}")
                # We consider any alert an XSS success in this context if triggered by our payload
                triggered_alert = True
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            logger.debug(f"Navigating to {url}")
            await page.goto(url, timeout=self.timeout)

            logger.debug(f"Filling selector '{input_selector}' with payload")
            # Wait for selector
            try:
                await page.wait_for_selector(
                    input_selector, state="visible", timeout=self.timeout / 2
                )
            except Exception:
                return {
                    "is_vulnerable": False,
                    "screenshot_path": None,
                    "error": f"Selector '{input_selector}' not found",
                }

            await page.fill(input_selector, payload)
            # Try to trigger via Enter key (common for search/forms)
            await page.press(input_selector, "Enter")

            # Wait for potential alert
            # If alert triggers, handle_dialog is called
            await page.wait_for_timeout(2000)

            if triggered_alert:
                logger.warning(
                    f"XSS Vulnerability detected at {url} with payload {payload}"
                )

                # Verify directory exists
                os.makedirs(screenshot_dir, exist_ok=True)

                # Generate unique filename
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"xss_proven_{timestamp}.png"
                screenshot_path = os.path.join(screenshot_dir, filename)

                await page.screenshot(path=screenshot_path)

            return {
                "is_vulnerable": triggered_alert,
                "screenshot_path": screenshot_path,
                "error": None,
            }

        except PlaywrightError as e:
            logger.error(f"Playwright error during XSS test: {e}")
            return {"is_vulnerable": False, "screenshot_path": None, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error during XSS test: {e}")
            return {"is_vulnerable": False, "screenshot_path": None, "error": str(e)}
        finally:
            if page:
                await page.close()

    async def get_page_title(self, url: str) -> Dict[str, Any]:
        """Navigate to URL and return page title.

        Args:
            url: Target URL

        Returns:
            Dict containing title or error.
        """
        try:
            self._check_playwright()
        except RuntimeError as e:
            return {"title": None, "error": str(e)}

        page: Optional[Page] = None
        try:
            page = await self._context.new_page()
            await page.goto(url, timeout=self.timeout)
            title = await page.title()
            return {"title": title, "error": None}

        except PlaywrightError as e:
            logger.error(f"Playwright error getting title: {e}")
            return {"title": None, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error getting title: {e}")
            return {"title": None, "error": str(e)}
        finally:
            if page:
                await page.close()

    async def get_console_logs(self, url: str) -> Dict[str, Any]:
        """Capture browser console logs/errors.

        Args:
            url: Target URL

        Returns:
            Dict containing list of logs or error.
        """
        try:
            self._check_playwright()
        except RuntimeError as e:
            return {"logs": [], "error": str(e)}

        logs: List[str] = []
        page: Optional[Page] = None

        try:
            page = await self._context.new_page()

            page.on("console", lambda msg: logs.append(f"{msg.type}: {msg.text}"))

            await page.goto(url, timeout=self.timeout)
            # Wait for logs
            await page.wait_for_timeout(1000)

            return {"logs": logs, "error": None}

        except PlaywrightError as e:
            logger.error(f"Playwright error getting logs: {e}")
            return {"logs": [], "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error getting logs: {e}")
            return {"logs": [], "error": str(e)}
        finally:
            if page:
                await page.close()
