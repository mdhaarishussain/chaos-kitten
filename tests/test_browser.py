import pytest
import asyncio
import sys
from unittest.mock import MagicMock, AsyncMock, patch

# Mock Playwright classes for testing
class MockDialog:
    def __init__(self, type_master="alert", message="XSS"):
        self.type = type_master
        self.message = message
        self.dismiss = AsyncMock()

class MockPage:
    def __init__(self):
        self.goto = AsyncMock()
        self.fill = AsyncMock()
        self.press = AsyncMock()
        self.title = AsyncMock(return_value="Test Page Title")
        self.wait_for_selector = AsyncMock()
        self.wait_for_timeout = AsyncMock()
        self.screenshot = AsyncMock()
        self.close = AsyncMock()
        self.is_visible = AsyncMock(return_value=True)
        self.listeners = {}

    def on(self, event, handler):
        self.listeners[event] = handler
    
    async def trigger_dialog(self, dialog_type="alert", message="XSS"):
        if "dialog" in self.listeners:
            mock_dialog = MockDialog(dialog_type, message)
            if asyncio.iscoroutinefunction(self.listeners["dialog"]):
                await self.listeners["dialog"](mock_dialog)
            else:
                self.listeners["dialog"](mock_dialog)

    def trigger_console(self, msg_type="log", text="Hello"):
        if "console" in self.listeners:
            msg = MagicMock()
            msg.type = msg_type
            msg.text = text
            if asyncio.iscoroutinefunction(self.listeners["console"]):
                pass # console listener is usually sync lambda in our code
            else:
                self.listeners["console"](msg)

class MockContext:
    def __init__(self):
        self.page = MockPage()
        self.new_page = AsyncMock(return_value=self.page)
        self.close = AsyncMock()

class MockBrowser:
    def __init__(self):
        self.context = MockContext()
        self.new_context = AsyncMock(return_value=self.context)
        self.close = AsyncMock()

class MockPlaywrightObj:
    def __init__(self):
        self.browser = MockBrowser()
        self.chromium = MagicMock()
        self.chromium.launch = AsyncMock(return_value=self.browser)
        self.stop = AsyncMock()

# Patch async_playwright before importing module if possible, 
# or patch where it is used.
# Since the module executes `from playwright.async_api import ...` at top level,
# we need to mock sys.modules["playwright.async_api"] if we want to avoid ImportError
# in environments without playwright.

# Create a dummy module for playwright.async_api
mock_pw_module = MagicMock()
mock_pw_module.async_playwright = MagicMock()
mock_pw_module.Error = Exception
sys.modules["playwright.async_api"] = mock_pw_module

from chaos_kitten.paws.browser import BrowserAutomation

@pytest.fixture
def mock_playwright_setup():
    with patch("chaos_kitten.paws.browser.async_playwright") as mock_ap:
        mock_p_obj = MockPlaywrightObj()
        # async_playwright() context manager or function? 
        # In code: `self._playwright = await async_playwright().start()` 
        # So async_playwright() returns a ContextManager whose __aenter__ returns Playwright execution object?
        # Actually standard usage is: `async with async_playwright() as p:` or 
        # `p = await async_playwright().start()`
        
        # We need to mock what `async_playwright()` returns.
        # It returns a PlaywrightContextManager
        mock_cm = MagicMock()
        mock_cm.start = AsyncMock(return_value=mock_p_obj)
        mock_ap.return_value = mock_cm
        
        yield mock_ap, mock_p_obj

@pytest.mark.asyncio
async def test_ctx_manager(mock_playwright_setup):
    """Test context manager entry and exit."""
    mock_ap, mock_p = mock_playwright_setup
    
    # Ensure PLAYWRIGHT_AVAILABLE is True for this test
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        async with BrowserAutomation(headless=True) as browser:
            assert browser._playwright is not None
            assert browser._browser is not None
            assert browser._context is not None
            mock_p.chromium.launch.assert_called_with(headless=True)
        
        # Verify cleanup
        mock_p.browser.context.close.assert_called_once()
        mock_p.browser.close.assert_called_once()
        mock_p.stop.assert_called_once()

@pytest.mark.asyncio
async def test_xss_success(mock_playwright_setup):
    """Test XSS detection when alert is triggered."""
    mock_ap, mock_p = mock_playwright_setup
    page = mock_p.browser.context.page
    
    # We need to trigger the dialog side effect when page.wait_for_timeout is called
    async def side_effect_wait(*args, **kwargs):
        await page.trigger_dialog("alert", "XSS Alert")
    
    page.wait_for_timeout.side_effect = side_effect_wait
    
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        async with BrowserAutomation() as browser:
            result = await browser.test_xss(
                url="http://test.com",
                payload="<script>alert(1)</script>",
                input_selector="#search"
            )
            
            assert result["is_vulnerable"] is True
            assert result["screenshot_path"] is not None
            
            page.goto.assert_called_with("http://test.com", timeout=10000)
            page.fill.assert_called_with("#search", "<script>alert(1)</script>")
            page.screenshot.assert_called_once()

@pytest.mark.asyncio
async def test_xss_no_vulnerability(mock_playwright_setup):
    """Test XSS detection when no alert is triggered."""
    mock_ap, mock_p = mock_playwright_setup
    page = mock_p.browser.context.page
    
    page.wait_for_timeout.side_effect = None # No dialog trigger
    
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        async with BrowserAutomation() as browser:
            result = await browser.test_xss(
                url="http://test.com",
                payload="safe",
                input_selector="#search"
            )
            
            assert result["is_vulnerable"] is False
            assert result["screenshot_path"] is None
            
            page.screenshot.assert_not_called()

@pytest.mark.asyncio
async def test_get_page_title(mock_playwright_setup):
    """Test getting page title."""
    mock_ap, mock_p = mock_playwright_setup
    
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        async with BrowserAutomation() as browser:
            result = await browser.get_page_title("http://test.com")
            
            assert result["title"] == "Test Page Title"
            mock_p.browser.context.page.title.assert_called_once()

@pytest.mark.asyncio
async def test_get_console_logs(mock_playwright_setup):
    """Test capturing console logs."""
    mock_ap, mock_p = mock_playwright_setup
    page = mock_p.browser.context.page
    
    # Trigger logs during wait
    async def side_effect_wait(*args, **kwargs):
        page.trigger_console("log", "Test Log")
    
    page.wait_for_timeout.side_effect = side_effect_wait
    
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        async with BrowserAutomation() as browser:
            result = await browser.get_console_logs("http://test.com")
            
            assert len(result["logs"]) == 1
            assert "log: Test Log" in result["logs"][0]

@pytest.mark.asyncio
async def test_playwright_missing():
    """Test behavior when Playwright is not installed."""
    # We force global variable to False
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", False):
        browser = BrowserAutomation()
        
        # Should log error and return self but not launch anything
        async with browser as b:
            assert b._playwright is None
        
        # Methods should fail gracefully
        result = await browser.test_xss("http://test.com", "payload")
        assert result["is_vulnerable"] is False
        assert "Playwright is not installed" in result["error"]

@pytest.mark.asyncio
async def test_uninitialized_usage():
    """Test usage without context manager."""
    browser = BrowserAutomation()
    
    with patch("chaos_kitten.paws.browser.PLAYWRIGHT_AVAILABLE", True):
        # We manually check the raise by calling _check_playwright implicitly via methods
        # Because _browser is None, it should raise RuntimeError caught inside methods
        result = await browser.test_xss("http://test.com", "payload")
        assert result["is_vulnerable"] is False
        assert "Browser not initialized" in result["error"]
