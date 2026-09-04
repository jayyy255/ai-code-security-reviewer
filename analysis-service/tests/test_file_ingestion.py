import os
import zipfile
import tempfile
import pytest
from app.services.file_ingestion_service import (
    sanitize_filename,
    classify_file,
    is_binary_content,
    safe_extract_archive,
    safe_temp_workspace,
    MAX_ARCHIVE_ENTRIES,
    MAX_UNCOMPRESSED_SIZE
)

def test_filename_sanitization():
    assert sanitize_filename("../../etc/passwd") == "passwd"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("payload\x00.py") == "payload.py"
    assert sanitize_filename("") == "unnamed_file.txt"

def test_file_classification():
    c1 = classify_file("server.js")
    assert c1.category == "Source code"
    assert c1.is_safe_for_static_analysis is True

    c2 = classify_file("docker-compose.yml")
    assert c2.category == "Configuration"

    c3 = classify_file("report.pdf")
    assert c3.category == "Text/document"

    c4 = classify_file("archive.zip")
    assert c4.category == "Archive"

    c5 = classify_file("malicious.exe")
    assert c5.category == "Binary/executable"
    assert c5.is_safe_for_static_analysis is False
    assert c5.is_quarantined is True

def test_binary_detection():
    binary_bytes = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert is_binary_content(binary_bytes) is True

    text_bytes = b"import os\nprint('Hello world')\n"
    assert is_binary_content(text_bytes) is False

def test_safe_archive_extraction():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "test.zip")
        dest_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(dest_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("app/main.py", "import os\n")
            zf.writestr("app/config.json", '{"debug": false}')

        files = safe_extract_archive(zip_path, dest_dir)
        assert len(files) == 2
        assert os.path.exists(os.path.join(dest_dir, "app", "main.py"))

def test_zip_slip_rejection():
    with tempfile.TemporaryDirectory() as temp_dir:
        zip_path = os.path.join(temp_dir, "slip.zip")
        dest_dir = os.path.join(temp_dir, "extracted")
        os.makedirs(dest_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Dangerous member path
            zf.writestr("../../evil.txt", "evil")

        with pytest.raises(ValueError, match="Zip slip"):
            safe_extract_archive(zip_path, dest_dir)
