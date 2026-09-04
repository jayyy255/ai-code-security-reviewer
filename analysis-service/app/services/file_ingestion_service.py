import os
import re
import shutil
import tempfile
import zipfile
import tarfile
from pathlib import Path
from contextlib import contextmanager
from pydantic import BaseModel, Field

# Supported extensions classification
SOURCE_CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".c", ".cpp", ".cc", ".cxx",
    ".h", ".hpp", ".cs", ".rb", ".php", ".rs", ".scala", ".kt", ".kts", ".sh", ".bash",
    ".sql", ".html", ".htm", ".css", ".scss", ".sass", ".vue", ".svelte"
}

CONFIG_EXTENSIONS = {
    ".json", ".yaml", ".yml", ".toml", ".xml", ".ini", ".env", ".properties",
    ".conf", ".config", ".tf", ".tfvars", ".dockerfile", "dockerfile"
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".docx", ".doc", ".txt", ".md", ".rst", ".rtf", ".csv", ".tsv"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z"
}

IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp"
}

DANGEROUS_BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".msi", ".com", ".scr", ".bat", ".cmd", ".vbs", ".ps1"
}

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024       # 50 MB
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024     # 100 MB max unpacked archive
MAX_COMPRESSION_RATIO = 100                   # 100:1 Zip bomb limit
MAX_ARCHIVE_ENTRIES = 500                     # Max files in archive
MAX_ARCHIVE_DEPTH = 1                         # Disallow nested archives

class FileClassification(BaseModel):
    category: str # "Source code", "Configuration", "Text/document", "Archive", "Binary/executable", "Image", "Unknown"
    mime_type: str | None = None
    extension: str = ""
    is_safe_for_static_analysis: bool = True
    is_quarantined: bool = False
    warning: str | None = None

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes filename against path traversal (../, ..\\), null bytes, and dangerous characters.
    """
    if not filename:
        return "unnamed_file.txt"
    # Remove null bytes and control chars
    clean = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    # Remove directory traversal segments
    clean = clean.replace('\\', '/').split('/')[-1]
    clean = re.sub(r'\.+[/\\]', '', clean)
    clean = re.sub(r'[^a-zA-Z0-9_\-\.\+]', '_', clean)
    return clean or "sanitized_file.txt"

def is_binary_content(data: bytes) -> bool:
    """
    Detects if raw byte content represents a binary file rather than text.
    """
    if not data:
        return False
    if b'\x00' in data:
        return True
    # If more than 30% non-text bytes in first 1024 bytes
    sample = data[:1024]
    text_characters = bytes(range(32, 127)) + b'\n\r\t\b'
    non_text = sum(1 for byte in sample if byte not in text_characters)
    return (non_text / len(sample)) > 0.30

def classify_file(filename: str, content_sample: bytes = b"") -> FileClassification:
    """
    Classifies a file by extension and byte inspection.
    """
    clean_name = sanitize_filename(filename).lower()
    ext = os.path.splitext(clean_name)[1]
    base = os.path.basename(clean_name)

    if ext in DANGEROUS_BINARY_EXTENSIONS:
        return FileClassification(
            category="Binary/executable",
            extension=ext,
            is_safe_for_static_analysis=False,
            is_quarantined=True,
            warning="Dangerous executable/binary rejected from dynamic execution."
        )

    if base == "dockerfile" or ext in CONFIG_EXTENSIONS:
        return FileClassification(category="Configuration", extension=ext, is_safe_for_static_analysis=True)

    if ext in SOURCE_CODE_EXTENSIONS:
        return FileClassification(category="Source code", extension=ext, is_safe_for_static_analysis=True)

    if ext in ARCHIVE_EXTENSIONS:
        return FileClassification(category="Archive", extension=ext, is_safe_for_static_analysis=True)

    if ext in DOCUMENT_EXTENSIONS:
        return FileClassification(category="Text/document", extension=ext, is_safe_for_static_analysis=True)

    if ext in IMAGE_EXTENSIONS:
        return FileClassification(category="Image", extension=ext, is_safe_for_static_analysis=False)

    if is_binary_content(content_sample):
        return FileClassification(
            category="Binary/executable",
            extension=ext,
            is_safe_for_static_analysis=False,
            is_quarantined=True,
            warning="Binary content detected; skipped from static AST parsing."
        )

    return FileClassification(category="Unknown", extension=ext, is_safe_for_static_analysis=True)

def extract_text_from_document(file_path: str) -> str:
    """
    Safely extracts plain text from PDF and DOCX files without executing embedded macros or scripts.
    """
    ext = os.path.splitext(file_path)[1].lower()
    extracted_text = []

    if ext == ".pdf":
        try:
            from pypdf import PdfReader
            reader = PdfReader(file_path)
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    extracted_text.append(text)
            return "\n".join(extracted_text)
        except Exception as e:
            return f"[Error extracting PDF text: {str(e)}]"

    elif ext in (".docx", ".doc"):
        try:
            import docx
            doc = docx.Document(file_path)
            for p in doc.paragraphs:
                if p.text:
                    extracted_text.append(p.text)
            return "\n".join(extracted_text)
        except Exception as e:
            return f"[Error extracting Word text: {str(e)}]"

    else:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            return f"[Error reading file: {str(e)}]"

def safe_extract_archive(archive_path: str, destination_dir: str) -> list[str]:
    """
    Safely decompresses a zip/tar archive enforcing:
    - Path traversal checks (no absolute paths or '../')
    - Zip bomb limits (max entries, max total size, compression ratio)
    - Recursive archive limits
    Returns list of extracted relative file paths.
    """
    extracted_files = []
    total_uncompressed_size = 0
    archive_size = os.path.getsize(archive_path) or 1

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, 'r') as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ARCHIVE_ENTRIES:
                raise ValueError(f"Archive exceeds maximum allowed entries limit ({len(infolist)} > {MAX_ARCHIVE_ENTRIES}).")

            dest_path = Path(destination_dir).resolve()

            for member in infolist:
                # Path traversal check
                member_path = (dest_path / member.filename).resolve()
                if not str(member_path).startswith(str(dest_path)):
                    raise ValueError(f"Zip slip path traversal attempt detected: {member.filename}")

                total_uncompressed_size += member.file_size
                if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError(f"Archive uncompressed size exceeds limit ({total_uncompressed_size} > {MAX_UNCOMPRESSED_SIZE}). Potential Zip Bomb.")

                ratio = total_uncompressed_size / archive_size
                if ratio > MAX_COMPRESSION_RATIO:
                    raise ValueError(f"Archive compression ratio exceeds safe limit ({ratio:.1f} > {MAX_COMPRESSION_RATIO}). Potential Zip Bomb.")

                # Check recursive archive
                member_ext = os.path.splitext(member.filename)[1].lower()
                if member_ext in ARCHIVE_EXTENSIONS:
                    # Skip or reject nested archive
                    continue

                # Check dangerous binary
                if member_ext in DANGEROUS_BINARY_EXTENSIONS:
                    continue

                if not member.is_dir():
                    zf.extract(member, destination_dir)
                    extracted_files.append(member.filename)

    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, 'r:*') as tf:
            members = tf.getmembers()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                raise ValueError(f"Tar archive exceeds entry limit ({len(members)} > {MAX_ARCHIVE_ENTRIES}).")

            dest_path = Path(destination_dir).resolve()

            for member in members:
                member_path = (dest_path / member.name).resolve()
                if not str(member_path).startswith(str(dest_path)):
                    raise ValueError(f"Tar traversal attempt detected: {member.name}")

                total_uncompressed_size += member.size
                if total_uncompressed_size > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError("Tar uncompressed size exceeds limit.")

                member_ext = os.path.splitext(member.name)[1].lower()
                if member_ext in DANGEROUS_BINARY_EXTENSIONS:
                    continue

                if member.isfile():
                    tf.extract(member, destination_dir)
                    extracted_files.append(member.name)
    else:
        raise ValueError("Unsupported or invalid archive format.")

    return extracted_files

@contextmanager
def safe_temp_workspace():
    """
    Context manager creating an isolated temporary workspace with guaranteed cleanup.
    Never executes or installs scripts inside the temp folder.
    """
    temp_dir = tempfile.mkdtemp(prefix="sec_scan_")
    try:
        yield temp_dir
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
