import os
import re
import shutil
import tempfile
import zipfile
import tarfile
import stat
from pathlib import PurePosixPath, PureWindowsPath
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
    return clean if clean not in ("", ".", "..") else "sanitized_file.txt"

def is_binary_content(data: bytes) -> bool:
    """
    Detects if raw byte content represents a binary file rather than text.
    """
    if not data:
        return False
    if b'\x00' in data:
        return True
    try:
        data.decode("utf-8")
        return False
    except UnicodeDecodeError:
        pass
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

    if ext not in ARCHIVE_EXTENSIONS | DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS and is_binary_content(content_sample):
        return FileClassification(category="Binary/executable", extension=ext,
                                  is_safe_for_static_analysis=False, is_quarantined=True,
                                  warning="Binary content detected; skipped from static parsing.")

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
            raise ValueError("Unable to extract text from this PDF.") from e

    elif ext in (".docx", ".doc"):
        try:
            if ext == ".docx":
                with zipfile.ZipFile(file_path) as archive:
                    entries = archive.infolist()
                    unpacked = sum(entry.file_size for entry in entries)
                    if (len(entries) > MAX_ARCHIVE_ENTRIES or unpacked > MAX_UNCOMPRESSED_SIZE
                            or unpacked / max(os.path.getsize(file_path), 1) > MAX_COMPRESSION_RATIO):
                        raise ValueError("Word document exceeds safe decompression limits.")
            import docx
            doc = docx.Document(file_path)
            for p in doc.paragraphs:
                if p.text:
                    extracted_text.append(p.text)
            return "\n".join(extracted_text)
        except Exception as e:
            raise ValueError("Unable to extract text from this Word document.") from e

    else:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()
        except Exception as e:
            return f"[Error reading file: {str(e)}]"

def safe_extract_archive(archive_path: str, destination_dir: str, max_uncompressed_size: int = MAX_UNCOMPRESSED_SIZE) -> list[str]:
    """Validate every member before writing; never follow links or nested archives."""
    dest = Path(destination_dir).resolve()
    archive_size = os.path.getsize(archive_path) or 1

    def validate(members):
        if len(members) > MAX_ARCHIVE_ENTRIES:
            raise ValueError("Archive exceeds maximum allowed entries limit.")
        total = 0
        seen = set()
        for name, size, is_file in members:
            path = PurePosixPath(name.replace("\\", "/"))
            if (path.is_absolute() or PureWindowsPath(name).drive or ".." in path.parts
                    or any(":" in part for part in path.parts)):
                raise ValueError(f"Zip slip / Tar traversal attempt detected: {name}")
            target = (dest / str(path)).resolve()
            if not target.is_relative_to(dest) or target == dest:
                raise ValueError(f"Zip slip / Tar traversal attempt detected: {name}")
            # Reject collisions including Windows case folding and trailing dots/spaces.
            identity = str(path).rstrip(" .").casefold()
            if is_file and identity in seen:
                raise ValueError(f"Duplicate archive entry: {name}")
            seen.add(identity)
            total += size
            if size > MAX_FILE_SIZE_BYTES or total > max_uncompressed_size:
                raise ValueError("Archive uncompressed size exceeds limit. Potential Zip Bomb.")
            if total / archive_size > MAX_COMPRESSION_RATIO:
                raise ValueError("Archive compression ratio exceeds safe limit. Potential Zip Bomb.")

    extracted = []
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            validate([(m.filename, m.file_size, not m.is_dir()) for m in members])
            if any(stat.S_ISLNK(m.external_attr >> 16) for m in members):
                raise ValueError("Archive symbolic links are not permitted.")
            for member in members:
                if member.is_dir():
                    continue
                target = dest / member.filename.replace("\\", "/")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                extracted.append(target.relative_to(dest).as_posix())
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            validate([(m.name, m.size, m.isfile()) for m in members])
            if any(not (m.isfile() or m.isdir()) for m in members):
                raise ValueError("Archive links and special files are not permitted.")
            for member in members:
                if not member.isfile():
                    continue
                target = dest / member.name.replace("\\", "/")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                extracted.append(target.relative_to(dest).as_posix())
    else:
        raise ValueError("Unsupported or invalid archive format. Use ZIP or TAR.")
    return extracted

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
