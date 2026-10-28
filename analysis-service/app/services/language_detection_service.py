"""Conservative, local language detection. Submitted code is never executed."""
import json
import re
from pathlib import Path

EXTENSIONS = {
    "python": ".py", "javascript": ".js", "typescript": ".ts", "java": ".java",
    "go": ".go", "c": ".c", "cpp": ".cpp", "csharp": ".cs", "ruby": ".rb",
    "php": ".php", "rust": ".rs", "scala": ".scala", "kotlin": ".kt",
    "dockerfile": "Dockerfile", "terraform": ".tf", "yaml": ".yml", "json": ".json",
    "bash": ".sh", "html": ".html",
}
ALIASES = {"py": "python", "js": "javascript", "jsx": "javascript", "ts": "typescript",
           "tsx": "typescript", "golang": "go", "c++": "cpp", "cc": "cpp", "c#": "csharp",
           "cs": "csharp", "rb": "ruby", "rs": "rust", "kt": "kotlin", "docker": "dockerfile",
           "tf": "terraform", "yml": "yaml", "sh": "bash"}

# Signals favor distinctive syntax; shared expressions such as eval(user_input)
# deliberately remain ambiguous instead of producing a misleading clean scan.
SIGNALS = {
    "python": [r"^\s*(?:async\s+)?def\s+\w+\s*\([^\n]*\)\s*(?:->[^\n]+)?\s*:", r"^\s*from\s+[\w.]+\s+import\s+", r"^\s*import\s+(?:os|sys|sqlite3|subprocess|requests)\b", r"^\s*(?:print|os\.system|subprocess\.run)\s*\(", r"^\s*(?:if|for|while|class)\s+[^\n{]+:\s*$", r"^#!.*python"],
    "javascript": [r"\b(?:const|let|var)\s+\w+\s*=", r"\b(?:async\s+)?function\s*\w*\s*\(", r"\bconsole\.(?:log|error|warn)\s*\(", r"\brequire\s*\(", r"=>", r"^\s*import\s+.+\s+from\s+['\"]"],
    "typescript": [r"\b(?:interface|type)\s+\w+\s*(?:=|\{)", r"\b(?:const|let|var)\s+\w+\s*:\s*\w+", r"\b\w+\??\s*:\s*(?:string|number|boolean|unknown|never|any)\b", r"\bimport\s+type\b"],
    "java": [r"^\s*import\s+java\.", r"\bpublic\s+(?:static\s+)?(?:class|void|String)\b", r"\bSystem\.out\.print", r"\bthrows\s+\w+Exception\b"],
    "go": [r"^\s*package\s+\w+", r"^\s*func\s+(?:\([^)]*\)\s*)?\w+\s*\(", r"\b\w+\s*:=", r"\bfmt\.(?:Print|Sprint|Fprint)"],
    "c": [r"^\s*#\s*include\s*[<\"](?:stdio|stdlib|string|unistd)\.h", r"\b(?:int|void)\s+main\s*\(", r"\b(?:printf|malloc|strcpy)\s*\("],
    "cpp": [r"^\s*#\s*include\s*<(?:iostream|vector|string|map|memory)>", r"\bstd::", r"\busing\s+namespace\s+std\b", r"\btemplate\s*<"],
    "csharp": [r"^\s*using\s+System\b", r"\bConsole\.(?:Write|Read)", r"\bnamespace\s+[\w.]+\s*\{", r"\bpublic\s+(?:async\s+)?Task\b"],
    "ruby": [r"^\s*require(?:_relative)?\s+['\"]", r"^\s*def\s+\w+(?:\([^\n]*\))?\s*$", r"^\s*puts\s+", r"^\s*end\s*$"],
    "php": [r"<\?php", r"\$\w+\s*=", r"\b(?:echo|include_once|require_once)\s+"],
    "rust": [r"\bfn\s+\w+\s*\(", r"^\s*use\s+[\w:]+", r"\b(?:println|format|vec)!\s*\(", r"\blet\s+mut\s+"],
    "scala": [r"\bobject\s+\w+\s+(?:extends\s+App\s*)?\{", r"\bobject\s+\w+\s+extends\s+App\b", r"\bdef\s+\w+\s*\([^\n]*\)\s*:\s*\w+\s*=", r"^\s*import\s+scala\."],
    "kotlin": [r"\bfun\s+\w+\s*\(", r"\b(?:val|var)\s+\w+\s*(?:=|:)", r"\bdata\s+class\s+"],
    "dockerfile": [r"^\s*FROM\s+\S+", r"^\s*(?:RUN|COPY|ENTRYPOINT|WORKDIR|CMD)\s+"],
    "terraform": [r'^\s*(?:resource|data)\s+"[^"]+"\s+"[^"]+"\s*\{', r'^\s*(?:provider|variable|module)\s+"[^"]+"\s*\{'],
    "yaml": [r"^---\s*$", r"^\s*[\w.-]+:\s+(?![=])[^\n{}]+$", r"^\s*[\w.-]+:\s*$", r"^\s*-\s+\w+\s*:"],
    "bash": [r"^#!.*\b(?:bash|sh)\b", r"^\s*(?:export|echo|source)\s+", r"\b(?:then|fi|esac)\s*$", r"\$\{\w+\}"],
    "html": [r"<!DOCTYPE\s+html", r"<html\b", r"<(?:div|script|body|head|form)\b[^>]*>"],
}


def detect_language(code: str, file_name: str | None = None) -> dict:
    name = Path(file_name or "snippet").name.lower()
    suffix = Path(name).suffix
    if name == "dockerfile":
        return {"language": "dockerfile", "confidence": "high"}
    for language, ext in EXTENSIONS.items():
        if suffix and suffix == ext:
            return {"language": language, "confidence": "high"}
    if suffix in (".jsx", ".tsx", ".yaml", ".hpp", ".cc", ".kts"):
        return {"language": {".jsx": "javascript", ".tsx": "typescript", ".yaml": "yaml", ".hpp": "cpp", ".cc": "cpp", ".kts": "kotlin"}[suffix], "confidence": "high"}
    sample = code[:20_000].strip()
    try:
        if isinstance(json.loads(sample), (dict, list)):
            return {"language": "json", "confidence": "high"}
    except (ValueError, RecursionError):
        pass
    scores = {lang: sum(bool(re.search(pattern, sample, re.M)) for pattern in patterns) for lang, patterns in SIGNALS.items()}
    # Supersets win when their distinctive syntax is present.
    if scores["typescript"]:
        scores["typescript"] += scores["javascript"]
        scores["javascript"] = 0
    if scores["cpp"]:
        scores["cpp"] += scores["c"]
        scores["c"] = 0
    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    language, score = ranked[0]
    if not score or score == ranked[1][1]:
        return {"language": None, "confidence": "unknown"}
    return {"language": language, "confidence": "high" if score >= 2 else "medium"}


def resolve_language(code: str, language: str | None, file_name: str | None = None) -> str | None:
    selected = (language or "auto").strip().lower()
    if selected in ("auto", "automatic"):
        return detect_language(code, file_name)["language"]
    return ALIASES.get(selected, selected)
