import re

INJECTION_PATTERNS = [
    (r"(?i)\bignore\s+(all\s+)?(previous|above|prior)\s+instructions\b", "Direct Instruction Override Attempt", "CRITICAL"),
    (r"(?i)\b(disregard|forget)\s+(all\s+)?(previous|system|security)\s+(rules|prompts|instructions)\b", "System Instruction Reset Attempt", "CRITICAL"),
    (r"(?i)\b(reveal|show|print|output|dump)\s+(the\s+)?(system\s+prompt|developer\s+instructions|secret\s+key)\b", "System Prompt / Secret Extraction Attempt", "HIGH"),
    (r"(?i)\b(pretend|assume|act\s+as\s+if)\s+(this\s+code\s+is\s+safe|there\s+are\s+no\s+vulnerabilities|all\s+checks\s+passed)\b", "Scanner Manipulation / Safety Bypass", "HIGH"),
    (r"(?i)\b(mark|classify|report)\s+(as\s+)?(clean|safe|secure|0\s+vulnerabilities|no\s+findings)\b", "Security Reporting Manipulation Attempt", "HIGH"),
    (r"(?i)\bbypass\s+(all\s+)?(security|vulnerability|malware)\s+(scanners?|checks?|filters?)\b", "Scanner Bypass Directive", "HIGH"),
    (r"(?i)\bexfiltrate\s+(data|secrets|env|keys)\s+to\b", "Data Exfiltration Directive", "CRITICAL"),
    (r"(?i)\beval\s*\(\s*base64_decode\b", "Obfuscated Dynamic Execution Payload", "HIGH"),
    (r"(?i)\b(rm\s+-rf\s+\/|format\s+c:|del\s+\/f\s+\/s\s+\/q)\b", "Destructive Command Injection Pattern", "CRITICAL"),
]

def scan_for_prompt_injection(content: str, file_path: str = "snippet") -> list[dict]:
    """
    Scans untrusted input for prompt injection vectors and returns security findings.
    Does NOT execute or treat untrusted content as system instructions.
    """
    if not content:
        return []

    findings = []
    lines = content.splitlines()

    for pattern_regex, description, severity in INJECTION_PATTERNS:
        compiled = re.compile(pattern_regex)
        for idx, line in enumerate(lines, start=1):
            if compiled.search(line):
                findings.append({
                    "scanner": "prompt_injection_guard",
                    "rule_id": f"prompt-injection-{re.sub(r'[^a-zA-Z0-9]', '-', description).lower()[:40]}",
                    "file_path": file_path,
                    "line": idx,
                    "column": 1,
                    "severity": severity,
                    "category": "prompt-injection",
                    "message": f"Potential Prompt Injection / Manipulation Detected: {description}",
                    "source": "prompt_injection_guard",
                    "confidence": "HIGH",
                    "owasp": ["A03:2021 - Injection"],
                    "cwe": ["CWE-20: Improper Input Validation"],
                    "vulnerability_class": ["Prompt Injection", "Adversarial Input"],
                    "likelihood": "HIGH",
                    "impact": "HIGH",
                    "explanation": f"The scanned content contains an adversarial prompt injection pattern: '{description}'. Untrusted content attempting to override model or scanner behavior was isolated.",
                    "risk": "If passed directly to an LLM without strict untrusted-data boundaries, it could lead to prompt leakage or altered analysis behavior.",
                    "remediation": [
                        "Isolate untrusted code snippets in dedicated data containers.",
                        "Never allow user content to modify system instructions or security evaluator prompts.",
                        "Inspect input for adversarial evasion techniques."
                    ],
                    "requires_verification": True
                })

    return findings
