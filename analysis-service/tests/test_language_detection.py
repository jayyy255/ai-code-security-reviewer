import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.language_detection_service import detect_language, resolve_language


@pytest.mark.parametrize("language,code", [
    ("python", 'import os\nos.system("ping " + host)'),
    ("javascript", 'const command = input;\nfunction run() { eval(command); }'),
    ("typescript", 'const name: string = input;\ninterface User { name: string }'),
    ("java", 'import java.sql.*;\npublic class App { public void run() {} }'),
    ("go", 'package main\nfunc main() { fmt.Println("hi") }'),
    ("c", '#include <stdio.h>\nint main() { printf("hi"); }'),
    ("cpp", '#include <iostream>\nint main() { std::cout << "hi"; }'),
    ("csharp", 'using System;\nnamespace App { public class Program { Console.WriteLine("hi"); } }'),
    ("ruby", 'require "json"\ndef run\n puts "hi"\nend'),
    ("php", '<?php\n$name = $_GET["name"];\necho $name;'),
    ("rust", 'use std::io;\nfn main() { println!("hi"); }'),
    ("scala", 'object Main extends App {\nval x = 1\n}'),
    ("kotlin", 'fun main() { val name = "hi" }'),
    ("dockerfile", 'FROM node:22-alpine\nUSER root\nRUN echo hello'),
    ("terraform", 'resource "aws_security_group" "web" {\n ingress {}\n}'),
    ("yaml", 'services:\n  web:\n    image: nginx\n'),
    ("json", '{"name": "example", "debug": true}'),
    ("bash", '#!/bin/bash\necho "hello"\n'),
])
def test_detect_supported_languages(language, code):
    assert detect_language(code)["language"] == language


def test_ambiguous_code_requires_manual_override():
    assert detect_language('eval(user_input)')["language"] is None
    assert resolve_language('eval(user_input)', 'python') == 'python'
    assert resolve_language('eval(user_input)', 'js') == 'javascript'


def test_auto_scan_uses_detected_parser_and_real_source_snippet():
    client = TestClient(app, headers={"X-Analysis-Token": "test-analysis-service-token-32-characters"})
    code = 'import os\nos.system("ping " + host)\n'
    detection = client.post('/api/v1/language/detect', json={"code": code}).json()
    assert detection["language"] == 'python'
    response = client.post('/api/v1/files/scan', json={"code": code, "language": "auto", "ephemeral": True})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data['language'] == 'python'
    assert data['files_analyzed'] == ['snippet.py']
    assert any('command' in f['rule_id'] and 'os.system' in (f['snippet'] or '') for f in data['findings'])


def test_uncertain_auto_scan_returns_a_helpful_error():
    client = TestClient(app, headers={"X-Analysis-Token": "test-analysis-service-token-32-characters"})
    response = client.post('/api/v1/files/scan', json={"code": "eval(user_input)", "language": None})
    assert response.status_code == 422
    assert 'Select a language' in response.json()['detail']
