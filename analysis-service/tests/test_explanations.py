import asyncio
import json
from types import SimpleNamespace

from app.services.explanation_service import generate_explanations


def finding(path='app.py', line=1, **changes):
    return {'rule_id': 'command-injection', 'file_path': path, 'line': line,
            'message': 'Unsafe command execution', 'category': 'injection', **changes}


def test_local_advice_works_without_a_provider_key(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    result = asyncio.run(generate_explanations([finding()], 'os.system(command)', 'python'))[0]
    assert result['advisory_source'] == 'local'
    assert result['requires_verification'] is True
    assert result['snippet'] == 'os.system(command)'
    assert 'subprocess.run' in result['fixed_code']


def test_local_advice_does_not_offer_python_code_for_javascript(monkeypatch):
    monkeypatch.delenv('GEMINI_API_KEY', raising=False)
    result = asyncio.run(generate_explanations([finding('app.js')], language='javascript'))[0]
    assert result['explanation']
    assert result['remediation']
    assert result['fixed_code'] is None


def mock_ai(monkeypatch, generate):
    from google import genai
    monkeypatch.setenv('GEMINI_API_KEY', 'synthetic-test-key')
    monkeypatch.setattr(genai, 'Client', lambda **kwargs: SimpleNamespace(aio=SimpleNamespace(models=SimpleNamespace(generate_content=generate))))


def test_ai_explanations_map_to_occurrences_and_validate_field_types(monkeypatch):
    async def generate(**kwargs):
        return SimpleNamespace(text=json.dumps([
            {'finding_id': 0, 'explanation': 'First occurrence', 'remediation': ['First fix']},
            {'finding_id': 1, 'explanation': {'invalid': 'object'}, 'risk': ['invalid'],
             'fixed_code': ['invalid'], 'remediation': [{'invalid': 'object'}]},
        ]))
    mock_ai(monkeypatch, generate)
    result = asyncio.run(generate_explanations([finding(line=1), finding(line=2)], 'first\nsecond', 'python'))
    assert result[0]['explanation'] == 'First occurrence'
    assert result[1]['explanation'] != 'First occurrence'
    assert isinstance(result[1]['explanation'], str)
    assert isinstance(result[1]['risk'], str)
    assert isinstance(result[1]['fixed_code'], str)
    assert result[1]['advisory_source'] == 'local'
    assert all(isinstance(value, str) for value in result[1]['remediation'])


def test_ai_context_uses_only_local_snippets_and_redacts_secrets(monkeypatch):
    async def generate(**kwargs):
        assert 'PRIVATE_FILE_CONTENT_OUTSIDE_FINDINGS' not in kwargs['contents']
        assert 'AKIAIOSFODNN7EXAMPLE' not in kwargs['contents']
        assert '[credential redacted]' in kwargs['contents']
        assert kwargs['config']['system_instruction']
        return SimpleNamespace(text='[]')
    mock_ai(monkeypatch, generate)
    asyncio.run(generate_explanations([
        finding(category='secrets', snippet='AWS_KEY=AKIAIOSFODNN7EXAMPLE'),
    ], 'PRIVATE_FILE_CONTENT_OUTSIDE_FINDINGS', 'python'))
