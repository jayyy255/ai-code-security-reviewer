import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import * as api from '../src/services/api.js';

let storage;
beforeEach(() => {
  storage = new Map();
  globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  };
  api.setLoggedInStatus(false);
});
const response = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
const report = {
  analysis_id: 'test-scan', findings: [], code: 'private complete source',
  summary: { security_score: 85, critical: 1 }, privacy_metadata: { ephemeral_scan: false },
};

test('failed paste and upload requests never return synthetic findings', async () => {
  globalThis.fetch = async () => response({ detail: 'Engine failed' }, 503);
  await assert.rejects(api.analyzeCode('print(1)', 'python'), /Engine failed/);
  await assert.rejects(api.scanUploadedFiles([new File(['test'], 'test.py')]), /Engine failed/);
  assert.equal(storage.size, 0);
});
test('history comes from authenticated server and strips full source', async () => {
  globalThis.fetch = async (url) => { assert.ok(url.endsWith('/history')); return response([report]); };
  const [saved] = await api.getHistory();
  assert.equal(saved.score, 85);
  assert.equal(saved.code, undefined);
});

test('ephemeral results never enter browser storage', async () => {
  await api.saveToHistory({ ...report, privacy_metadata: { ephemeral_scan: true } });
  assert.equal(storage.size, 0);
  assert.equal((await api.getAnalysisResult(report.analysis_id)).analysis_id, report.analysis_id);
});
test('expired sessions clear cached reports and notify the UI', async () => {
  let expired = false;
  globalThis.window = { dispatchEvent: event => { expired = event.type === 'reviewer:unauthorized'; } };
  await api.saveToHistory(report);
  globalThis.fetch = async () => response({ error: 'Please log in.' }, 401);
  await assert.rejects(api.getHistory(), /Please log in/);
  assert.ok(expired);
  await assert.rejects(api.getAnalysisResult(report.analysis_id), /Please log in/);
});

test('failed delete and purge are reported to the caller', async () => {
  api.setLoggedInStatus(true);
  globalThis.fetch = async () => response({ error: 'Deletion failed' }, 500);
  await assert.rejects(api.deleteFromHistory('test-scan'), /Deletion failed/);
  await assert.rejects(api.clearHistory(), /Deletion failed/);
});
test('upload forwards original binary bytes via multipart', async () => {
  const file = new File([new Uint8Array([0, 255, 128, 32])], 'archive.zip');
  globalThis.fetch = async (_url, options) => {
    assert.ok(options.body instanceof FormData);
    assert.deepEqual(new Uint8Array(await options.body.get('files').arrayBuffer()), new Uint8Array([0, 255, 128, 32]));
    assert.equal(options.body.get('ephemeral'), 'true');
    return response({ ...report, privacy_metadata: { ephemeral_scan: true } });
  };
  await api.scanUploadedFiles([file], true);
  assert.equal(storage.size, 0);
});

test('automatic paste sends no misleading filename or explicit parser', async () => {
  globalThis.fetch = async (_url, options) => {
    const payload = JSON.parse(options.body);
    assert.equal(payload.language, null);
    assert.equal(payload.file_name, 'snippet');
    return response({ ...report, language: 'javascript' });
  };
  assert.equal((await api.analyzeCode('const x = input;', null)).language, 'javascript');
});

test('language detection supports canceling stale requests', async () => {
  const controller = new AbortController();
  const aborted = new DOMException('Canceled', 'AbortError');
  globalThis.fetch = async (url, options) => {
    assert.ok(url.endsWith('/api/v1/language/detect'));
    assert.equal(options.signal, controller.signal);
    throw aborted;
  };
  await assert.rejects(api.detectCodeLanguage('print(1)', controller.signal), err => err === aborted);
});
