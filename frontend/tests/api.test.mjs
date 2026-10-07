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
test('guest history has usable dates and scores without full source', async () => {
  await api.saveToHistory(report);
  const [saved] = await api.getHistory();
  assert.equal(saved.score, 85);
  assert.equal(saved.critical, 1);
  assert.ok(Number.isFinite(Date.parse(saved.timestamp)));
  assert.equal(saved.code, undefined);
  assert.equal((await api.getAnalysisResult(report.analysis_id)).analysis_id, report.analysis_id);
});
test('ephemeral results never enter browser storage', async () => {
  await api.saveToHistory({ ...report, privacy_metadata: { ephemeral_scan: true } });
  assert.equal(storage.size, 0);
  assert.equal((await api.getAnalysisResult(report.analysis_id)).analysis_id, report.analysis_id);
});
test('failed account-history sync preserves the guest report', async () => {
  await api.saveToHistory(report);
  api.setLoggedInStatus(true);
  globalThis.fetch = async () => response({ error: 'Database offline' }, 503);
  await assert.rejects(api.syncLocalHistoryToBackend(), /Database offline/);
  assert.ok(storage.get('reviewer_scan_history').includes('test-scan'));
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
