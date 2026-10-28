// Run against the local test stack, never a shared production database.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const base = process.env.TEST_BASE_URL || 'http://127.0.0.1:5173/api';
const password = 'local-test-pass-42';

function client() {
  let cookie = '';
  const send = async (path, body, method = body ? 'POST' : 'GET') => {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
    const setCookie = response.headers.get('set-cookie');
    if (setCookie) cookie = setCookie.split(';')[0];
    return { status: response.status, data: await response.json() };
  };
  send.cookie = () => cookie;
  send.restore = value => { cookie = value; };
  return send;
}

test('real gateway, account, scans, privacy, ownership, and vault lifecycle', { timeout: 180000 }, async () => {
  const owner = client();
  const other = client();
  const guest = client();
  const username = `integration_${Date.now()}`;
  const account = { username, email: `${username}@example.test`, password };
  assert.equal((await guest('/health')).data.database, true);
  assert.equal((await guest('/api/v1/scans/missing')).status, 401);
  for (const route of ['/analyze', '/api/v1/files/scan', '/api/v1/files/scan-batch', '/api/v1/commits/analyze', '/api/v1/language/detect']) {
    assert.equal((await guest(route, { code: 'print(1)' })).status, 401, route);
  }
  assert.equal((await owner('/auth/signup', account)).status, 201);
  assert.equal((await owner('/auth/me')).data.user.username, username);
  const invalidRepo = await owner('/api/v1/commits/analyze', { repository_url: 'http://127.0.0.1/private' });
  assert.equal(invalidRepo.status, 400, 'Repository requests cannot access internal URLs');
  assert.equal((await other('/auth/signup', account)).status, 400);
  const revokedCookie = owner.cookie();
  assert.equal((await owner('/auth/logout', {})).status, 200);
  const replay = client(); replay.restore(revokedCookie);
  assert.equal((await replay('/api/v1/files/scan', { code: 'print(1)' })).status, 401);
  assert.equal((await replay('/history')).status, 401);
  assert.equal((await owner('/auth/me')).data.user, null);
  assert.equal((await owner('/auth/login', { username, password: 'wrong' })).status, 400);
  assert.equal((await owner('/auth/login', { username: account.email, password })).status, 200);

  const payload = { code: 'import os\nos.system("ping " + host)\n', language: 'python', file_name: 'network.py' };
  assert.equal((await owner('/api/v1/language/detect', { code: payload.code })).data.language, 'python');
  const scan = await owner('/api/v1/files/scan', payload);
  assert.equal(scan.status, 200, JSON.stringify(scan.data));
  assert.ok(scan.data.findings.some(f => f.rule_id.includes('command')));
  assert.ok(scan.data.findings.every(f => f.explanation && f.remediation.length));
  assert.equal(scan.data.is_demo, undefined);
  const id = scan.data.analysis_id;
  const history = await owner('/history');
  assert.equal(history.status, 200);
  assert.ok(history.data.some(record => record.analysis_id === id));
  const saved = await owner(`/api/v1/scans/${id}`);
  assert.equal(saved.status, 200);
  assert.equal(saved.data.code, undefined);
  assert.equal(saved.data.score, scan.data.summary.security_score);

  const otherName = `${username}_other`;
  assert.equal((await other('/auth/signup', { username: otherName, email: `${otherName}@example.test`, password })).status, 201);
  assert.equal((await other(`/api/v1/scans/${id}`)).status, 404);
  assert.equal((await other(`/api/v1/scans/${id}`, null, 'DELETE')).status, 404);
  assert.equal((await other('/history')).data.length, 0);
  assert.equal((await other(`/history/${id}`, null, 'DELETE')).status, 404);
  assert.equal((await other('/history', null, 'DELETE')).status, 200);
  assert.equal((await owner(`/api/v1/scans/${id}`)).status, 200);

  const privateScan = await owner('/api/v1/files/scan', { ...payload, ephemeral: true });
  assert.equal(privateScan.status, 200);
  assert.equal((await owner(`/api/v1/scans/${privateScan.data.analysis_id}`)).status, 404);
  assert.equal((await owner('/history', privateScan.data)).status, 405);
  assert.equal((await owner('/api/v1/files/scan', { code: ' ', language: 'python' })).status, 422);

  const form = new FormData();
  form.append('files', new Blob(['const token = "AKIAIOSFODNN7EXAMPLE";']), 'config.js');
  form.append('files', new Blob([new Uint8Array([0, 255, 0, 42])]), 'image.png');
  form.append('ephemeral', 'true');
  const uploaded = await fetch(`${base}/api/v1/files/scan-batch`, { method: 'POST', headers: { Cookie: owner.cookie() }, body: form });
  const batch = await uploaded.json();
  assert.equal(uploaded.status, 200, JSON.stringify(batch));
  assert.ok(batch.findings.some(f => f.category === 'secrets'));
  assert.ok(batch.files_skipped.some(file => file.includes('image.png')));
  assert.equal(batch.privacy_metadata.ephemeral_scan, true);

  assert.equal((await owner(`/api/v1/scans/${id}`, null, 'DELETE')).status, 200);
  assert.equal((await owner(`/api/v1/scans/${id}`)).status, 404);
  // The second account cannot forge or delete another account's report.
  assert.equal((await other('/history', { ...scan.data, user: saved.data.user, _id: saved.data._id })).status, 405);
  assert.equal((await other(`/history/${privateScan.data.analysis_id}`, null, 'DELETE')).status, 404);
  const crossOrigin = await fetch(`${base}/api/v1/files/scan`, { method: 'POST', headers: { Cookie: owner.cookie(), Origin: 'https://attacker.example', 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  assert.equal(crossOrigin.status, 403);
  assert.equal((await owner('/history', null, 'DELETE')).status, 200);
  assert.equal((await owner('/history')).data.length, 0);
});
