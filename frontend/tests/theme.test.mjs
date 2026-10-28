import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readThemePreference, resolveTheme } from '../src/services/theme-preference.js';

test('uses device appearance until the user chooses a theme', () => {
  assert.equal(resolveTheme(null, true), 'dark');
  assert.equal(resolveTheme(null, false), 'light');
  assert.equal(resolveTheme('light', true), 'light');
  assert.equal(resolveTheme('dark', false), 'dark');
});
test('ignores invalid or unavailable stored preferences', () => {
  assert.equal(readThemePreference({ getItem: () => 'broken' }), null);
  assert.equal(readThemePreference({ getItem() { throw new Error('Storage blocked'); } }), null);
  assert.equal(readThemePreference({ getItem: () => 'light' }), 'light');
});
