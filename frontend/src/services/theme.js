import { useSyncExternalStore } from 'react';
import { THEME_KEY, readThemePreference, resolveTheme } from './theme-preference';

const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
const listeners = new Set();
let preference = readThemePreference({ getItem: key => window.localStorage.getItem(key) });
let currentTheme = resolveTheme(preference, systemTheme.matches);

function applyTheme() {
  currentTheme = resolveTheme(preference, systemTheme.matches);
  document.documentElement.dataset.theme = currentTheme;
  document.documentElement.style.colorScheme = currentTheme;
  listeners.forEach(listener => listener());
}

systemTheme.addEventListener('change', () => { if (!preference) applyTheme(); });
window.addEventListener('storage', event => {
  if (event.key === THEME_KEY || event.key === null) {
    preference = readThemePreference({ getItem: key => window.localStorage.getItem(key) });
    applyTheme();
  }
});
applyTheme();

function subscribe(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}
function getSnapshot() { return currentTheme; }

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getSnapshot);
  function toggleTheme() {
    preference = currentTheme === 'dark' ? 'light' : 'dark';
    try { window.localStorage.setItem(THEME_KEY, preference); } catch { /* The current tab still works when storage is unavailable. */ }
    applyTheme();
  }
  return { theme, toggleTheme };
}
