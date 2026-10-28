import { loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor';
import EditorWorker from 'monaco-editor/editor/editor.worker.js?worker';
import JsonWorker from 'monaco-editor/language/json/json.worker.js?worker';
import CssWorker from 'monaco-editor/language/css/css.worker.js?worker';
import HtmlWorker from 'monaco-editor/language/html/html.worker.js?worker';
import TsWorker from 'monaco-editor/language/typescript/ts.worker.js?worker';

globalThis.MonacoEnvironment = {
  getWorker(_moduleId, label) {
    if (label === 'json') return new JsonWorker();
    if (['css', 'scss', 'less'].includes(label)) return new CssWorker();
    if (['html', 'handlebars', 'razor'].includes(label)) return new HtmlWorker();
    if (['typescript', 'javascript'].includes(label)) return new TsWorker();
    return new EditorWorker();
  },
};
loader.config({ monaco });
monaco.editor.defineTheme('frosted-carbon', {
  base: 'vs-dark', inherit: true,
  rules: [
    { token: 'comment', foreground: 'A0A0A0' },
    { token: 'keyword', foreground: 'DEDEDE' },
    { token: 'string', foreground: 'CECECE' },
    { token: 'number', foreground: 'BDBDBD' },
  ],
  colors: {
    'editor.background': '#00000000', 'editorGutter.background': '#00000000',
    'minimap.background': '#00000000', 'editorOverviewRuler.background': '#00000000',
    'editor.foreground': '#F2F2F2',
    'editorLineNumber.foreground': '#919191', 'editorLineNumber.activeForeground': '#DEDEDE',
    'editor.selectionBackground': '#FFFFFF22', 'editor.lineHighlightBackground': '#DEDEDE0B',
    'editorCursor.foreground': '#DEDEDE', 'editorWidget.background': '#1B1B1B',
  },
});
monaco.editor.defineTheme('frosted-light', {
  base: 'vs', inherit: true,
  rules: [
    { token: 'comment', foreground: '5E7081' },
    { token: 'keyword', foreground: '174E9C' },
    { token: 'string', foreground: '17624B' },
    { token: 'number', foreground: '795098' },
  ],
  colors: {
    'editor.background': '#00000000', 'editorGutter.background': '#00000000',
    'minimap.background': '#00000000', 'editorOverviewRuler.background': '#00000000',
    'editor.foreground': '#182C42', 'editorLineNumber.foreground': '#63758B',
    'editorLineNumber.activeForeground': '#174E9C', 'editor.selectionBackground': '#367ADF30',
    'editor.lineHighlightBackground': '#367ADF0A', 'editorCursor.foreground': '#174E9C',
    'editorWidget.background': '#F2F7FD',
  },
});
