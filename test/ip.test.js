import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeHtml,
  SENSITIVE_HEADERS,
  headersToObject,
  redactHeaders,
} from '../functions/_lib.js';

test('escapeHtml leaves a plain string unchanged', () => {
  assert.equal(escapeHtml('curl/8.7.1'), 'curl/8.7.1');
});

test('escapeHtml escapes all five HTML-significant characters', () => {
  assert.equal(
    escapeHtml(`<script>"a"&'b'</script>`),
    '&lt;script&gt;&quot;a&quot;&amp;&#39;b&#39;&lt;/script&gt;',
  );
});

test('escapeHtml escapes & exactly once (no double-encoding)', () => {
  assert.equal(escapeHtml('a & b'), 'a &amp; b');
});

test('escapeHtml maps null/undefined to empty string', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('headersToObject lowercases keys and preserves values', () => {
  const h = new Headers({ 'User-Agent': 'curl/8.7.1', 'Accept': '*/*' });
  assert.deepEqual(headersToObject(h), {
    'user-agent': 'curl/8.7.1',
    accept: '*/*',
  });
});

test('redactHeaders drops sensitive headers case-insensitively', () => {
  const input = {
    'user-agent': 'curl/8.7.1',
    cookie: 'session=abc',
    authorization: 'Bearer xyz',
  };
  const out = redactHeaders(input);
  assert.deepEqual(out, { 'user-agent': 'curl/8.7.1' });
  assert.equal('cookie' in out, false);
  assert.equal('authorization' in out, false);
});

test('redactHeaders keeps x-forwarded-for', () => {
  const out = redactHeaders({ 'x-forwarded-for': '203.0.113.7' });
  assert.deepEqual(out, { 'x-forwarded-for': '203.0.113.7' });
});

test('SENSITIVE_HEADERS contains the documented omit set', () => {
  for (const name of [
    'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
    'cf-access-jwt-assertion', 'cf-access-authenticated-user-email',
  ]) {
    assert.equal(SENSITIVE_HEADERS.has(name), true, name);
  }
});
