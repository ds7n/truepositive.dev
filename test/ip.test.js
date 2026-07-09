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

test('redactHeaders drops sensitive headers with mixed-case keys', () => {
  const out = redactHeaders({ 'Cookie': 'x', 'AUTHORIZATION': 'y', 'User-Agent': 'curl/8.7.1' });
  assert.equal('Cookie' in out, false);
  assert.equal('AUTHORIZATION' in out, false);
  assert.deepEqual(out, { 'User-Agent': 'curl/8.7.1' });
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

import { extractFields } from '../functions/_lib.js';

function fakeRequest({ url = 'https://truepositive.dev/ip', method = 'GET', headers = {}, cf = {} } = {}) {
  return { url, method, headers: new Headers(headers), cf };
}

test('extractFields pulls IP from cf-connecting-ip and path from URL', () => {
  const f = extractFields(fakeRequest({
    headers: { 'cf-connecting-ip': '203.0.113.7', 'user-agent': 'curl/8.7.1' },
    cf: { country: 'US', city: 'Dallas', asn: 13335, colo: 'DFW',
          httpProtocol: 'HTTP/2', tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256' },
  }));
  assert.equal(f.ip, '203.0.113.7');
  assert.equal(f.path, '/ip');
  assert.equal(f.method, 'GET');
  assert.equal(f.country, 'US');
  assert.equal(f.asn, 13335);
  assert.equal(f.colo, 'DFW');
  assert.equal(f.http_ver, 'HTTP/2');
  assert.equal(f.tls_version, 'TLSv1.3');
  assert.equal(f.tls_cipher, 'AEAD-AES128-GCM-SHA256');
  assert.equal(f.user_agent, 'curl/8.7.1');
  assert.equal(typeof f.ts, 'string');
  assert.match(f.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test('extractFields defaults missing cf fields to null (no throw)', () => {
  const f = extractFields(fakeRequest({ headers: {}, cf: {} }));
  assert.equal(f.country, null);
  assert.equal(f.asn, null);
  assert.equal(f.tls_version, null);
  assert.equal(f.ip, null);
  assert.equal(f.user_agent, null);
  assert.equal(f.referer, null);
  assert.equal(f.accept_lang, null);
});

test('extractFields redacts sensitive headers in the headers map', () => {
  const f = extractFields(fakeRequest({
    headers: { 'user-agent': 'curl/8.7.1', cookie: 'session=abc', authorization: 'Bearer x' },
  }));
  assert.equal('cookie' in f.headers, false);
  assert.equal('authorization' in f.headers, false);
  assert.equal(f.headers['user-agent'], 'curl/8.7.1');
});

test('extractFields tolerates a request with no cf property', () => {
  const f = extractFields({ url: 'https://truepositive.dev/ip', method: 'GET', headers: new Headers() });
  assert.equal(f.country, null);
  assert.equal(f.path, '/ip');
});
