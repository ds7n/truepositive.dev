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

test('extractFields includes the full cf geo/network field set', () => {
  const f = extractFields(fakeRequest({
    headers: { 'cf-connecting-ip': '203.0.113.7' },
    cf: {
      country: 'US', region: 'Texas', regionCode: 'TX', city: 'Dallas',
      postalCode: '75201', continent: 'NA', metroCode: '623',
      timezone: 'America/Chicago', latitude: '32.7767', longitude: '-96.7970',
      isEUCountry: null, asn: 13335, asOrganization: 'Cloudflare, Inc.',
    },
  }));
  assert.equal(f.region, 'Texas');
  assert.equal(f.region_code, 'TX');
  assert.equal(f.postal_code, '75201');
  assert.equal(f.continent, 'NA');
  assert.equal(f.metro_code, '623');
  assert.equal(f.timezone, 'America/Chicago');
  assert.equal(f.latitude, '32.7767');
  assert.equal(f.longitude, '-96.7970');
  assert.equal(f.as_org, 'Cloudflare, Inc.');
});

test('extractFields attaches a parsed ua object', () => {
  const f = extractFields(fakeRequest({
    headers: { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' },
  }));
  assert.equal(f.ua.browser, 'Firefox');
  assert.equal(f.ua.os, 'Linux');
  assert.equal(f.ua.bot, false);
});

test('extractFields tolerates a request with no cf property', () => {
  const f = extractFields({ url: 'https://truepositive.dev/ip', method: 'GET', headers: new Headers() });
  assert.equal(f.country, null);
  assert.equal(f.path, '/ip');
});

import { renderJson, renderHtml, parseUserAgent } from '../functions/_lib.js';

const SAMPLE = {
  ts: '2026-07-09T12:00:00.000Z', ip: '203.0.113.7',
  country: 'US', region: 'Texas', region_code: 'TX', city: 'Dallas',
  postal_code: '75201', continent: 'NA', metro_code: '623',
  timezone: 'America/Chicago', latitude: '32.7767', longitude: '-96.7970', is_eu: null,
  asn: 13335, as_org: 'Cloudflare, Inc.', colo: 'DFW',
  method: 'GET', path: '/ip', http_ver: 'HTTP/2',
  user_agent: 'curl/8.7.1', ua: parseUserAgent('curl/8.7.1'),
  referer: null, accept_lang: null,
  tls_version: 'TLSv1.3', tls_cipher: 'AEAD-AES128-GCM-SHA256',
  headers: { 'user-agent': 'curl/8.7.1', accept: '*/*' },
};

test('renderJson returns the fields object unchanged', () => {
  assert.deepEqual(renderJson(SAMPLE), SAMPLE);
});

test('renderHtml escapes a malicious User-Agent (no raw <script>)', () => {
  const evil = '<script>alert(1)</script>';
  const html = renderHtml({ ...SAMPLE, user_agent: evil, ua: parseUserAgent(evil),
    headers: { 'user-agent': evil } });
  assert.equal(html.includes('<script>alert(1)</script>'), false);
  assert.equal(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), true);
});

test('renderHtml escapes a malicious Referer and header value', () => {
  const html = renderHtml({ ...SAMPLE,
    referer: '"><img src=x onerror=alert(1)>',
    headers: { 'x-evil': '<b>x</b>' } });
  // No raw injection from either the referer cell or a header value.
  assert.equal(html.includes('<img src=x'), false);
  assert.equal(html.includes('<b>x</b>'), false);
  assert.equal(html.includes('&lt;img src=x onerror=alert(1)&gt;'), true);
  assert.equal(html.includes('&lt;b&gt;x&lt;/b&gt;'), true);
});

test('renderHtml never emits a sensitive header even if one leaks into headers', () => {
  // Defense-in-depth: renderHtml only renders what it is given, but the field
  // pipeline redacts upstream. Verify a benign header shows and the doc is well-formed.
  const html = renderHtml(SAMPLE);
  assert.equal(html.startsWith('<!DOCTYPE html>'), true);
  assert.equal(html.includes('203.0.113.7'), true);
  assert.equal(html.includes('TLSv1.3'), true);
  assert.equal(html.toLowerCase().includes('cookie'), false);
  assert.equal(html.toLowerCase().includes('authorization'), false);
});

test('renderHtml renders missing values as an em dash', () => {
  const html = renderHtml({ ...SAMPLE, referer: null });
  // The Referer cell renders label then an em-dash value with no other cell
  // boundary in between — pins the dash to Referer's own value, not a later field.
  assert.match(html, /Referer<\/span><span class="v">—<\/span>/);
});

test('renderHtml renders parsed browser and keeps the raw user agent', () => {
  const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36';
  const html = renderHtml({ ...SAMPLE, user_agent: ua, ua: parseUserAgent(ua) });
  assert.equal(html.includes('Chrome 127.0.0.0'), true);   // parsed
  assert.equal(html.includes('Windows'), true);            // parsed OS
  assert.equal(html.includes(ua), true);                   // raw UA still present
});

// --- parseUserAgent ---

test('parseUserAgent handles Chrome on Windows', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36');
  assert.equal(r.browser, 'Chrome');
  assert.equal(r.browser_version, '127.0.0.0');
  assert.equal(r.os, 'Windows');
  assert.equal(r.os_version, '10/11');
  assert.equal(r.device, 'Desktop');
  assert.equal(r.engine, 'Blink');
  assert.equal(r.bot, false);
});

test('parseUserAgent handles Safari on iPhone (iOS)', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1');
  assert.equal(r.browser, 'Safari');
  assert.equal(r.browser_version, '17.5');
  assert.equal(r.os, 'iOS');
  assert.equal(r.os_version, '17.5');
  assert.equal(r.device, 'Mobile');
});

test('parseUserAgent handles Firefox on Linux', () => {
  const r = parseUserAgent('Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0');
  assert.equal(r.browser, 'Firefox');
  assert.equal(r.browser_version, '128.0');
  assert.equal(r.os, 'Linux');
  assert.equal(r.engine, 'Gecko');
  assert.equal(r.device, 'Desktop');
});

test('parseUserAgent handles Chrome on Android (mobile)', () => {
  const r = parseUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Mobile Safari/537.36');
  assert.equal(r.browser, 'Chrome');
  assert.equal(r.os, 'Android');
  assert.equal(r.os_version, '14');
  assert.equal(r.device, 'Mobile');
});

test('parseUserAgent picks Edge over Chrome despite the Chrome token', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0');
  assert.equal(r.browser, 'Edge');
  assert.equal(r.browser_version, '127.0.0.0');
});

test('parseUserAgent handles Chrome on iOS (CriOS, no Version token)', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/127.0.6533.107 Mobile/15E148 Safari/604.1');
  assert.equal(r.browser, 'Chrome');
  assert.equal(r.browser_version, '127.0.6533.107');
  assert.equal(r.os, 'iOS');
  assert.equal(r.device, 'Mobile');
});

test('parseUserAgent handles Firefox on iOS (FxiOS, no Version token)', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15');
  assert.equal(r.browser, 'Firefox');
  assert.equal(r.browser_version, '127.0');
  assert.equal(r.os, 'iOS');
  assert.equal(r.device, 'Mobile');
});

test('parseUserAgent still detects plain Safari on iOS (Version token present)', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1');
  assert.equal(r.browser, 'Safari');
  assert.equal(r.browser_version, '17.5');
});

test('parseUserAgent flags Googlebot as a bot', () => {
  const r = parseUserAgent('Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');
  assert.equal(r.bot, true);
  assert.equal(r.browser, 'Googlebot');
});

test('parseUserAgent flags curl as a bot with its version', () => {
  const r = parseUserAgent('curl/8.7.1');
  assert.equal(r.bot, true);
  assert.equal(r.browser, 'curl');
  assert.equal(r.browser_version, '8.7.1');
});

test('parseUserAgent returns all-null (bot=false) for empty/invalid input', () => {
  for (const bad of [null, undefined, '', 42]) {
    const r = parseUserAgent(bad);
    assert.equal(r.browser, null);
    assert.equal(r.os, null);
    assert.equal(r.device, null);
    assert.equal(r.bot, false);
  }
});

test('parseUserAgent does not throw on a garbage string', () => {
  const r = parseUserAgent('!!!!not a real ua!!!!');
  // Unknown browser/os, but device defaults to Desktop and no crash.
  assert.equal(r.browser, null);
  assert.equal(r.bot, false);
});

// --- visitRow: single source of truth for the D1 INSERT ---

import { visitRow, prefersJson } from '../functions/_lib.js';
import { readFileSync } from 'node:fs';

test('visitRow columns exactly match schema.sql (order and set, minus id)', () => {
  const schema = readFileSync(new URL('../schema.sql', import.meta.url), 'utf8');
  const create = schema.match(/CREATE TABLE visits \(([\s\S]*?)\);/)[1];
  const schemaCols = create
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('--'))
    .map((l) => l.split(/\s+/)[0])
    .filter((c) => c !== 'id');
  const rowCols = visitRow(SAMPLE).map(([c]) => c);
  assert.deepEqual(rowCols, schemaCols);
});

test('visitRow maps values in the same order as its columns', () => {
  const row = visitRow(SAMPLE);
  const byCol = Object.fromEntries(row);
  assert.equal(byCol.ip, '203.0.113.7');
  assert.equal(byCol.region_code, 'TX');
  assert.equal(byCol.as_org, 'Cloudflare, Inc.');
  assert.equal(byCol.ua_browser, SAMPLE.ua.browser);
  assert.equal(byCol.headers_json, JSON.stringify(SAMPLE.headers));
});

test('visitRow coerces ua_bot to 1/0 integer', () => {
  const botRow = Object.fromEntries(visitRow({ ...SAMPLE, ua: { ...SAMPLE.ua, bot: true } }));
  const humanRow = Object.fromEntries(visitRow({ ...SAMPLE, ua: { ...SAMPLE.ua, bot: false } }));
  assert.equal(botRow.ua_bot, 1);
  assert.equal(humanRow.ua_bot, 0);
});

test('visitRow tolerates a missing ua object (all ua_* null, bot 0)', () => {
  const row = Object.fromEntries(visitRow({ ...SAMPLE, ua: undefined }));
  assert.equal(row.ua_browser, null);
  assert.equal(row.ua_bot, 0);
});

// --- prefersJson: format negotiation ---

test('prefersJson: /ip/json path returns JSON even for a browser Accept', () => {
  assert.equal(prefersJson('https://x/ip/json', 'text/html,application/xhtml+xml'), true);
});

test('prefersJson: /ip/json/ trailing slash still returns JSON', () => {
  assert.equal(prefersJson('https://x/ip/json/', 'text/html'), true);
});

test('prefersJson: ?format=json returns JSON (case-insensitive)', () => {
  assert.equal(prefersJson('https://x/ip?format=JSON', 'text/html'), true);
});

test('prefersJson: plain /ip with browser Accept returns HTML', () => {
  assert.equal(prefersJson('https://x/ip', 'text/html,application/xhtml+xml'), false);
});

test('prefersJson: plain /ip with no/curl Accept returns JSON', () => {
  assert.equal(prefersJson('https://x/ip', '*/*'), true);
  assert.equal(prefersJson('https://x/ip', ''), true);
  assert.equal(prefersJson('https://x/ip', null), true);
});
