import { extractFields, renderJson, renderHtml, visitRow, prefersJson } from './_lib.js';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:";

/** Best-effort insert; never throws into the response path. Columns and bound
 *  values both come from visitRow() so they cannot drift out of alignment. */
async function logVisit(env, fields) {
  try {
    if (!env || !env.DB) return;
    const row = visitRow(fields);
    const columns = row.map(([c]) => c).join(', ');
    const placeholders = row.map(() => '?').join(', ');
    await env.DB
      .prepare(`INSERT INTO visits (${columns}) VALUES (${placeholders})`)
      .bind(...row.map(([, v]) => v))
      .run();
  } catch (err) {
    // Logging is best-effort; never surface DB errors to the client.
    console.log('visit-log-failed', err && err.message);
  }
}

async function handle(context) {
  const { request, env } = context;
  const fields = extractFields(request);
  await logVisit(env, fields);

  const asJson = prefersJson(request.url, request.headers.get('accept'));
  if (!asJson) {
    return new Response(renderHtml(fields), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': CSP,
      },
    });
  }
  return new Response(JSON.stringify(renderJson(fields), null, 2), {
    headers: { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export async function onRequestGet(context) {
  try {
    return await handle(context);
  } catch (err) {
    console.log('ip-endpoint-error', err && err.message);
    return new Response('Internal error', { status: 500, headers: SECURITY_HEADERS });
  }
}

// HEAD: same headers, no body — reuse GET then strip the body.
export async function onRequestHead(context) {
  const res = await onRequestGet(context);
  return new Response(null, { status: res.status, headers: res.headers });
}

// GET and HEAD are handled by onRequestGet/onRequestHead above (Cloudflare
// routes method-specific handlers with precedence over onRequest). This
// catch-all therefore only runs for other methods → 405.
export function onRequest() {
  return new Response('Method Not Allowed', {
    status: 405,
    headers: { ...SECURITY_HEADERS, Allow: 'GET, HEAD' },
  });
}
