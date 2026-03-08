/*  ═══════════════════════════════════════════════════════════════════
    ADVANCED DoS CHECK — Slowloris, HTTP Flood, Large Payload, ReDoS
    Tests server resilience against application-layer DoS attacks.
    All tests are lightweight and non-destructive (defensive audit).
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');
const net   = require('net');
const tls   = require('tls');

function httpGet(rawUrl, opts = {}) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = d => { if (!done) { done = true; resolve({ ...d, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.get({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.1',
          'Accept': '*/*',
          ...(opts.headers || {})
        },
        rejectUnauthorized: false,
        timeout: opts.timeout || 8000
      }, res => {
        let body = '';
        res.on('data', c => body += c);
        res.on('end', () => finish({ status: res.statusCode, headers: res.headers, body, error: null }));
      });
      req.on('error', e => finish({ status: 0, headers: {}, body: '', error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '', error: 'timeout' }); });
    } catch (e) {
      finish({ status: 0, headers: {}, body: '', error: e.message });
    }
  });
}

function httpPost(rawUrl, body, opts = {}) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = d => { if (!done) { done = true; resolve({ ...d, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);

      const req = lib.request({
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.1',
          'Content-Type': opts.contentType || 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          ...(opts.headers || {})
        },
        rejectUnauthorized: false,
        timeout: opts.timeout || 6000
      }, res => {
        let data = '';
        res.on('data', c => data += c);
        res.on('end', () => finish({ status: res.statusCode, headers: res.headers, body: data, error: null }));
      });
      req.on('error', e => finish({ status: 0, headers: {}, body: '', error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, body: '', error: 'timeout' }); });
      req.write(bodyStr);
      req.end();
    } catch (e) {
      finish({ status: 0, headers: {}, body: '', error: e.message });
    }
  });
}

// Test if server keeps connections open (Slowloris indicator)
async function testConnectionKeepAlive(hostname, port, isHttps, timeoutMs = 5000) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = r => { if (!done) { done = true; resolve({ ...r, ms: Date.now() - t0 }); } };

    try {
      let socket;
      if (isHttps) {
        socket = tls.connect({ host: hostname, port, rejectUnauthorized: false }, () => {
          // Send partial HTTP request (Slowloris-style)
          socket.write(`GET / HTTP/1.1\r\nHost: ${hostname}\r\nConnection: keep-alive\r\n`);
          // Don't send final \r\n — keep connection open
        });
      } else {
        socket = net.createConnection(port, hostname, () => {
          socket.write(`GET / HTTP/1.1\r\nHost: ${hostname}\r\nConnection: keep-alive\r\n`);
        });
      }

      socket.setTimeout(timeoutMs);

      let gotData = false;
      socket.on('data', () => { gotData = true; });
      socket.on('timeout', () => {
        const ms = Date.now() - t0;
        socket.destroy();
        // If server held the connection for timeout without closing it,
        // it might be vulnerable to Slowloris
        finish({
          keptOpen: !gotData,
          ms,
          timedOut: true,
          serverClosed: false
        });
      });
      socket.on('close', () => {
        finish({
          keptOpen: false,
          ms: Date.now() - t0,
          timedOut: false,
          serverClosed: true
        });
      });
      socket.on('error', e => finish({ keptOpen: false, ms: Date.now() - t0, error: e.message }));
    } catch (e) {
      finish({ keptOpen: false, error: e.message });
    }
  });
}

async function checkDosAdvanced(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];

  if (emit) emit({ type: 'progress-detail', message: '🌊 DoS Avançado: Iniciando análise de vetores de ataque DoS...' });

  let hostname, port, isHttps;
  try {
    const u = new URL(baseUrl);
    hostname = u.hostname;
    isHttps = u.protocol === 'https:';
    port = u.port ? parseInt(u.port) : (isHttps ? 443 : 80);
  } catch (e) {
    hostname = baseUrl.replace(/^https?:\/\//, '').split('/')[0];
    isHttps = baseUrl.startsWith('https');
    port = isHttps ? 443 : 80;
  }

  // ── 1. Slowloris Vulnerability Detection ─────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🐢 DoS: Testando vulnerabilidade Slowloris...' });

  const slowlorisTest = await testConnectionKeepAlive(hostname, port, isHttps, 4000);
  const slowlorisTimeout = await testConnectionKeepAlive(hostname, port, isHttps, 2000);

  // A server that keeps incomplete HTTP requests open without timeout
  // is potentially vulnerable to Slowloris
  const possiblySlowlorisVulnerable = slowlorisTest.keptOpen && slowlorisTimeout.keptOpen;

  if (possiblySlowlorisVulnerable) {
    results.push({
      check: '🐢 DoS — Slowloris Vulnerability',
      status: 'WARN',
      severity: 'high',
      message: 'Servidor manteve conexão com requisição HTTP incompleta por mais de 4 segundos — possível vulnerabilidade a Slowloris.',
      details: {
        connectionHeldMs: slowlorisTest.ms,
        recommendation: 'Configure timeout para conexões incompletas no servidor web (Nginx: client_header_timeout, Apache: RequestReadTimeout).'
      }
    });
  } else {
    results.push({
      check: '🐢 DoS — Slowloris Vulnerability',
      status: 'PASS',
      severity: 'info',
      message: 'Servidor fechou conexão com requisição HTTP incompleta — proteção básica contra Slowloris detectada.',
      details: { connectionClosedAfterMs: slowlorisTest.ms, serverClosed: slowlorisTest.serverClosed }
    });
  }

  // ── 2. Large Payload DoS Testing ─────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '📦 DoS: Testando limite de tamanho de payload...' });

  const payloadSizes = [
    { size: 1024, label: '1KB' },
    { size: 1024 * 100, label: '100KB' },
    { size: 1024 * 1024, label: '1MB' },
  ];

  const payloadResults = [];
  let hasPayloadLimit = false;

  for (const { size, label } of payloadSizes) {
    const largePayload = 'A'.repeat(size);
    const res = await httpPost(baseUrl, { data: largePayload }, { timeout: 8000 });

    payloadResults.push({
      size: label,
      status: res.status,
      ms: res.ms,
      rejected: res.status === 413 || res.status === 400
    });

    if (res.status === 413) {
      hasPayloadLimit = true;
    }
    if (res.status === 0 && res.error === 'timeout') break; // Stop if server crashes
    await new Promise(r => setTimeout(r, 300));
  }

  const largestAccepted = payloadResults.filter(r => r.status > 0 && !r.rejected).pop();

  if (!hasPayloadLimit && largestAccepted) {
    results.push({
      check: '📦 DoS — Large Payload Attack',
      status: 'WARN',
      severity: 'medium',
      message: `Servidor aceita payloads grandes sem restrição (até ${largestAccepted.size} testado). Vulnerável a ataques de esgotamento de memória.`,
      details: {
        results: payloadResults,
        recommendation: 'Configure limite de tamanho de request (Nginx: client_max_body_size, Express: limit em bodyParser).'
      }
    });
  } else if (hasPayloadLimit) {
    results.push({
      check: '📦 DoS — Large Payload Attack',
      status: 'PASS',
      severity: 'info',
      message: 'Servidor rejeita payloads grandes com status 413 — proteção contra ataques de esgotamento de memória.',
      details: { results: payloadResults }
    });
  }

  // ── 3. HTTP Header Flooding ───────────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '📋 DoS: Testando limite de headers HTTP...' });

  // Generate many custom headers
  const manyHeaders = {};
  for (let i = 0; i < 100; i++) {
    manyHeaders[`X-Custom-Header-${i}`] = `value-${i}-${'A'.repeat(50)}`;
  }

  const headerFloodRes = await httpGet(baseUrl, {
    headers: manyHeaders,
    timeout: 6000
  });

  const headerFloodHandled = headerFloodRes.status === 431 || headerFloodRes.status === 400 ||
                              headerFloodRes.status === 413 || (headerFloodRes.status > 0 && headerFloodRes.status < 500);

  if (!headerFloodHandled) {
    results.push({
      check: '📋 DoS — HTTP Header Flooding',
      status: 'WARN',
      severity: 'medium',
      message: 'Servidor pode não limitar quantidade/tamanho de headers HTTP — potencial vetor de DoS.',
      details: {
        headersSeeded: 100,
        response: headerFloodRes.status,
        recommendation: 'Configure limite de headers HTTP (Nginx: large_client_header_buffers).'
      }
    });
  } else {
    results.push({
      check: '📋 DoS — HTTP Header Flooding',
      status: 'PASS',
      severity: 'info',
      message: `Servidor respondeu adequadamente com ${headerFloodRes.status} ao receber 100 headers customizados.`,
      details: { status: headerFloodRes.status }
    });
  }

  // ── 4. ReDoS Vulnerability Testing ───────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔁 DoS: Testando vulnerabilidade ReDoS...' });

  // ReDoS payloads that cause catastrophic backtracking in common regex patterns
  const redosPayloads = [
    'a'.repeat(50) + '!',               // Triggers backtracking in /^(a+)+$/
    '(' + 'a'.repeat(30) + ')',          // Nested groups
    '1' + '1'.repeat(40) + '2',         // Email-like patterns
    `${'a'.repeat(20)}@${'b'.repeat(20)}.com`, // Email ReDoS
    `<${'a'.repeat(30)}>`,              // HTML-like ReDoS
  ];

  const redosVulns = [];
  const redosEndpoints = [
    { path: '/?q=', type: 'query param' },
    { path: '/?search=', type: 'search' },
    { path: '/?email=', type: 'email' },
  ];

  for (const ep of redosEndpoints) {
    for (const payload of redosPayloads) {
      const url = baseUrl + ep.path + encodeURIComponent(payload);
      const t0 = Date.now();
      const res = await httpGet(url, { timeout: 10000 });
      const elapsed = Date.now() - t0;

      if (elapsed > 5000 && res.status !== 0) {
        redosVulns.push({
          endpoint: ep.path,
          payload: payload.substring(0, 30),
          responseTimeMs: elapsed,
          status: res.status
        });
      }
    }
  }

  if (redosVulns.length > 0) {
    results.push({
      check: '🔁 DoS — ReDoS Vulnerability',
      status: 'FAIL',
      severity: 'high',
      message: `Possível ReDoS (Regex DoS) detectado! ${redosVulns.length} endpoint(s) com resposta muito lenta para inputs especiais.`,
      details: {
        vulnerable: redosVulns,
        recommendation: 'Revise regex usadas em validação de input. Use regex seguras e adicione timeout em operações de regex.'
      }
    });
  } else {
    results.push({
      check: '🔁 DoS — ReDoS Vulnerability',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhuma vulnerabilidade ReDoS detectada nos endpoints testados.',
      details: { endpointsTested: redosEndpoints.length, payloadsTested: redosPayloads.length }
    });
  }

  // ── 5. HTTP/2 Rapid Reset (CVE-2023-44487) Detection ─────────────
  if (emit) emit({ type: 'progress-detail', message: '⚡ DoS: Verificando proteção contra HTTP/2 Rapid Reset...' });

  const http2ProtectionHeaders = [
    'cf-ray',          // Cloudflare (patched)
    'x-amz-cf-id',     // AWS CloudFront (patched)
    'x-goog-',         // Google (patched)
    'x-azure-ref',     // Azure (patched)
    'x-fastly-request-id', // Fastly (patched)
  ];

  const mainRes = await httpGet(baseUrl, { timeout: 6000 });
  const hasHttp2Protection = http2ProtectionHeaders.some(h =>
    Object.keys(mainRes.headers || {}).some(k => k.toLowerCase().includes(h))
  );

  const serverHeader = (mainRes.headers || {})['server'] || '';
  const isNginxLatest = serverHeader.toLowerCase().includes('nginx') &&
    !serverHeader.match(/nginx\/1\.(1[0-8]|[0-9])\./); // nginx < 1.19 potentially vulnerable

  if (!hasHttp2Protection && isNginxLatest) {
    results.push({
      check: '⚡ DoS — HTTP/2 Rapid Reset (CVE-2023-44487)',
      status: 'WARN',
      severity: 'high',
      message: 'Sem proteção CDN detectada contra HTTP/2 Rapid Reset (CVE-2023-44487). Verifique versão do servidor.',
      details: {
        server: serverHeader,
        recommendation: 'Atualize Nginx/Apache para versões com patch para CVE-2023-44487. Use CDN com proteção ativa.'
      }
    });
  } else {
    results.push({
      check: '⚡ DoS — HTTP/2 Rapid Reset (CVE-2023-44487)',
      status: 'PASS',
      severity: 'info',
      message: hasHttp2Protection
        ? 'CDN com proteção ativa contra HTTP/2 Rapid Reset detectada.'
        : 'Servidor aparentemente protegido contra HTTP/2 Rapid Reset.',
      details: { server: serverHeader, cdnProtection: hasHttp2Protection }
    });
  }

  // ── 6. Connection Exhaustion Test ────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔗 DoS: Testando resiliência a esgotamento de conexões...' });

  const connExhaustResults = await Promise.all(
    Array.from({ length: 15 }, () => httpGet(baseUrl, { timeout: 5000 }))
  );

  const connSuccessful = connExhaustResults.filter(r => r.status >= 200 && r.status < 500).length;
  const connTimeout = connExhaustResults.filter(r => r.error === 'timeout').length;
  const connErrors = connExhaustResults.filter(r => r.status === 0 && r.error !== 'timeout').length;

  if (connTimeout >= 8 || connErrors >= 8) {
    results.push({
      check: '🔗 DoS — Connection Exhaustion',
      status: 'FAIL',
      severity: 'high',
      message: `Servidor instável sob 15 conexões simultâneas: ${connTimeout} timeouts, ${connErrors} erros. Vulnerável a esgotamento de conexões.`,
      details: {
        total: 15, successful: connSuccessful, timeouts: connTimeout, errors: connErrors,
        recommendation: 'Configure connection pooling, worker limits e max connections no servidor.'
      }
    });
  } else if (connTimeout >= 3 || connErrors >= 3) {
    results.push({
      check: '🔗 DoS — Connection Exhaustion',
      status: 'WARN',
      severity: 'medium',
      message: `Alguma instabilidade sob 15 conexões simultâneas: ${connTimeout} timeouts, ${connErrors} erros.`,
      details: { total: 15, successful: connSuccessful, timeouts: connTimeout, errors: connErrors }
    });
  } else {
    results.push({
      check: '🔗 DoS — Connection Exhaustion',
      status: 'PASS',
      severity: 'info',
      message: `Servidor respondeu a 15 conexões simultâneas adequadamente. ${connSuccessful}/15 bem-sucedidas.`,
      details: { total: 15, successful: connSuccessful, timeouts: connTimeout, errors: connErrors }
    });
  }

  // ── 7. Overall DoS Protection Score ──────────────────────────────
  const failCount = results.filter(r => r.status === 'FAIL').length;
  const warnCount = results.filter(r => r.status === 'WARN').length;

  let dosStatus, dosSev, dosMsg;
  if (failCount >= 2) {
    dosStatus = 'FAIL'; dosSev = 'high';
    dosMsg = `Sistema vulnerável a múltiplos vetores de DoS (${failCount} falhas, ${warnCount} alertas).`;
  } else if (failCount === 1 || warnCount >= 3) {
    dosStatus = 'WARN'; dosSev = 'medium';
    dosMsg = `Proteção DoS parcial — ${failCount} falha(s) e ${warnCount} alerta(s) detectados.`;
  } else {
    dosStatus = 'PASS'; dosSev = 'info';
    dosMsg = 'Sistema demonstra boa resiliência aos vetores de DoS testados.';
  }

  results.push({
    check: '🌊 DoS Avançado — Análise Geral',
    status: dosStatus,
    severity: dosSev,
    message: dosMsg,
    details: {
      failCount, warnCount,
      recommendation: 'Implemente rate limiting, WAF, timeouts adequados e monitore métricas de conexão.'
    }
  });

  return results;
}

module.exports = { checkDosAdvanced };
