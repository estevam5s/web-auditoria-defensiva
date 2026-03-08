/*  ═══════════════════════════════════════════════════════════════════
    OPEN REDIRECT CHECK — Tests common redirect parameters for
    unvalidated redirect vulnerabilities (CWE-601)
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');
const { URL } = require('url');

const EVIL_DOMAIN = 'evil-redirect-test.example.com';
const EVIL_URL    = `https://${EVIL_DOMAIN}`;

const REDIRECT_PARAMS = [
  'next', 'redirect', 'url', 'return', 'goto', 'target',
  'destination', 'redir', 'redirect_to', 'redirect_url',
  'return_to', 'returnTo', 'continue', 'to', 'link',
  'forward', 'location', 'back', 'callback',
];

function httpGetFollowRedirects(startUrl, maxRedirects = 5, timeout = 8000) {
  return new Promise(resolve => {
    let redirectCount = 0;
    let finalUrl = startUrl;
    const history = [startUrl];

    function request(url) {
      let parsed;
      try { parsed = new URL(url); } catch { return resolve({ finalUrl, history, status: 0, redirected: false }); }

      const lib = parsed.protocol === 'https:' ? https : http;
      const req = lib.get(url, { rejectUnauthorized: false }, res => {
        const { statusCode, headers } = res;
        res.destroy();

        if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location) {
          redirectCount++;
          if (redirectCount > maxRedirects) {
            return resolve({ finalUrl, history, status: statusCode, redirected: true });
          }
          let nextUrl = headers.location;
          if (!nextUrl.startsWith('http')) {
            try {
              nextUrl = new URL(nextUrl, url).href;
            } catch {
              return resolve({ finalUrl, history, status: statusCode, redirected: true });
            }
          }
          finalUrl = nextUrl;
          history.push(nextUrl);
          request(nextUrl);
        } else {
          resolve({ finalUrl, history, status: statusCode, redirected: redirectCount > 0 });
        }
      });
      req.setTimeout(timeout, () => { req.destroy(); resolve({ finalUrl, history, status: 0, redirected: false }); });
      req.on('error', () => resolve({ finalUrl, history, status: 0, redirected: false }));
    }

    request(startUrl);
  });
}

function isExternalRedirect(originalHost, finalUrl) {
  try {
    const finalParsed = new URL(finalUrl);
    return finalParsed.hostname !== originalHost &&
           finalParsed.hostname.includes(EVIL_DOMAIN.split('.')[0]);
  } catch {
    return false;
  }
}

async function checkOpenRedirect(config, emit) {
  const results = [];

  let baseUrl, host;
  try {
    const parsed = new URL(config.projectUrl);
    host = parsed.hostname;
    baseUrl = `${parsed.protocol}//${parsed.host}`;
  } catch {
    results.push({
      check: '🔗 Open Redirect — Configuração',
      status: 'ERROR',
      severity: 'info',
      message: `URL inválida: ${config.projectUrl}`,
      details: null,
    });
    return results;
  }

  emit && emit({ type: 'progress', message: `[Open Redirect] Testando ${REDIRECT_PARAMS.length} parâmetros de redirecionamento em ${host}...` });

  const vulnerable = [];

  // Test both encoded and plain payloads per parameter
  const payloads = [
    EVIL_URL,
    `//${EVIL_DOMAIN}`,
    `\\\\${EVIL_DOMAIN}`,
  ];

  for (const param of REDIRECT_PARAMS) {
    for (const payload of payloads.slice(0, 2)) { // Test 2 payloads per param
      const testUrl = `${baseUrl}/?${param}=${encodeURIComponent(payload)}`;
      const res = await httpGetFollowRedirects(testUrl);

      if (res.redirected && isExternalRedirect(host, res.finalUrl)) {
        vulnerable.push({
          param,
          payload,
          testUrl,
          finalUrl: res.finalUrl,
          redirectChain: res.history,
        });
        break; // Found vulnerable, no need to test more payloads for this param
      }
    }
  }

  if (vulnerable.length === 0) {
    results.push({
      check: '🔗 Open Redirect — Redirecionamento Não Validado',
      status: 'PASS',
      severity: 'info',
      message: `Nenhum redirecionamento aberto detectado. ${REDIRECT_PARAMS.length} parâmetros testados em ${host}.`,
      details: { paramsTested: REDIRECT_PARAMS.length, host },
    });
  } else {
    results.push({
      check: '🔗 Open Redirect — Redirecionamento Aberto Detectado',
      status: 'FAIL',
      severity: 'high',
      message: `${vulnerable.length} parâmetro(s) vulnerável(is) a Open Redirect em ${host}! Pode ser usado para phishing e bypass de autenticação OAuth.`,
      details: {
        vulnerable,
        cvss: 6.1,
        cwe: 'CWE-601',
        recommendation: 'Valide a URL de destino contra uma allowlist de domínios permitidos. Nunca redirecione diretamente para parâmetros de URL.',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'],
      },
    });
  }

  return results;
}

module.exports = { checkOpenRedirect };
