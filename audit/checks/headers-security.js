/*  ═══════════════════════════════════════════════════════════════════
    SECURITY HEADERS CHECK
    Analyzes HTTP security headers for best practices:
    HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');

function httpGet(rawUrl, timeoutMs = 6000) {
  return new Promise(resolve => {
    const t0 = Date.now();
    let done = false;
    const finish = (data) => { if (!done) { done = true; resolve({ ...data, ms: Date.now() - t0 }); } };

    try {
      const u = new URL(rawUrl);
      const lib = u.protocol === 'https:' ? https : http;
      const req = lib.get({
        hostname: u.hostname,
        path: u.pathname + u.search,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        headers: {
          'User-Agent': 'SupabaseGuard-SecurityAudit/3.0',
          'Accept': 'text/html,application/json,*/*'
        },
        rejectUnauthorized: false,
        timeout: timeoutMs
      }, (res) => {
        res.resume();
        finish({ status: res.statusCode, headers: res.headers, error: null });
      });
      req.on('error', e => finish({ status: 0, headers: {}, error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, error: 'timeout' }); });
    } catch (e) {
      finish({ status: 0, headers: {}, error: e.message });
    }
  });
}

const SECURITY_HEADERS = {
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    description: 'Força HTTPS connections',
    recommended: 'max-age=31536000; includeSubDomains',
    severity: 'high'
  },
  'content-security-policy': {
    name: 'Content-Security-Policy (CSP)',
    description: 'Previne XSS e injection attacks',
    recommended: "default-src 'self'",
    severity: 'high'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    description: 'Previne clickjacking',
    recommended: 'DENY or SAMEORIGIN',
    severity: 'medium'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    description: 'Previne MIME type sniffing',
    recommended: 'nosniff',
    severity: 'medium'
  },
  'x-xss-protection': {
    name: 'X-XSS-Protection',
    description: 'Filtro XSS legacy (deprecated)',
    recommended: '1; mode=block',
    severity: 'low'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    description: 'Controla informação do referenciador',
    recommended: 'strict-origin-when-cross-origin',
    severity: 'low'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    description: 'Controla features do browser',
    recommended: 'geolocation=(), microphone=(), camera=()',
    severity: 'low'
  },
  'cross-origin-opener-policy': {
    name: 'Cross-Origin-Opener-Policy (COOP)',
    description: 'Isola contexto de navegação',
    recommended: 'same-origin',
    severity: 'low'
  },
  'cross-origin-embedder-policy': {
    name: 'Cross-Origin-Embedder-Policy (COEP)',
    description: 'Controla cross-origin resources',
    recommended: 'require-corp',
    severity: 'low'
  },
  'cross-origin-resource-policy': {
    name: 'Cross-Origin-Resource-Policy (CORP)',
    description: 'Previne cross-origin loading',
    recommended: 'same-origin',
    severity: 'low'
  }
};

function analyzeHeaderValue(headerName, value) {
  const issues = [];
  const recommendations = [];

  if (!value) {
    return { present: false, issues, recommendations };
  }

  const lowerValue = value.toLowerCase();

  // HSTS specific checks
  if (headerName === 'strict-transport-security') {
    if (!lowerValue.includes('max-age')) {
      issues.push('Falta max-age');
    } else {
      const maxAgeMatch = lowerValue.match(/max-age=(\d+)/);
      if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) {
        issues.push('max-age muito baixo (recomendado: 31536000)');
      }
    }
    if (!lowerValue.includes('includesubdomains')) {
      recommendations.push('Adicionar includeSubDomains');
    }
    if (!lowerValue.includes('preload')) {
      recommendations.push('Considerar adicionar preload para lista de preload HSTS');
    }
  }

  // CSP specific checks
  if (headerName === 'content-security-policy') {
    if (lowerValue.includes("'unsafe-inline'") || lowerValue.includes("'unsafe-eval'")) {
      issues.push('CSP permite unsafe-inline ou unsafe-eval');
    }
    if (lowerValue === "default-src 'none'" && lowerValue.length < 50) {
      recommendations.push('CSP muito restritiva ou mal configurada');
    }
  }

  // X-Frame-Options specific checks
  if (headerName === 'x-frame-options') {
    if (lowerValue === 'allowall' || lowerValue === '*') {
      issues.push('X-Frame-Options permite qualquer domínio');
    }
  }

  return { present: true, value, issues, recommendations };
}

async function checkSecurityHeaders(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];

  if (emit) emit({ type: 'progress-detail', message: '🛡️ Analisando security headers...' });

  // Get headers from the base URL
  const response = await httpGet(baseUrl, 8000);
  const headers = response.headers || {};

  // Analyze each security header
  const headerAnalysis = {};
  let presentCount = 0;
  let missingCount = 0;

  for (const [headerKey, info] of Object.entries(SECURITY_HEADERS)) {
    const headerName = Object.keys(headers).find(k => k.toLowerCase() === headerKey);
    const rawValue = headerName ? headers[headerName] : null;
    const analysis = analyzeHeaderValue(headerKey, rawValue);
    
    headerAnalysis[headerKey] = {
      ...info,
      ...analysis,
      headerName
    };

    if (analysis.present) {
      presentCount++;
    } else {
      missingCount++;
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // RESULTS
  // ═══════════════════════════════════════════════════════════════════

  // Result 1: Overall security headers score
  {
    const score = Math.round((presentCount / Object.keys(SECURITY_HEADERS).length) * 100);
    let status, sev, msg;

    if (score >= 80) {
      status = 'PASS'; sev = 'info';
      msg = `Excelente! ${presentCount}/${Object.keys(SECURITY_HEADERS).length} security headers presentes`;
    } else if (score >= 50) {
      status = 'WARN'; sev = 'medium';
      msg = `Proteção parcial: ${presentCount}/${Object.keys(SECURITY_HEADERS).length} headers de segurança presentes`;
    } else {
      status = 'FAIL'; sev = 'high';
      msg = `Poucos security headers: apenas ${presentCount}/${Object.keys(SECURITY_HEADERS).length}`;
    }

    results.push({
      check: '🛡️ Security Headers — Geral',
      status, severity: sev, message: msg,
      details: {
        totalHeaders: Object.keys(SECURITY_HEADERS).length,
        presentCount,
        missingCount,
        score: `${score}%`,
        headers: Object.fromEntries(
          Object.entries(headers).filter(([k]) => 
            Object.keys(SECURITY_HEADERS).includes(k.toLowerCase())
          )
        )
      }
    });
  }

  // Result 2: Critical headers (HSTS, CSP)
  {
    const criticalHeaders = ['strict-transport-security', 'content-security-policy'];
    const criticalPresent = criticalHeaders.filter(h => headerAnalysis[h]?.present).length;
    
    let status, sev, msg;
    
    if (criticalPresent === 2) {
      status = 'PASS'; sev = 'info';
      msg = 'Headers críticos HSTS e CSP ambos presentes';
    } else if (criticalPresent === 1) {
      status = 'WARN'; sev = 'medium';
      msg = `Apenas ${criticalPresent} de 2 headers críticos presente`;
    } else {
      status = 'FAIL'; sev = 'high';
      msg = 'Nenhum dos headers críticos (HSTS, CSP) está presente';
    }

    results.push({
      check: '🔒 Security Headers — Críticos (HSTS, CSP)',
      status, severity: sev, message: msg,
      details: {
        hsts: headerAnalysis['strict-transport-security'],
        csp: headerAnalysis['content-security-policy']
      }
    });
  }

  // Result 3: X-Frame-Options
  {
    const xfo = headerAnalysis['x-frame-options'];
    let status, sev, msg;

    if (xfo.present) {
      status = 'PASS'; sev = 'low';
      msg = `X-Frame-Options presente: ${xfo.value}`;
    } else {
      status = 'WARN'; sev = 'medium';
      msg = 'X-Frame-Options ausente — vulnerável a clickjacking';
    }

    results.push({
      check: '🖼️ Security Headers — X-Frame-Options',
      status, severity: sev, message: msg,
      details: { ...xfo }
    });
  }

  // Result 4: X-Content-Type-Options
  {
    const xcto = headerAnalysis['x-content-type-options'];
    let status, sev, msg;

    if (xcto.present && xcto.value.toLowerCase() === 'nosniff') {
      status = 'PASS'; sev = 'low';
      msg = 'X-Content-Type-Options: nosniff configurado corretamente';
    } else if (xcto.present) {
      status = 'WARN'; sev = 'medium';
      msg = `X-Content-Type-Options presente mas com valor incorreto: ${xcto.value}`;
    } else {
      status = 'WARN'; sev = 'medium';
      msg = 'X-Content-Type-Options ausente — vulnerável a MIME sniffing';
    }

    results.push({
      check: '📝 Security Headers — X-Content-Type-Options',
      status, severity: sev, message: msg,
      details: { ...xcto }
    });
  }

  // Result 5: Referrer-Policy
  {
    const rp = headerAnalysis['referrer-policy'];
    let status, sev, msg;

    if (rp.present) {
      status = 'PASS'; sev = 'info';
      msg = `Referrer-Policy presente: ${rp.value}`;
    } else {
      status = 'WARN'; sev = 'low';
      msg = 'Referrer-Policy ausente — informações de referenciador podem vazar';
    }

    results.push({
      check: '🔗 Security Headers — Referrer-Policy',
      status, severity: sev, message: msg,
      details: { ...rp }
    });
  }

  // Result 6: Permissions-Policy
  {
    const pp = headerAnalysis['permissions-policy'];
    let status, sev, msg;

    if (pp.present) {
      status = 'PASS'; sev = 'info';
      msg = `Permissions-Policy presente: ${pp.value.substring(0, 60)}...`;
    } else {
      status = 'WARN'; sev = 'low';
      msg = 'Permissions-Policy ausente — considere restricting browser features';
    }

    results.push({
      check: '⚙️ Security Headers — Permissions-Policy',
      status, severity: sev, message: msg,
      details: { ...pp }
    });
  }

  // Result 7: All missing headers
  {
    const missing = Object.entries(headerAnalysis)
      .filter(([_, v]) => !v.present)
      .map(([k, v]) => ({ header: k, recommended: v.recommended }));

    if (missing.length > 0) {
      results.push({
        check: '📋 Security Headers — Headers Ausentes',
        status: 'WARN',
        severity: 'medium',
        message: `${missing.length} security header(s) ausente(s) — recomendações:`,
        details: {
          missingHeaders: missing,
          recommendation: 'Adicionar os headers recomendados via Edge Function ou CDN/WAF'
        }
      });
    }
  }

  return results;
}

module.exports = { checkSecurityHeaders };
