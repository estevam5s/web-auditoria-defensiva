/*  CHECK: CORS Headers
    Tests CORS configuration for overly permissive settings */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

async function checkCORSConfig(config) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  // 1. Check CORS preflight response
  const endpoints = [
    '/rest/v1/',
    '/auth/v1/settings',
    '/storage/v1/bucket',
    '/graphql/v1'
  ];

  for (const endpoint of endpoints) {
    const url = baseUrl + endpoint;
    
    // OPTIONS preflight with suspicious origin
    const preflight = await safeFetch(url, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'https://evil-attacker.com',
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'authorization,apikey'
      }
    });

    const acao = preflight.headers['access-control-allow-origin'];
    const acac = preflight.headers['access-control-allow-credentials'];

    if (acao === '*') {
      results.push({
        check: `CORS — ${endpoint}`,
        status: 'WARN',
        severity: 'medium',
        message: `CORS wildcard (*) em ${endpoint}. Qualquer domínio pode fazer requests.`,
        details: {
          endpoint,
          'Access-Control-Allow-Origin': acao,
          'Access-Control-Allow-Credentials': acac,
          recommendation: 'Configure origens permitidas específicas no Supabase Dashboard.'
        }
      });
    } else if (acao === 'https://evil-attacker.com') {
      results.push({
        check: `CORS — ${endpoint} Origin Reflection`,
        status: 'FAIL',
        severity: 'high',
        message: `CORS reflete qualquer Origin em ${endpoint}! Vulnerável a CSRF.`,
        details: {
          endpoint,
          'Access-Control-Allow-Origin': acao,
          'Access-Control-Allow-Credentials': acac,
          recommendation: 'URGENTE: Configure uma allowlist de origens.'
        }
      });
    }

    if (acac === 'true' && (acao === '*' || acao === 'https://evil-attacker.com')) {
      results.push({
        check: `CORS — ${endpoint} Credentials + Wildcard`,
        status: 'FAIL',
        severity: 'critical',
        message: `CORS permite credentials com origin permissivo em ${endpoint}!`,
        details: {
          endpoint,
          recommendation: 'Combinação perigosa: credentials + wildcard origin permite roubo de sessão.'
        }
      });
    }
  }

  // 2. Check security headers
  const mainRes = await safeFetch(baseUrl, { headers });
  const secHeaders = {
    'strict-transport-security': mainRes.headers['strict-transport-security'],
    'x-frame-options': mainRes.headers['x-frame-options'],
    'x-content-type-options': mainRes.headers['x-content-type-options'],
    'x-xss-protection': mainRes.headers['x-xss-protection'],
    'content-security-policy': mainRes.headers['content-security-policy'],
    'referrer-policy': mainRes.headers['referrer-policy'],
    'permissions-policy': mainRes.headers['permissions-policy']
  };

  const missingHeaders = Object.entries(secHeaders)
    .filter(([_, v]) => !v)
    .map(([k]) => k);

  if (missingHeaders.length > 0) {
    results.push({
      check: 'Security Headers',
      status: missingHeaders.length > 3 ? 'WARN' : 'INFO',
      severity: missingHeaders.length > 3 ? 'medium' : 'low',
      message: `${missingHeaders.length} header(s) de segurança ausente(s).`,
      details: {
        missing: missingHeaders,
        present: Object.entries(secHeaders).filter(([_, v]) => v).map(([k, v]) => ({ [k]: v })),
        recommendation: 'Configure headers de segurança: HSTS, X-Frame-Options, CSP, etc.'
      }
    });
  } else {
    results.push({
      check: 'Security Headers',
      status: 'PASS',
      severity: 'info',
      message: 'Todos os headers de segurança recomendados estão presentes. ✓',
      details: secHeaders
    });
  }

  if (results.length === 0) {
    results.push({
      check: 'CORS — General',
      status: 'PASS',
      severity: 'info',
      message: 'Configuração CORS parece adequada.',
      details: null
    });
  }

  return results;
}

module.exports = { checkCORSConfig };
