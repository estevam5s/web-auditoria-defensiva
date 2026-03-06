/*  CHECK: DNS & Connectivity
    Basic connectivity and DNS resolution checks */

const { safeFetch } = require('../helpers/http');

async function checkDNSInfo(config) {
  const results = [];
  const baseUrl = config.projectUrl;

  // 1. Basic connectivity
  const res = await safeFetch(baseUrl, { timeout: 15000 });

  if (res.status === 0) {
    results.push({
      check: 'DNS — Connectivity',
      status: 'FAIL',
      severity: 'critical',
      message: `Não foi possível conectar ao projeto: ${res.statusText}`,
      details: {
        url: baseUrl,
        error: res.error,
        recommendation: 'Verifique se a URL do projeto está correta e o projeto está ativo.'
      }
    });
    return results;
  }

  results.push({
    check: 'DNS — Connectivity',
    status: 'PASS',
    severity: 'info',
    message: `Projeto acessível. Status: ${res.status}`,
    details: {
      url: baseUrl,
      status: res.status,
      server: res.headers?.['server'] || 'unknown',
      via: res.headers?.['via'] || null,
      cfRay: res.headers?.['cf-ray'] || null
    }
  });

  // 2. Check HTTPS
  if (baseUrl.startsWith('http://')) {
    results.push({
      check: 'DNS — HTTPS',
      status: 'FAIL',
      severity: 'high',
      message: 'Projeto está usando HTTP sem criptografia!',
      details: { recommendation: 'Use HTTPS para todas as comunicações.' }
    });
  } else {
    results.push({
      check: 'DNS — HTTPS',
      status: 'PASS',
      severity: 'info',
      message: 'Projeto usa HTTPS. ✓',
      details: null
    });
  }

  // 3. Check server headers
  const serverInfo = {
    server: res.headers?.['server'],
    poweredBy: res.headers?.['x-powered-by'],
    via: res.headers?.['via'],
    cdn: res.headers?.['cf-ray'] ? 'Cloudflare' : (res.headers?.['x-amz-cf-id'] ? 'CloudFront' : null)
  };

  if (serverInfo.poweredBy) {
    results.push({
      check: 'DNS — Server Info Leak',
      status: 'WARN',
      severity: 'low',
      message: `Header X-Powered-By expõe tecnologia: ${serverInfo.poweredBy}`,
      details: {
        ...serverInfo,
        recommendation: 'Remova o header X-Powered-By para reduzir fingerprinting.'
      }
    });
  }

  // 4. Check if Supabase project or custom domain
  if (config.projectRef) {
    results.push({
      check: 'DNS — Project Info',
      status: 'INFO',
      severity: 'info',
      message: `Projeto Supabase detectado. Ref: ${config.projectRef}`,
      details: {
        ref: config.projectRef,
        region: baseUrl.includes('.co') ? 'Supabase Cloud' : 'Self-hosted'
      }
    });
  }

  return results;
}

module.exports = { checkDNSInfo };
