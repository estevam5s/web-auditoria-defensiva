/*  CHECK: Service Key Leak Detection
    Checks if service_role key is leaked in public resources */

const { safeFetch } = require('../helpers/http');

async function checkServiceKeyLeak(config) {
  const results = [];
  const baseUrl = config.projectUrl;

  // Common places where service keys get leaked
  const publicPaths = [
    '/',
    '/index.html',
    '/app.js',
    '/main.js',
    '/bundle.js',
    '/static/js/main.js',
    '/static/js/bundle.js',
    '/_next/static/chunks/app/layout.js',
    '/_next/static/chunks/main.js',
    '/assets/index.js',
    '/dist/index.js',
    '/build/bundle.js',
    '/js/app.js',
    '/js/main.js',
    '/config.js',
    '/env.js',
    '/api/config',
    '/manifest.json',
    '/__next/data.json'
  ];

  let serviceKeyFound = false;
  const jwtPattern = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]+/g;

  for (const path of publicPaths) {
    const url = baseUrl + path;
    const res = await safeFetch(url, { timeout: 8000 });

    if (!res.ok || !res.text || res.text.length === 0) continue;

    const matches = res.text.match(jwtPattern);
    if (!matches) continue;

    for (const token of [...new Set(matches)]) {
      try {
        const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
        
        if (payload.role === 'service_role') {
          serviceKeyFound = true;
          results.push({
            check: 'Service Key — Leaked in Public',
            status: 'FAIL',
            severity: 'critical',
            message: `SERVICE_ROLE key encontrada em: ${path}`,
            details: {
              path,
              tokenPreview: token.substring(0, 40) + '...[REDACTED]',
              role: payload.role,
              issuer: payload.iss,
              recommendation: 'URGENTE: Rotacione a service_role key IMEDIATAMENTE. Remova do código público.'
            }
          });
        } else if (payload.role === 'anon') {
          // Anon key is expected in frontend, but note it
          results.push({
            check: `Service Key — Anon Key in ${path}`,
            status: 'INFO',
            severity: 'info',
            message: `Anon key encontrada em ${path} (esperado em frontends).`,
            details: { path, role: payload.role }
          });
        }
      } catch {}
    }

    // Also check for direct env variable patterns
    const envPatterns = [
      /SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*["']?([^"'\s]+)/gi,
      /service_role_key\s*[=:]\s*["']?([^"'\s]+)/gi,
      /SERVICE_KEY\s*[=:]\s*["']?([^"'\s]+)/gi
    ];

    for (const pattern of envPatterns) {
      const envMatches = res.text.match(pattern);
      if (envMatches) {
        results.push({
          check: 'Service Key — Env Variable Exposed',
          status: 'FAIL',
          severity: 'critical',
          message: `Variável de ambiente com service key encontrada em: ${path}`,
          details: {
            path,
            pattern: pattern.source,
            recommendation: 'URGENTE: Remova variáveis de ambiente do código público.'
          }
        });
      }
    }
  }

  if (!serviceKeyFound && results.filter(r => r.severity === 'critical').length === 0) {
    results.push({
      check: 'Service Key — Leak Check',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum vazamento de service_role key detectado em recursos públicos. ✓',
      details: { pathsChecked: publicPaths.length }
    });
  }

  return results;
}

module.exports = { checkServiceKeyLeak };
