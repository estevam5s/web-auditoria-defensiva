/*  CHECK: .env / Key Exposure
    Tests if sensitive keys or .env data is exposed in common locations */

const { safeFetch } = require('../helpers/http');

async function checkEnvExposure(config) {
  const results = [];
  const baseUrl = config.projectUrl;

  // 1. Common paths where .env or keys might be exposed
  const sensitiveFiles = [
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/.env.example',
    '/env.js',
    '/config.js',
    '/config.json',
    '/.git/config',
    '/.git/HEAD',
    '/wp-config.php',
    '/.DS_Store',
    '/package.json',
    '/.npmrc',
    '/docker-compose.yml',
    '/Dockerfile',
    '/.dockerenv',
    '/api/config',
    '/api/env',
    '/debug',
    '/info',
    '/phpinfo.php',
    '/server-status',
    '/actuator',
    '/actuator/env',
    '/.well-known/security.txt',
    '/robots.txt',
    '/sitemap.xml',
    '/.htaccess',
    '/web.config'
  ];

  const exposedFiles = [];

  for (const file of sensitiveFiles) {
    const url = baseUrl + file;
    const res = await safeFetch(url, { timeout: 5000 });

    if (res.ok && res.text && res.text.length > 0) {
      // Check if it looks like a real file (not a generic error page)
      const isLikelyReal = 
        res.text.length < 50000 && (
          res.text.includes('=') || 
          res.text.includes('{') || 
          res.text.includes('[') ||
          res.text.includes('ref:') ||
          res.text.includes('supabase') ||
          res.text.includes('password') ||
          res.text.includes('secret') ||
          res.text.includes('key') ||
          res.text.includes('token') ||
          file.endsWith('.txt') ||
          file.endsWith('.xml')
        );

      if (isLikelyReal) {
        // Check for leaked secrets in the content
        const secretPatterns = [
          { name: 'SUPABASE_URL', pattern: /SUPABASE_URL|NEXT_PUBLIC_SUPABASE_URL/i },
          { name: 'SUPABASE_ANON_KEY', pattern: /SUPABASE_ANON_KEY|NEXT_PUBLIC_SUPABASE_ANON_KEY/i },
          { name: 'SUPABASE_SERVICE_KEY', pattern: /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE_KEY/i },
          { name: 'DATABASE_URL', pattern: /DATABASE_URL|DB_URL|DB_CONNECTION/i },
          { name: 'JWT_SECRET', pattern: /JWT_SECRET|JWT_KEY/i },
          { name: 'API_KEY', pattern: /API_KEY|APIKEY|API_SECRET/i },
          { name: 'AWS_KEY', pattern: /AWS_ACCESS_KEY|AWS_SECRET/i },
          { name: 'STRIPE_KEY', pattern: /STRIPE_SECRET|STRIPE_KEY|sk_live/i },
          { name: 'OPENAI_KEY', pattern: /OPENAI_API_KEY|OPENAI_KEY/i },
          { name: 'SMTP_PASSWORD', pattern: /SMTP_PASSWORD|MAIL_PASSWORD|EMAIL_PASS/i },
          { name: 'PRIVATE_KEY', pattern: /PRIVATE_KEY|-----BEGIN.*KEY/i },
          { name: 'PASSWORD', pattern: /PASSWORD\s*=|PASS\s*=/i },
          { name: 'GIT_CONFIG', pattern: /\[remote|url\s*=.*github|url\s*=.*gitlab/i }
        ];

        const foundSecrets = secretPatterns
          .filter(sp => sp.pattern.test(res.text))
          .map(sp => sp.name);

        exposedFiles.push({
          path: file,
          size: res.text.length,
          secrets: foundSecrets,
          contentType: res.headers?.['content-type'] || 'unknown',
          preview: res.text.substring(0, 200).replace(/[a-zA-Z0-9]{20,}/g, '[REDACTED]')
        });
      }
    }
  }

  if (exposedFiles.length > 0) {
    const withSecrets = exposedFiles.filter(f => f.secrets.length > 0);
    
    results.push({
      check: 'Env/Key Exposure — File Discovery',
      status: 'FAIL',
      severity: withSecrets.length > 0 ? 'critical' : 'high',
      message: `${exposedFiles.length} arquivo(s) sensível(is) acessível(is)! ${withSecrets.length > 0 ? `Secrets detectados: ${[...new Set(withSecrets.flatMap(f => f.secrets))].join(', ')}` : ''}`,
      details: {
        files: exposedFiles,
        recommendation: 'URGENTE: Remova arquivos sensíveis do servidor público. Rotacione todas as chaves expostas imediatamente.'
      }
    });
  } else {
    results.push({
      check: 'Env/Key Exposure — File Discovery',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum arquivo .env ou configuração sensível encontrado exposto.',
      details: { filesChecked: sensitiveFiles.length }
    });
  }

  // 2. Check if anon key looks like a service_role key (common mistake)
  if (config.anonKey) {
    try {
      const parts = config.anonKey.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        
        if (payload.role === 'service_role') {
          results.push({
            check: 'Key Exposure — Service Role Key',
            status: 'FAIL',
            severity: 'critical',
            message: 'A chave fornecida é uma SERVICE_ROLE key! Esta chave nunca deve ser exposta no cliente.',
            details: {
              role: payload.role,
              iss: payload.iss,
              recommendation: 'URGENTE: Rotacione a service_role key imediatamente. Use apenas anon key no cliente.'
            }
          });
        } else {
          results.push({
            check: 'Key Exposure — Key Type',
            status: 'PASS',
            severity: 'info',
            message: `Chave identificada como role "${payload.role}". ✓`,
            details: { role: payload.role, iss: payload.iss }
          });
        }
      }
    } catch {}
  }

  // 3. Check common frontend build paths for exposed env vars
  const buildPaths = [
    '/static/js/main.js',
    '/_next/static/',
    '/assets/index.js',
    '/build/static/js/',
    '/js/app.js',
    '/bundle.js'
  ];

  for (const path of buildPaths) {
    const url = baseUrl + path;
    const res = await safeFetch(url, { timeout: 5000 });

    if (res.ok && res.text) {
      const serviceKeyPattern = /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g;
      const matches = res.text.match(serviceKeyPattern);

      if (matches) {
        for (const token of matches) {
          try {
            const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
            if (payload.role === 'service_role') {
              results.push({
                check: 'Key Exposure — Service Key in Bundle',
                status: 'FAIL',
                severity: 'critical',
                message: `SERVICE_ROLE key encontrada em bundle JavaScript: ${path}`,
                details: {
                  path,
                  recommendation: 'URGENTE: Remova a service_role key do código frontend. Rotacione a chave.'
                }
              });
            }
          } catch {}
        }
      }
    }
  }

  return results;
}

module.exports = { checkEnvExposure };
