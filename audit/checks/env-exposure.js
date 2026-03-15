/*  ═══════════════════════════════════════════════════════════════════
    ENV & SOURCE CODE EXPOSURE SCANNER v2
    Scans website for leaked credentials in:
    - Sensitive file paths (.env, .git/config, docker-compose.yml, etc.)
    - JavaScript bundles (all <script src=""> found in HTML)
    - Source maps (*.js.map) — expose full unminified source
    - Next.js / CRA / Vite build artifacts
    - Inline HTML scripts
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

// ── All sensitive file paths to probe ────────────────────────────
const SENSITIVE_PATHS = [
  // .env variants
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  '/.env.staging', '/.env.test', '/.env.backup', '/.env.example',
  '/.env.prod', '/.env.dev', '/.env.old', '/.env.bak',
  // Config files
  '/config.js', '/config.json', '/config.yml', '/config.yaml',
  '/app.config.js', '/next.config.js', '/nuxt.config.js',
  '/webpack.config.js', '/vite.config.js',
  // Docker / infra
  '/docker-compose.yml', '/docker-compose.yaml', '/Dockerfile',
  '/.dockerenv', '/docker-compose.override.yml',
  // Git
  '/.git/config', '/.git/HEAD', '/.git/COMMIT_EDITMSG',
  '/.git/logs/HEAD', '/.git/refs/heads/main', '/.git/refs/heads/master',
  // PHP / CMS
  '/wp-config.php', '/wp-config-sample.php', '/configuration.php',
  '/settings.php', '/LocalSettings.php',
  // Build artifacts
  '/package.json', '/package-lock.json', '/yarn.lock', '/pnpm-lock.yaml',
  '/.npmrc', '/.yarnrc', '/.nvmrc',
  // Server config
  '/.htaccess', '/web.config', '/nginx.conf', '/apache2.conf',
  // Debug / admin
  '/debug', '/info', '/phpinfo.php', '/server-status', '/server-info',
  '/actuator', '/actuator/env', '/actuator/health', '/actuator/beans',
  '/actuator/configprops', '/actuator/httptrace',
  // APIs
  '/api/config', '/api/env', '/api/settings', '/api/debug',
  '/api/health', '/api/info', '/api/status',
  // Well-known
  '/.well-known/security.txt', '/robots.txt', '/sitemap.xml',
  // Backup files
  '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
  '/backup.zip', '/site.zip', '/www.zip',
  // Key files
  '/id_rsa', '/.ssh/id_rsa', '/server.key', '/private.key',
  '/ssl.key', '/cert.key',
];

// ── Secret patterns to detect in any text content ─────────────────
const SECRET_PATTERNS = [
  // Supabase
  { name: 'SUPABASE_URL',             regex: /(?:NEXT_PUBLIC_)?SUPABASE_URL\s*[=:]\s*["']?(https?:\/\/[^\s"'<>]+)["']?/gi,  severity: 'high'     },
  { name: 'SUPABASE_ANON_KEY',        regex: /(?:NEXT_PUBLIC_)?SUPABASE_ANON_KEY\s*[=:]\s*["']?(eyJ[A-Za-z0-9_\-\.]{20,})["']?/gi, severity: 'high' },
  { name: 'SUPABASE_SERVICE_KEY',     regex: /SUPABASE_SERVICE_ROLE_KEY\s*[=:]\s*["']?(eyJ[A-Za-z0-9_\-\.]{20,})["']?/gi,  severity: 'critical' },
  // Stripe
  { name: 'STRIPE_SECRET_KEY',        regex: /sk_(?:live|test)_[A-Za-z0-9]{20,}/g,                                          severity: 'critical' },
  { name: 'STRIPE_PUBLISHABLE_KEY',   regex: /pk_(?:live|test)_[A-Za-z0-9]{20,}/g,                                          severity: 'medium'   },
  { name: 'STRIPE_WEBHOOK',           regex: /whsec_[A-Za-z0-9]{20,}/g,                                                      severity: 'critical' },
  // MercadoPago
  { name: 'MERCADOPAGO_TOKEN',        regex: /(?:APP_USR-|TEST-)\d{2,}-\d{10,}-[A-Za-z0-9\-]{10,}/g,                        severity: 'critical' },
  { name: 'MERCADOPAGO_KEY',          regex: /(?:mp_access_token|MERCADO_PAGO)\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,})["']?/gi, severity: 'critical' },
  // AWS
  { name: 'AWS_ACCESS_KEY_ID',        regex: /AKIA[0-9A-Z]{16}/g,                                                            severity: 'critical' },
  { name: 'AWS_SECRET_ACCESS_KEY',    regex: /AWS_SECRET(?:_ACCESS_KEY)?\s*[=:]\s*["']?([A-Za-z0-9+\/]{40})["']?/gi,        severity: 'critical' },
  // OpenAI
  { name: 'OPENAI_API_KEY',           regex: /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g,                                           severity: 'critical' },
  // GitHub
  { name: 'GITHUB_TOKEN',             regex: /gh[pso]_[A-Za-z0-9]{36,}/g,                                                   severity: 'critical' },
  // SendGrid
  { name: 'SENDGRID_API_KEY',         regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,                                 severity: 'critical' },
  // Twilio
  { name: 'TWILIO_AUTH_TOKEN',        regex: /(?:TWILIO_AUTH_TOKEN|twilio_auth)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,        severity: 'critical' },
  // Database URLs
  { name: 'DATABASE_URL (Postgres)',  regex: /postgres(?:ql)?:\/\/[^\s"'<>\\]{10,}/gi,                                       severity: 'critical' },
  { name: 'DATABASE_URL (MySQL)',     regex: /mysql:\/\/[^\s"'<>\\]{10,}/gi,                                                  severity: 'critical' },
  { name: 'DATABASE_URL (MongoDB)',   regex: /mongodb(?:\+srv)?:\/\/[^\s"'<>\\]{10,}/gi,                                     severity: 'critical' },
  { name: 'REDIS_URL',               regex: /rediss?:\/\/[^\s"'<>\\]{8,}/gi,                                                  severity: 'critical' },
  // JWT secrets
  { name: 'JWT_SECRET',              regex: /JWT_SECRET\s*[=:]\s*["']?([^\s"'<>]{16,})["']?/gi,                              severity: 'critical' },
  { name: 'JWT_PRIVATE_KEY',         regex: /JWT_PRIVATE_KEY\s*[=:]\s*["']?([^\s"'<>]{16,})["']?/gi,                        severity: 'critical' },
  // Generic API keys
  { name: 'API_KEY',                 regex: /(?<!\w)API_(?:KEY|SECRET)\s*[=:]\s*["']?([A-Za-z0-9_\-\.]{16,})["']?/gi,       severity: 'high'     },
  { name: 'SECRET_KEY',              regex: /SECRET_KEY\s*[=:]\s*["']?([^\s"'<>]{12,})["']?/gi,                              severity: 'high'     },
  { name: 'AUTH_SECRET',             regex: /(?:AUTH|NEXTAUTH)_SECRET\s*[=:]\s*["']?([^\s"'<>]{12,})["']?/gi,               severity: 'high'     },
  // Passwords
  { name: 'PASSWORD',               regex: /(?:PASSWORD|PASSWD|DB_PASS|SMTP_PASS|MAIL_PASS)\s*[=:]\s*["']?([^\s"'<>]{6,})["']?/gi, severity: 'critical' },
  // SMTP
  { name: 'SMTP_CREDENTIALS',       regex: /SMTP_(?:HOST|USER|PASS|PORT)\s*[=:]\s*["']?([^\s"'<>]{4,})["']?/gi,             severity: 'high'     },
  // Private keys
  { name: 'RSA_PRIVATE_KEY',        regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,                                          severity: 'critical' },
  { name: 'SSH_PRIVATE_KEY',        regex: /-----BEGIN OPENSSH PRIVATE KEY-----/g,                                           severity: 'critical' },
  // Firebase
  { name: 'FIREBASE_API_KEY',       regex: /(?:FIREBASE_API_KEY|apiKey)\s*[=:]\s*["']?(AIza[A-Za-z0-9_\-]{35})["']?/gi,    severity: 'high'     },
  // Google
  { name: 'GOOGLE_CLIENT_SECRET',   regex: /GOOGLE_CLIENT_SECRET\s*[=:]\s*["']?([^\s"'<>]{12,})["']?/gi,                   severity: 'high'     },
  { name: 'GCP_KEY_JSON',           regex: /"type"\s*:\s*"service_account"/g,                                                severity: 'critical' },
  // Pusher / Ably
  { name: 'PUSHER_APP_SECRET',      regex: /PUSHER_APP_SECRET\s*[=:]\s*["']?([^\s"'<>]{10,})["']?/gi,                       severity: 'high'     },
  // Cloudinary
  { name: 'CLOUDINARY_API_SECRET',  regex: /CLOUDINARY_API_SECRET\s*[=:]\s*["']?([^\s"'<>]{10,})["']?/gi,                  severity: 'high'     },
  // PagarMe / PagSeguro
  { name: 'PAGARME_KEY',            regex: /ak_(?:live|test)_[A-Za-z0-9]{20,}/g,                                             severity: 'critical' },
  { name: 'PAGSEGURO_TOKEN',        regex: /PAGSEGURO_TOKEN\s*[=:]\s*["']?([a-f0-9\-]{32,})["']?/gi,                        severity: 'critical' },
  // PagerDuty / Slack / Discord webhooks
  { name: 'SLACK_WEBHOOK',          regex: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,            severity: 'high'     },
  { name: 'DISCORD_WEBHOOK',        regex: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/g,                    severity: 'medium'   },
  // Misc
  { name: 'ENCRYPTION_KEY',         regex: /(?:ENCRYPTION|CRYPTO)_KEY\s*[=:]\s*["']?([^\s"'<>]{16,})["']?/gi,              severity: 'high'     },
];

// ── Helpers ───────────────────────────────────────────────────────
function maskValue(val) {
  if (!val) return '[VAZIO]';
  const s = String(val);
  if (s.length <= 10) return s.slice(0, 3) + '[...]';
  return s.slice(0, 6) + '[...]' + s.slice(-3);
}

function getContext(text, matchIndex, matchLen, radius = 60) {
  const start = Math.max(0, matchIndex - radius);
  const end   = Math.min(text.length, matchIndex + matchLen + radius);
  let ctx = text.slice(start, end).replace(/[\n\r\t]+/g, ' ').trim();
  // Redact long base64-like sequences to avoid leaking full keys in context
  ctx = ctx.replace(/[A-Za-z0-9+/=_\-]{30,}/g, '[KEY_MATERIAL]');
  if (start > 0) ctx = '...' + ctx;
  if (end < text.length) ctx = ctx + '...';
  return ctx;
}

function extractScriptUrls(html, baseUrl) {
  const urls = new Set();
  const RE = /<script[^>]*\bsrc=["']([^"']+)["']/gi;
  let m;
  while ((m = RE.exec(html)) !== null) {
    let src = m[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl.replace(/\/$/, '') + src;
    else if (!src.startsWith('http')) src = baseUrl.replace(/\/$/, '') + '/' + src;
    // Only include same-origin scripts
    try {
      const parsedSrc = new URL(src);
      const parsedBase = new URL(baseUrl);
      if (parsedSrc.hostname === parsedBase.hostname) urls.add(src);
    } catch {}
  }
  return [...urls];
}

function scanContent(text, sourceUrl, findings) {
  const content = text.slice(0, 800000); // max 800kb per file
  for (const pat of SECRET_PATTERNS) {
    let match;
    const re = new RegExp(pat.regex.source, pat.regex.flags);
    while ((match = re.exec(content)) !== null) {
      const fullMatch = match[0];
      const capturedVal = match[1] || fullMatch;

      // Skip obvious false positives
      if (/example|test_key|YOUR_|REPLACE_ME|placeholder|xxxx|1234/i.test(capturedVal)) continue;
      if (capturedVal.length < 8) continue;

      findings.push({
        type:     pat.name,
        severity: pat.severity,
        source:   sourceUrl,
        value:    maskValue(capturedVal),
        context:  getContext(content, match.index, fullMatch.length),
      });

      // Avoid flooding with same pattern from same file
      if (findings.filter(f => f.type === pat.name && f.source === sourceUrl).length >= 3) break;
    }
  }
}

async function checkEnvExposure(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl.replace(/\/$/, '');
  const allFindings = [];

  // ── 1. Probe sensitive file paths ────────────────────────────
  emit && emit({ type: 'log', level: 'info', message: `[Env Scanner] Testando ${SENSITIVE_PATHS.length} caminhos sensíveis...` });

  const pathResults = await Promise.all(
    SENSITIVE_PATHS.map(p =>
      safeFetch(baseUrl + p, { timeout: 6000 }).then(res => ({ path: p, res }))
    )
  );

  const exposedPaths = [];
  for (const { path, res } of pathResults) {
    if (!res.ok || !res.text || res.text.length < 5) continue;

    // Avoid generic HTML 404/error pages
    const t = res.text.slice(0, 2000);
    const isHtmlPage = /<html|<!DOCTYPE/i.test(t) && !path.endsWith('.html');
    if (isHtmlPage && t.length > 800) continue;

    const url = baseUrl + path;
    const prevLen = allFindings.length;
    scanContent(res.text, url, allFindings);
    const newFindings = allFindings.length - prevLen;

    // Store raw content for .env files so the report can display the actual exposed content
    const isEnvFile = /\.(env|env\..+)$/.test(path) || path === '/.env';
    const rawContent = isEnvFile ? res.text : undefined;

    exposedPaths.push({ path, url, size: res.text.length, findings: newFindings, rawContent });
    emit && emit({ type: 'log', level: newFindings > 0 ? 'warn' : 'info',
      message: `[Env Scanner] ${path} → ${res.text.length}B${newFindings > 0 ? ` — ${newFindings} segredo(s)!` : ''}` });
  }

  // ── 2. Fetch main page and scan inline scripts + extract bundle URLs ──
  emit && emit({ type: 'log', level: 'info', message: '[Env Scanner] Carregando página principal e extraindo bundles...' });

  const mainPage = await safeFetch(baseUrl, { timeout: 12000 });
  const bundleUrls = [];

  if (mainPage.ok && mainPage.text) {
    // Scan inline scripts
    const inlineRE = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    while ((inlineMatch = inlineRE.exec(mainPage.text)) !== null) {
      if (inlineMatch[1].length > 50) {
        scanContent(inlineMatch[1], `${baseUrl}/ (inline script)`, allFindings);
      }
    }

    bundleUrls.push(...extractScriptUrls(mainPage.text, baseUrl));
    emit && emit({ type: 'log', level: 'info', message: `[Env Scanner] ${bundleUrls.length} bundle(s) JavaScript encontrado(s).` });
  }

  // Also add common Next.js / CRA / Vite paths
  const COMMON_BUNDLE_PATHS = [
    '/static/js/main.js', '/static/js/main.chunk.js',
    '/assets/index.js', '/bundle.js', '/app.js',
    '/_next/static/chunks/main.js', '/_next/static/chunks/webpack.js',
    '/_next/static/chunks/pages/_app.js',
    '/js/app.js', '/js/main.js', '/js/vendor.js',
  ];
  for (const p of COMMON_BUNDLE_PATHS) {
    bundleUrls.push(baseUrl + p);
  }

  // ── 3. Scan JavaScript bundles ───────────────────────────────
  emit && emit({ type: 'log', level: 'info', message: `[Env Scanner] Analisando ${Math.min(bundleUrls.length, 50)} bundles JS...` });

  const BATCH = 6;
  const uniqueBundles = [...new Set(bundleUrls)].slice(0, 50);
  for (let i = 0; i < uniqueBundles.length; i += BATCH) {
    const batch = uniqueBundles.slice(i, i + BATCH);
    const fetches = await Promise.all(
      batch.map(url => safeFetch(url, { timeout: 8000 }).then(res => ({ url, res })))
    );
    for (const { url, res } of fetches) {
      if (!res.ok || !res.text || res.text.length < 100) continue;
      const prevLen = allFindings.length;
      scanContent(res.text, url, allFindings);
      const n = allFindings.length - prevLen;
      if (n > 0) {
        emit && emit({ type: 'log', level: 'warn', message: `[Env Scanner] ${n} segredo(s) em bundle: ${url.replace(baseUrl, '')}` });
      }

      // Also check for .map file (source maps)
      if (url.endsWith('.js') && !url.endsWith('.min.js')) {
        bundleUrls.push(url + '.map');
      }
    }
  }

  // ── 4. Scan source maps (*.js.map) ───────────────────────────
  const mapUrls = [...new Set(bundleUrls)].filter(u => u.endsWith('.map')).slice(0, 15);
  if (mapUrls.length > 0) {
    emit && emit({ type: 'log', level: 'info', message: `[Env Scanner] Verificando ${mapUrls.length} source map(s)...` });
    for (const mapUrl of mapUrls) {
      const res = await safeFetch(mapUrl, { timeout: 8000 });
      if (!res.ok || !res.text) continue;
      const prevLen = allFindings.length;
      scanContent(res.text, mapUrl + ' [SOURCE MAP]', allFindings);
      const n = allFindings.length - prevLen;
      if (n > 0) {
        emit && emit({ type: 'log', level: 'warn',
          message: `[Env Scanner] Source map com credenciais: ${mapUrl.replace(baseUrl, '')} (${n} achados)` });
      }
    }
  }

  // ── 5. Check if provided anon key is actually a service_role key ──
  if (config.anonKey) {
    try {
      const parts = config.anonKey.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
        if (payload.role === 'service_role') {
          results.push({
            check: 'Env/Key — Service Role Key no Frontend',
            status: 'FAIL',
            severity: 'critical',
            message: 'A chave fornecida é uma SERVICE_ROLE key! Nunca deve ser exposta no cliente.',
            details: {
              role: payload.role, iss: payload.iss,
              recommendation: 'URGENTE: Rotacione no Dashboard → Settings → API → Regenerate service_role key.'
            }
          });
        }
      }
    } catch {}
  }

  // ── Compile and deduplicate findings ─────────────────────────
  const seen = new Set();
  const deduped = allFindings.filter(f => {
    const key = `${f.type}:${f.source}:${f.value}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  emit && emit({ type: 'log', level: 'info', message: `[Env Scanner] Compilando ${deduped.length} achados únicos...` });

  // ── Group by severity and emit results ───────────────────────
  const critical = deduped.filter(f => f.severity === 'critical');
  const high     = deduped.filter(f => f.severity === 'high');
  const medium   = deduped.filter(f => f.severity === 'medium');

  if (critical.length > 0) {
    results.push({
      check: 'Env/Source — Credenciais CRÍTICAS Expostas',
      status: 'FAIL',
      severity: 'critical',
      message: `${critical.length} credencial(is) CRÍTICA(S) detectada(s) em código-fonte, bundles ou arquivos .env! Exposição imediata de segurança.`,
      details: {
        findings: critical.map(f => ({
          tipo: f.type,
          localização: f.source,
          valor_mascarado: f.value,
          contexto: f.context,
        })),
        recommendation: 'URGENTE: Rotacione TODAS as chaves listadas imediatamente. Audite o histórico git para garantir que não foram comprometidas anteriormente.',
        affectedUrls: [...new Set(critical.map(f => f.source))],
      }
    });
  }

  if (high.length > 0) {
    results.push({
      check: 'Env/Source — Chaves de Alto Risco Expostas',
      status: 'FAIL',
      severity: 'high',
      message: `${high.length} chave(s) de API de alto risco encontrada(s) em código público.`,
      details: {
        findings: high.map(f => ({
          tipo: f.type,
          localização: f.source,
          valor_mascarado: f.value,
          contexto: f.context,
        })),
        recommendation: 'Rotacione as chaves e mova-as para variáveis de ambiente no servidor.',
        affectedUrls: [...new Set(high.map(f => f.source))],
      }
    });
  }

  if (medium.length > 0) {
    results.push({
      check: 'Env/Source — Configurações Sensíveis',
      status: 'WARN',
      severity: 'medium',
      message: `${medium.length} configuração(ões) sensível(is) de risco médio.`,
      details: {
        findings: medium.map(f => ({ tipo: f.type, localização: f.source, valor_mascarado: f.value })),
      }
    });
  }

  // Exposed paths report
  const exposedWithSecrets = exposedPaths.filter(p => p.findings > 0);
  if (exposedWithSecrets.length > 0) {
    results.push({
      check: 'Env/Source — Arquivos Sensíveis Acessíveis',
      status: 'FAIL',
      severity: 'critical',
      message: `${exposedWithSecrets.length} arquivo(s) sensível(is) com credenciais acessível(is) publicamente!`,
      details: {
        files: exposedWithSecrets.map(p => ({
          url: p.url,
          achados: p.findings,
          tamanho: p.size + ' bytes',
          // rawContent only populated for .env files — stripped before DB persistence
          rawContent: p.rawContent || undefined
        })),
        recommendation: 'Bloqueie acesso a estes arquivos via configuração do servidor (nginx/apache). Rotacione todas as credenciais imediatamente.',
      }
    });
  } else if (exposedPaths.length > 0) {
    results.push({
      check: 'Env/Source — Arquivos de Configuração Expostos',
      status: 'WARN',
      severity: 'medium',
      message: `${exposedPaths.length} arquivo(s) de configuração acessível(is) sem credenciais detectadas.`,
      details: { files: exposedPaths.map(p => p.url) }
    });
  }

  if (deduped.length === 0 && exposedPaths.length === 0) {
    results.push({
      check: 'Env/Source — Scanner de Credenciais',
      status: 'PASS',
      severity: 'info',
      message: `Nenhuma credencial ou arquivo sensível detectado. ${SENSITIVE_PATHS.length} caminhos + ${uniqueBundles.length} bundles JS analisados.`,
      details: {
        pathsScanned: SENSITIVE_PATHS.length,
        bundlesScanned: uniqueBundles.length,
        sourceMapsScanned: mapUrls.length,
      }
    });
  }

  return results;
}

module.exports = { checkEnvExposure };
