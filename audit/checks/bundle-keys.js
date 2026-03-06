/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Token & Key Bundle Scanner
    Deep analysis of all public JS/CSS/HTML bundles for:
    - Supabase service_role keys
    - Gateway payment credentials (Stripe, MercadoPago, PagSeguro, etc)
    - Cloud provider keys (AWS, GCP, Azure)
    - API keys for third-party services
    - JWT secrets, private keys, connection strings
    - Env variables embedded in bundles
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// ── Comprehensive Key/Token Patterns ─────────────────────────────
const KEY_PATTERNS = [
  // ── Supabase ──
  { name: 'Supabase Service Role Key',    regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/g, decode: 'jwt', severity: 'critical', category: 'Supabase' },
  { name: 'SUPABASE_SERVICE_ROLE_KEY',     regex: /(?:SUPABASE_SERVICE_ROLE_KEY|supabase_service_role_key|SERVICE_ROLE_KEY)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Supabase' },
  { name: 'Supabase DB Password',         regex: /(?:SUPABASE_DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*[=:]\s*["']?([^"'\s]{6,})["']?/gi, severity: 'critical', category: 'Supabase' },
  { name: 'Supabase JWT Secret',          regex: /(?:JWT_SECRET|SUPABASE_JWT_SECRET|SIGNING_KEY)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Supabase' },

  // ── Payment Gateways ──
  { name: 'Stripe Secret Key',    regex: /sk_live_[A-Za-z0-9]{20,}/g,                     severity: 'critical', category: 'Payment' },
  { name: 'Stripe Test Secret',   regex: /sk_test_[A-Za-z0-9]{20,}/g,                     severity: 'high',     category: 'Payment' },
  { name: 'Stripe Publishable',   regex: /pk_(?:live|test)_[A-Za-z0-9]{20,}/g,            severity: 'low',      category: 'Payment' },
  { name: 'Stripe Webhook Secret',regex: /whsec_[A-Za-z0-9]{20,}/g,                       severity: 'critical', category: 'Payment' },
  { name: 'Stripe Connect',       regex: /(?:rk_live|rk_test)_[A-Za-z0-9]{20,}/g,         severity: 'critical', category: 'Payment' },
  { name: 'MercadoPago Access',   regex: /(?:APP_USR-|TEST-)\d{10,}-[A-Za-z0-9]{6,}-[A-Za-z0-9-]{20,}/g, severity: 'critical', category: 'Payment' },
  { name: 'MercadoPago Token',    regex: /(?:MERCADOPAGO_TOKEN|MP_ACCESS_TOKEN|mercado_pago_access_token)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Payment' },
  { name: 'PagSeguro Token',      regex: /(?:PAGSEGURO_TOKEN|pagseguro_token)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Payment' },
  { name: 'PagarMe API Key',      regex: /(?:PAGARME_API_KEY|pagarme_api_key|ak_live_|ak_test_)[A-Za-z0-9]{10,}/gi, severity: 'critical', category: 'Payment' },
  { name: 'Asaas API Key',        regex: /(?:ASAAS_API_KEY|asaas_api_key)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Payment' },
  { name: 'Iugu API Token',       regex: /(?:IUGU_API_TOKEN|iugu_api_token)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Payment' },
  { name: 'PayPal Secret',        regex: /(?:PAYPAL_SECRET|PAYPAL_CLIENT_SECRET|paypal_secret)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Payment' },
  { name: 'PayPal Access Token',  regex: /A21AA[A-Za-z0-9_\-]{50,}/g,                    severity: 'critical', category: 'Payment' },
  { name: 'Square Access Token',  regex: /sq0atp-[A-Za-z0-9_\-]{22}/g,                   severity: 'critical', category: 'Payment' },
  { name: 'Razorpay Key',         regex: /rzp_(?:live|test)_[A-Za-z0-9]{14,}/g,           severity: 'critical', category: 'Payment' },

  // ── AWS ──
  { name: 'AWS Access Key',       regex: /AKIA[0-9A-Z]{16}/g,                              severity: 'critical', category: 'Cloud' },
  { name: 'AWS Secret Key',       regex: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi, severity: 'critical', category: 'Cloud' },
  { name: 'AWS Session Token',    regex: /(?:AWS_SESSION_TOKEN)\s*[=:]\s*["']?([^"'\s]{50,})["']?/gi, severity: 'critical', category: 'Cloud' },

  // ── Google ──
  { name: 'Google API Key',       regex: /AIza[A-Za-z0-9_\-]{35}/g,                        severity: 'high',     category: 'Cloud' },
  { name: 'Google OAuth Secret',  regex: /(?:GOOGLE_CLIENT_SECRET|google_client_secret)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'Cloud' },
  { name: 'Firebase Config',      regex: /(?:FIREBASE_API_KEY|FIREBASE_TOKEN)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'high', category: 'Cloud' },
  { name: 'GCP Service Account',  regex:/"type"\s*:\s*"service_account"/g,                 severity: 'critical', category: 'Cloud' },

  // ── Azure ──
  { name: 'Azure Connection',     regex: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+/g, severity: 'critical', category: 'Cloud' },
  { name: 'Azure SAS Token',      regex: /(?:sv|se|sp|sig)=[A-Za-z0-9%]+&(?:sv|se|sp|sig)=[A-Za-z0-9%]+/g, severity: 'high', category: 'Cloud' },

  // ── Communication ──
  { name: 'Twilio Auth Token',    regex: /(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, severity: 'critical', category: 'Communication' },
  { name: 'SendGrid API Key',     regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g,  severity: 'critical', category: 'Communication' },
  { name: 'Mailgun API Key',      regex: /key-[a-f0-9]{32}/g,                              severity: 'critical', category: 'Communication' },
  { name: 'Resend API Key',       regex: /re_[A-Za-z0-9]{20,}/g,                           severity: 'critical', category: 'Communication' },
  { name: 'Postmark Token',       regex: /(?:POSTMARK_TOKEN|POSTMARK_SERVER_TOKEN)\s*[=:]\s*["']?([a-f0-9-]{36,})["']?/gi, severity: 'critical', category: 'Communication' },

  // ── AI / LLM ──
  { name: 'OpenAI API Key',       regex: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g, severity: 'critical', category: 'AI' },
  { name: 'OpenAI Key v2',        regex: /sk-proj-[A-Za-z0-9_\-]{40,}/g,                  severity: 'critical', category: 'AI' },
  { name: 'Anthropic Key',        regex: /sk-ant-[A-Za-z0-9_\-]{40,}/g,                   severity: 'critical', category: 'AI' },
  { name: 'Cohere Key',           regex: /(?:COHERE_API_KEY)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'critical', category: 'AI' },

  // ── Version Control ──
  { name: 'GitHub Token',         regex: /gh[ps]_[A-Za-z0-9]{36,}/g,                       severity: 'critical', category: 'VCS' },
  { name: 'GitHub OAuth',         regex: /gho_[A-Za-z0-9]{36,}/g,                          severity: 'critical', category: 'VCS' },
  { name: 'GitLab Token',         regex: /glpat-[A-Za-z0-9_\-]{20,}/g,                    severity: 'critical', category: 'VCS' },

  // ── Database ──
  { name: 'Database URL',         regex: /(?:postgres|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'<>{}\[\]]+/gi, severity: 'critical', category: 'Database' },
  { name: 'Redis URL',            regex: /rediss?:\/\/[^\s"'<>]+/gi,                       severity: 'critical', category: 'Database' },

  // ── General Secrets ──
  { name: 'Private RSA Key',      regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,           severity: 'critical', category: 'Crypto' },
  { name: 'Private EC Key',       regex: /-----BEGIN EC PRIVATE KEY-----/g,                 severity: 'critical', category: 'Crypto' },
  { name: 'Private PGP Key',      regex: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,          severity: 'critical', category: 'Crypto' },
  { name: 'Generic Secret',       regex: /(?:SECRET_KEY|APP_SECRET|MASTER_KEY|ENCRYPTION_KEY|SIGNING_SECRET)\s*[=:]\s*["']?([^"'\s]{16,})["']?/gi, severity: 'high', category: 'Generic' },
  { name: 'Generic API Key',      regex: /(?:API_KEY|APIKEY|api_key)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi, severity: 'high', category: 'Generic' },
  { name: 'Bearer Token',         regex: /Bearer\s+[A-Za-z0-9_\-\.]{30,}/g,                severity: 'high', category: 'Generic' },
  { name: 'Basic Auth',           regex: /Basic\s+[A-Za-z0-9+/=]{20,}/g,                   severity: 'high', category: 'Generic' },

  // ── Slack / Discord ──
  { name: 'Slack Token',          regex: /xox[bsrp]-[A-Za-z0-9\-]{20,}/g,                 severity: 'critical', category: 'Communication' },
  { name: 'Slack Webhook',        regex: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g, severity: 'high', category: 'Communication' },
  { name: 'Discord Webhook',      regex: /discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/g, severity: 'high', category: 'Communication' },
  { name: 'Discord Bot Token',    regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,     severity: 'critical', category: 'Communication' },

  // ── Misc ──
  { name: 'Algolia Admin Key',    regex: /(?:ALGOLIA_ADMIN_KEY|algolia_admin_key)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, severity: 'critical', category: 'Search' },
  { name: 'Sentry DSN',          regex: /https:\/\/[a-f0-9]{32}@[^\s"']+\.ingest\.sentry\.io/g, severity: 'medium', category: 'Monitoring' },
  { name: 'Vercel Token',         regex: /(?:VERCEL_TOKEN)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'high', category: 'Deploy' },
  { name: 'Netlify Token',        regex: /(?:NETLIFY_AUTH_TOKEN)\s*[=:]\s*["']?([^"'\s]{20,})["']?/gi, severity: 'high', category: 'Deploy' },
];

// Extended list of paths to scan
const BUNDLE_PATHS = [
  // Root
  '/', '/index.html', '/app.html',
  // JavaScript bundles
  '/app.js', '/main.js', '/bundle.js', '/vendor.js', '/runtime.js', '/polyfills.js',
  '/chunk-vendors.js', '/config.js', '/env.js', '/constants.js', '/globals.js',
  // Build outputs
  '/static/js/main.js', '/static/js/bundle.js', '/static/js/vendor.js',
  '/static/js/runtime.js', '/static/js/app.js',
  '/assets/index.js', '/assets/vendor.js', '/assets/app.js',
  '/_next/static/chunks/main.js', '/_next/static/chunks/webpack.js',
  '/_next/static/chunks/framework.js', '/_next/static/chunks/pages/_app.js',
  '/_next/static/chunks/app/layout.js', '/_next/static/chunks/app/page.js',
  '/dist/index.js', '/dist/bundle.js', '/dist/app.js',
  '/build/static/js/main.js', '/build/bundle.js',
  '/js/app.js', '/js/main.js', '/js/config.js',
  '/scripts/main.js', '/scripts/app.js',
  // Config files
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  '/config.json', '/app.config.js', '/next.config.js', '/nuxt.config.js',
  '/vercel.json', '/netlify.toml',
  // API endpoints  
  '/api/config', '/api/env', '/api/settings', '/api/health',
  '/__env', '/__config',
  // Source maps
  '/app.js.map', '/main.js.map', '/bundle.js.map',
  '/static/js/main.js.map', '/assets/index.js.map',
  // Manifest
  '/manifest.json', '/asset-manifest.json', '/_buildManifest.js', '/_ssgManifest.js',
];

async function deepBundleKeyScanner(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const allFindings = [];

  emit({ type: 'log', level: 'info', message: '[Bundle Scanner] Iniciando varredura profunda de tokens e chaves em bundles...' });

  // ═══════════ 1. Scan all known paths ═══════════
  emit({ type: 'log', level: 'info', message: `[Bundle Scanner] Escaneando ${BUNDLE_PATHS.length} paths conhecidos...` });

  const BATCH = 8;
  let scannedPaths = 0;

  for (let i = 0; i < BUNDLE_PATHS.length; i += BATCH) {
    const batch = BUNDLE_PATHS.slice(i, i + BATCH);
    const fetches = batch.map(path =>
      safeFetch(baseUrl + path, { timeout: 8000 })
        .then(res => ({ path, res }))
    );

    const batchResults = await Promise.all(fetches);

    for (const { path, res } of batchResults) {
      scannedPaths++;
      if (!res.ok || !res.text || res.text.length < 20) continue;

      scanContentForKeys(res.text, path, allFindings, emit);
    }

    if (scannedPaths % 24 === 0) {
      emit({ type: 'log', level: 'info', message: `[Bundle Scanner] ${scannedPaths}/${BUNDLE_PATHS.length} paths escaneados... (${allFindings.length} achados)` });
    }
  }

  // ═══════════ 2. Dynamic JS Discovery from HTML ═══════════
  emit({ type: 'log', level: 'info', message: '[Bundle Scanner] Descobrindo scripts dinâmicos no HTML...' });

  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  if (mainPage.ok && mainPage.text) {
    const jsUrls = extractAllScriptUrls(mainPage.text, baseUrl);
    const newUrls = jsUrls.filter(u => !BUNDLE_PATHS.some(p => u.endsWith(p)));

    emit({ type: 'log', level: 'info', message: `[Bundle Scanner] ${newUrls.length} scripts adicionais encontrados no HTML...` });

    for (let i = 0; i < newUrls.length && i < 60; i += BATCH) {
      const batch = newUrls.slice(i, i + BATCH);
      const fetches = batch.map(url =>
        safeFetch(url, { timeout: 8000 })
          .then(res => ({ url, res }))
      );

      const batchResults = await Promise.all(fetches);
      for (const { url, res } of batchResults) {
        if (!res.ok || !res.text || res.text.length < 50) continue;
        const shortUrl = url.replace(baseUrl, '');
        scanContentForKeys(res.text, shortUrl, allFindings, emit);
      }
    }
  }

  // ═══════════ 3. Supabase JWT Analysis ═══════════
  emit({ type: 'log', level: 'info', message: '[Bundle Scanner] Analisando JWTs encontrados...' });

  const jwtFindings = allFindings.filter(f => f.pattern === 'Supabase Service Role Key');
  for (const finding of jwtFindings) {
    if (finding.rawMatch) {
      try {
        const parts = finding.rawMatch.split('.');
        const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());

        if (payload.role === 'service_role') {
          finding.confirmed = true;
          finding.jwtPayload = {
            role: payload.role,
            issuer: payload.iss,
            exp: payload.exp ? new Date(payload.exp * 1000).toISOString() : 'none',
          };
          emit({ type: 'log', level: 'warn', message: `[Bundle Scanner] 🚨 SERVICE_ROLE KEY CONFIRMADA em ${finding.source}!` });
        } else if (payload.role === 'anon') {
          finding.severity = 'info';
          finding.note = 'Anon key (esperado em frontend)';
        }
      } catch (e) {}
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[Bundle Scanner] Compilando ${allFindings.length} achados...` });

  // Group by category
  const byCategory = {};
  for (const f of allFindings) {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category].push(f);
  }

  // Payment gateway keys
  const paymentKeys = byCategory['Payment'] || [];
  if (paymentKeys.length > 0) {
    const live = paymentKeys.filter(k => k.severity === 'critical');
    results.push({
      check: 'Bundle — Credenciais de Gateway de Pagamento',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${paymentKeys.length} credencial(is) de pagamento encontrada(s) em bundles públicos! (${live.length} de produção)`,
      details: {
        findings: paymentKeys.map(k => ({
          type: k.pattern,
          source: k.source,
          preview: k.preview,
          severity: k.severity,
        })),
        recommendation: 'URGENTE: Rotacione TODAS as chaves de pagamento expostas. Nunca coloque chaves secretas de gateway em código frontend.'
      }
    });
  }

  // Supabase critical keys
  const supabaseKeys = (byCategory['Supabase'] || []).filter(k => k.severity === 'critical' && (k.confirmed || k.pattern !== 'Supabase Service Role Key'));
  if (supabaseKeys.length > 0) {
    results.push({
      check: 'Bundle — Chaves Supabase Críticas',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${supabaseKeys.length} chave(s) Supabase sensível(is) exposta(s) em bundles!`,
      details: {
        findings: supabaseKeys.map(k => ({
          type: k.pattern,
          source: k.source,
          preview: k.preview,
          confirmed: k.confirmed,
          jwtPayload: k.jwtPayload,
        })),
        recommendation: 'URGENTE: Rotacione a service_role key e JWT secret no Dashboard do Supabase.'
      }
    });
  }

  // Cloud provider keys
  const cloudKeys = byCategory['Cloud'] || [];
  if (cloudKeys.length > 0) {
    results.push({
      check: 'Bundle — Credenciais Cloud (AWS/GCP/Azure)',
      status: 'FAIL',
      severity: 'critical',
      message: `${cloudKeys.length} credencial(is) de cloud provider encontrada(s) em bundles!`,
      details: {
        findings: cloudKeys.map(k => ({ type: k.pattern, source: k.source, preview: k.preview })),
        recommendation: 'Rotacione imediatamente. Use IAM roles/service accounts em vez de keys estáticos.'
      }
    });
  }

  // Communication keys (Twilio, SendGrid, etc)
  const commsKeys = byCategory['Communication'] || [];
  if (commsKeys.length > 0) {
    results.push({
      check: 'Bundle — Chaves de Comunicação (Email/SMS)',
      status: 'FAIL',
      severity: 'high',
      message: `${commsKeys.length} chave(s) de serviço de comunicação encontrada(s) (Twilio, SendGrid, etc.)`,
      details: {
        findings: commsKeys.map(k => ({ type: k.pattern, source: k.source, preview: k.preview })),
        recommendation: 'Mova chaves de email/SMS para variáveis de ambiente no servidor. Nunca exponha no frontend.'
      }
    });
  }

  // AI keys
  const aiKeys = byCategory['AI'] || [];
  if (aiKeys.length > 0) {
    results.push({
      check: 'Bundle — Chaves de IA (OpenAI/Anthropic)',
      status: 'FAIL',
      severity: 'critical',
      message: `${aiKeys.length} chave(s) de API de IA encontrada(s) em bundles! Uso malicioso pode gerar custos.`,
      details: {
        findings: aiKeys.map(k => ({ type: k.pattern, source: k.source, preview: k.preview })),
        recommendation: 'URGENTE: Rotacione e mova para backend. Use proxy server para chamadas de IA.'
      }
    });
  }

  // Database URLs
  const dbKeys = byCategory['Database'] || [];
  if (dbKeys.length > 0) {
    results.push({
      check: 'Bundle — Connection Strings de Database',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${dbKeys.length} URL(s) de banco de dados encontrada(s) em bundles!`,
      details: {
        findings: dbKeys.map(k => ({ type: k.pattern, source: k.source, preview: k.preview })),
        recommendation: 'URGENTE: Mude senha do DB. Nunca exponha connection strings no frontend.'
      }
    });
  }

  // Crypto keys
  const cryptoKeys = byCategory['Crypto'] || [];
  if (cryptoKeys.length > 0) {
    results.push({
      check: 'Bundle — Chaves Privadas',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${cryptoKeys.length} chave(s) privada(s) (RSA/EC/PGP) encontrada(s) em bundles!`,
      details: {
        findings: cryptoKeys.map(k => ({ type: k.pattern, source: k.source })),
        recommendation: 'URGENTE: Chaves privadas NUNCA devem estar em código público. Revogue e regenere.'
      }
    });
  }

  // Generic/other
  const otherKeys = [...(byCategory['Generic'] || []), ...(byCategory['VCS'] || []),
    ...(byCategory['Search'] || []), ...(byCategory['Deploy'] || []), ...(byCategory['Monitoring'] || [])];
  if (otherKeys.length > 0) {
    results.push({
      check: 'Bundle — Outras Chaves/Tokens',
      status: 'WARN',
      severity: 'high',
      message: `${otherKeys.length} chave(s)/token(s) adicional(is) encontrado(s) em bundles.`,
      details: {
        findings: otherKeys.map(k => ({ type: k.pattern, source: k.source, preview: k.preview, severity: k.severity })),
        recommendation: 'Revise cada chave e mova para variáveis de ambiente do servidor quando possível.'
      }
    });
  }

  // All clear
  if (allFindings.length === 0) {
    results.push({
      check: 'Bundle — Token/Key Scan',
      status: 'PASS',
      severity: 'info',
      message: `✓ Nenhum token ou chave sensível detectado em ${scannedPaths} bundles públicos.`,
      details: { pathsScanned: scannedPaths, patternsChecked: KEY_PATTERNS.length }
    });
  } else {
    results.push({
      check: 'Bundle — Resumo Geral',
      status: 'INFO',
      severity: 'info',
      message: `Total: ${allFindings.length} chave(s)/token(s) em ${scannedPaths} bundles. Por categoria: ${Object.entries(byCategory).map(([k,v]) => `${k}:${v.length}`).join(', ')}`,
      details: { total: allFindings.length, byCategory: Object.fromEntries(Object.entries(byCategory).map(([k,v]) => [k, v.length])) }
    });
  }

  return results;
}

function scanContentForKeys(text, source, findings, emit) {
  const content = text.substring(0, 1000000); // 1MB max

  for (const pattern of KEY_PATTERNS) {
    const matches = content.match(pattern.regex);
    if (!matches) continue;

    const unique = [...new Set(matches)];

    for (const match of unique) {
      // Filter false positives
      if (isFalsePositive(match, pattern)) continue;

      const preview = match.length > 20
        ? match.substring(0, 10) + '***' + match.substring(match.length - 6)
        : '***REDACTED***';

      findings.push({
        pattern: pattern.name,
        category: pattern.category,
        severity: pattern.severity,
        source,
        preview,
        rawMatch: pattern.decode === 'jwt' ? match : undefined,
        matchLength: match.length,
      });

      if (pattern.severity === 'critical') {
        emit({ type: 'log', level: 'warn', message: `[Bundle Scanner] 🚨 ${pattern.name} encontrado em ${source}` });
      }
    }
  }
}

function isFalsePositive(match, pattern) {
  // Extremely short matches
  if (match.length < 10 && !pattern.name.includes('AKIA')) return true;

  // Common test/example values
  if (match.includes('example') || match.includes('placeholder') || match.includes('YOUR_')) return true;
  if (match.includes('xxxx') || match.includes('0000')) return true;

  // Stripe publishable keys in frontend are expected
  if (pattern.name === 'Stripe Publishable') return false; // Keep but low severity

  return false;
}

function extractAllScriptUrls(html, baseUrl) {
  const urls = [];
  const regex = /<script[^>]*src=["']([^"']+)["']/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    let src = match[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;
    urls.push(src);
  }

  // Also check for dynamic imports
  const importRegex = /import\s*\(\s*["']([^"']+\.js[^"']*)["']\s*\)/g;
  while ((match = importRegex.exec(html)) !== null) {
    let src = match[1];
    if (src.startsWith('/')) src = baseUrl + src;
    urls.push(src);
  }

  return [...new Set(urls)];
}

module.exports = { deepBundleKeyScanner };
