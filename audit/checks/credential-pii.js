/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Credential & PII Leak Detector
    Scans ALL accessible surfaces for leaked:
    - Payment gateway private credentials
    - Emails, documents (CPF, CNPJ, RG, SSN)
    - API keys and private credentials
    - Financial data (card numbers, bank details)
    - Personal data (phone, address, salary)
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// ── Credential Patterns ──────────────────────────────────────────
const CREDENTIAL_PATTERNS = [
  // Payment Gateways (private keys)
  { name: 'Stripe Secret Key (live)',     regex: /sk_live_[A-Za-z0-9]{20,}/g,              severity: 'critical', category: 'Payment Gateway' },
  { name: 'Stripe Secret Key (test)',     regex: /sk_test_[A-Za-z0-9]{20,}/g,              severity: 'high',     category: 'Payment Gateway' },
  { name: 'Stripe Webhook Secret',        regex: /whsec_[A-Za-z0-9]{20,}/g,                severity: 'critical', category: 'Payment Gateway' },
  { name: 'MercadoPago Access Token',     regex: /(?:APP_USR-|TEST-)\d+-[A-Za-z0-9-]{20,}/g, severity: 'critical', category: 'Payment Gateway' },
  { name: 'MercadoPago Config',           regex: /(?:mp_access_token|mercadopago_token|MERCADO_PAGO_ACCESS_TOKEN)\s*[=:]\s*["']?([^"'\s]{15,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },
  { name: 'PagSeguro Token',              regex: /(?:pagseguro_token|PAGSEGURO_TOKEN)\s*[=:]\s*["']?([^"'\s]{15,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },
  { name: 'PagarMe Key',                  regex: /(?:ak_live_|ak_test_)[A-Za-z0-9]{10,}/g, severity: 'critical', category: 'Payment Gateway' },
  { name: 'Asaas Key',                    regex: /\$aact_[A-Za-z0-9]{20,}/g,              severity: 'critical', category: 'Payment Gateway' },
  { name: 'PayPal Client Secret',         regex: /(?:PAYPAL_SECRET|PAYPAL_CLIENT_SECRET)\s*[=:]\s*["']?([^"'\s]{15,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },
  { name: 'Cielo Merchant Key',           regex: /(?:CIELO_MERCHANT_KEY|cielo_merchant_key)\s*[=:]\s*["']?([^"'\s]{15,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },
  { name: 'Rede eRede Key',              regex: /(?:EREDE_KEY|erede_key|erede_pv)\s*[=:]\s*["']?([^"'\s]{10,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },
  { name: 'Getnet Key',                   regex: /(?:GETNET_CLIENT_SECRET|getnet_secret)\s*[=:]\s*["']?([^"'\s]{15,})["']?/gi, severity: 'critical', category: 'Payment Gateway' },

  // Other API Credentials
  { name: 'OpenAI Key',                   regex: /sk-(?:proj-)?[A-Za-z0-9_\-]{20,}/g,     severity: 'critical', category: 'API Key' },
  { name: 'AWS Access Key',               regex: /AKIA[0-9A-Z]{16}/g,                      severity: 'critical', category: 'API Key' },
  { name: 'SendGrid Key',                 regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/g, severity: 'critical', category: 'API Key' },
  { name: 'Twilio Auth',                  regex: /(?:TWILIO_AUTH_TOKEN)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi, severity: 'critical', category: 'API Key' },
  { name: 'GitHub Token',                 regex: /gh[ps]_[A-Za-z0-9]{36,}/g,               severity: 'critical', category: 'API Key' },
  { name: 'Supabase Service Role',        regex: /(?:SUPABASE_SERVICE_ROLE_KEY|service_role)\s*[=:]\s*["']?(eyJ[^"'\s]{50,})["']?/gi, severity: 'critical', category: 'Supabase' },
  { name: 'Database URL',                 regex: /(?:postgres|mysql|mongodb):\/\/[^\s"'<>]+/gi, severity: 'critical', category: 'Database' },
  { name: 'Redis URL',                    regex: /rediss?:\/\/[^\s"'<>]+/gi,               severity: 'critical', category: 'Database' },

  // Generic
  { name: 'Private Key (RSA/PEM)',        regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,   severity: 'critical', category: 'Crypto' },
  { name: 'Password in text',            regex: /(?:password|passwd|pwd|senha)\s*[=:]\s*["']([^"']{3,50})["']/gi, severity: 'critical', category: 'Credential' },
  { name: 'bcrypt hash',                  regex: /\$2[ayb]\$\d{2}\$[A-Za-z0-9./]{53}/g,    severity: 'high', category: 'Credential' },
];

// ── PII Patterns ─────────────────────────────────────────────────
const PII_PATTERNS = [
  { name: 'CPF',                 regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,              severity: 'critical', category: 'Documento' },
  { name: 'CPF (sem formato)',   regex: /(?<!\d)\d{11}(?!\d)/g,                          severity: 'medium',   category: 'Documento', validate: validateCPF },
  { name: 'CNPJ',               regex: /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g,       severity: 'critical', category: 'Documento' },
  { name: 'RG',                 regex: /\b\d{2}\.\d{3}\.\d{3}-[\dxX]\b/g,              severity: 'high',     category: 'Documento' },
  { name: 'SSN (USA)',          regex: /\b\d{3}-\d{2}-\d{4}\b/g,                       severity: 'critical', category: 'Documento' },
  { name: 'Email',              regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, severity: 'high', category: 'PII' },
  { name: 'Phone BR',           regex: /\b(?:\+55\s?)?\(?\d{2}\)?\s?9\d{4}[\s-]?\d{4}\b/g, severity: 'high', category: 'PII' },
  { name: 'Credit Card Visa',   regex: /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: 'critical', category: 'Financeiro' },
  { name: 'Credit Card MC',     regex: /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: 'critical', category: 'Financeiro' },
  { name: 'PIX Key (Phone)',    regex: /\b(?:\+55)?\d{11}\b/g,                         severity: 'medium',   category: 'Financeiro' },
  { name: 'CEP',                regex: /\b\d{5}-?\d{3}\b/g,                            severity: 'medium',   category: 'PII' },
  { name: 'Bank Account BR',    regex: /(?:ag[eê]ncia|conta)\s*:?\s*\d{4,6}[-/]?\d{0,2}/gi, severity: 'high', category: 'Financeiro' },
];

// ── Scan Surfaces ────────────────────────────────────────────────
const REST_TABLES = [
  'users','profiles','accounts','customers','members','admins',
  'orders','payments','transactions','invoices','billing',
  'subscriptions','charges','refunds','wallets','balances',
  'cards','bank_accounts','credit_cards','pix_keys',
  'documents','files','settings','config','secrets','credentials',
  'api_keys','tokens','sessions','logs','audit_logs',
  'addresses','contacts','patients','medical_records',
  'employees','salaries','contracts','messages','notifications',
  'pedidos','pagamentos','clientes','usuarios','configuracoes',
];

async function deepCredentialPIIDetector(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);
  const allFindings = [];

  emit({ type: 'log', level: 'info', message: '[Credential/PII] Iniciando detecção profunda de credenciais e dados pessoais...' });

  // ═══════════ 1. Scan REST API Responses ═══════════
  emit({ type: 'log', level: 'info', message: `[Credential/PII] Escaneando ${REST_TABLES.length} tabelas REST...` });

  const BATCH = 8;
  for (let i = 0; i < REST_TABLES.length; i += BATCH) {
    const batch = REST_TABLES.slice(i, i + BATCH);
    const fetches = batch.map(table =>
      safeFetch(`${baseUrl}/rest/v1/${table}?select=*&limit=10`, { headers, timeout: 6000 })
        .then(res => ({ table, res }))
    );
    const batchResults = await Promise.all(fetches);

    for (const { table, res } of batchResults) {
      if (!res.ok || !Array.isArray(res.json) || res.json.length === 0) continue;

      const jsonStr = JSON.stringify(res.json);

      // Scan for credentials
      for (const pat of CREDENTIAL_PATTERNS) {
        const matches = jsonStr.match(pat.regex);
        if (matches) {
          const unique = [...new Set(matches)].filter(m => !isFP(m, pat.name));
          if (unique.length > 0) {
            allFindings.push({
              type: pat.name,
              category: pat.category,
              severity: pat.severity,
              source: `REST: ${table}`,
              count: unique.length,
              samples: unique.slice(0, 3).map(m => mask(m)),
            });
            emit({ type: 'log', level: 'warn', message: `[Credential/PII] 🚨 ${pat.name} em tabela "${table}" (${unique.length}x)` });
          }
        }
      }

      // Scan for PII
      for (const pat of PII_PATTERNS) {
        const matches = jsonStr.match(pat.regex);
        if (matches) {
          let unique = [...new Set(matches)];
          if (pat.validate) unique = unique.filter(m => pat.validate(m));
          unique = unique.filter(m => !isFP(m, pat.name));
          if (unique.length > 0) {
            allFindings.push({
              type: pat.name,
              category: pat.category,
              severity: pat.severity,
              source: `REST: ${table}`,
              count: unique.length,
              samples: unique.slice(0, 3).map(m => mask(m)),
            });
            emit({ type: 'log', level: 'warn', message: `[Credential/PII] ⚠ ${pat.name} em tabela "${table}" (${unique.length}x)` });
          }
        }
      }
    }

    if (i % 24 === 0 && i > 0) {
      emit({ type: 'log', level: 'info', message: `[Credential/PII] ${Math.min(i + BATCH, REST_TABLES.length)}/${REST_TABLES.length} tabelas...` });
    }
  }

  // ═══════════ 2. Scan Public JS Bundles ═══════════
  emit({ type: 'log', level: 'info', message: '[Credential/PII] Escaneando bundles JavaScript...' });

  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  if (mainPage.ok && mainPage.text) {
    scanText(mainPage.text, 'Homepage HTML', allFindings, emit);

    const jsUrls = extractScripts(mainPage.text, baseUrl);
    emit({ type: 'log', level: 'info', message: `[Credential/PII] ${jsUrls.length} scripts para análise...` });

    for (let i = 0; i < jsUrls.length && i < 40; i += BATCH) {
      const batch = jsUrls.slice(i, i + BATCH);
      const fetches = batch.map(url => safeFetch(url, { timeout: 8000 }).then(res => ({ url, res })));
      const responses = await Promise.all(fetches);

      for (const { url, res } of responses) {
        if (res.ok && res.text) {
          const shortUrl = url.replace(baseUrl, '');
          scanText(res.text, `Bundle: ${shortUrl}`, allFindings, emit);
        }
      }
    }
  }

  // ═══════════ 3. Scan Auth Endpoints ═══════════
  emit({ type: 'log', level: 'info', message: '[Credential/PII] Verificando endpoints de auth...' });

  const authEps = [
    '/auth/v1/settings',
    '/auth/v1/admin/users',
    '/auth/v1/admin/audit',
  ];

  for (const ep of authEps) {
    const res = await safeFetch(baseUrl + ep, { headers, timeout: 5000 });
    if (res.ok && res.text) {
      if (ep.includes('admin/users') && Array.isArray(res.json)) {
        allFindings.push({
          type: 'Admin Users Endpoint',
          category: 'Auth',
          severity: 'critical',
          source: ep,
          count: Array.isArray(res.json) ? res.json.length : 1,
          samples: ['Endpoint administrativo acessível'],
        });
        emit({ type: 'log', level: 'warn', message: `[Credential/PII] 🚨 ${ep} acessível com anon key!` });
      }
      scanText(res.text, `Auth: ${ep}`, allFindings, emit);
    }
  }

  // ═══════════ 4. Scan Storage Public Files ═══════════
  if (config.anonKey) {
    emit({ type: 'log', level: 'info', message: '[Credential/PII] Verificando arquivos de storage...' });

    const bucketsRes = await safeFetch(`${baseUrl}/storage/v1/bucket`, { headers, timeout: 8000 });
    if (bucketsRes.ok && Array.isArray(bucketsRes.json)) {
      for (const bucket of bucketsRes.json.filter(b => b.public)) {
        const files = await safeFetch(`${baseUrl}/storage/v1/object/list/${bucket.name}`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefix: '', limit: 20 }),
          timeout: 8000,
        });

        if (files.ok && Array.isArray(files.json)) {
          // Check text-based files for secrets
          const textFiles = files.json.filter(f => {
            const name = (f.name || '').toLowerCase();
            return name.match(/\.(json|js|txt|csv|env|log|xml|yaml|yml|html|htm|md|conf|cfg|toml|ini|sql)$/);
          });

          for (const tf of textFiles.slice(0, 10)) {
            const fileUrl = `${baseUrl}/storage/v1/object/public/${bucket.name}/${tf.name}`;
            const fileRes = await safeFetch(fileUrl, { timeout: 8000 });
            if (fileRes.ok && fileRes.text) {
              scanText(fileRes.text, `Storage: ${bucket.name}/${tf.name}`, allFindings, emit);
            }
          }
        }
      }
    }
  }

  // ═══════════ 5. Scan RPC Responses ═══════════
  emit({ type: 'log', level: 'info', message: '[Credential/PII] Testando RPCs sensíveis...' });

  const rpcNames = ['get_users', 'get_config', 'get_secrets', 'get_payments', 'get_credentials', 'export_data', 'search', 'get_all'];
  for (const fn of rpcNames) {
    const res = await safeFetch(`${baseUrl}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      timeout: 5000,
    });
    if (res.ok && res.text && res.text.length > 10) {
      scanText(res.text, `RPC: ${fn}`, allFindings, emit);
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[Credential/PII] Total: ${allFindings.length} achados. Compilando...` });

  // Deduplicate
  const deduped = deduplicateFindings(allFindings);

  // Group
  const byCategory = {};
  for (const f of deduped) {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category].push(f);
  }

  // Payment gateway credentials
  const pgCreds = byCategory['Payment Gateway'] || [];
  if (pgCreds.length > 0) {
    results.push({
      check: 'Credenciais — Gateway de Pagamento',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${pgCreds.length} credencial(is) PRIVADA(S) de gateway de pagamento detectada(s)! (Stripe, MercadoPago, PagSeguro, etc.)`,
      details: {
        findings: pgCreds,
        recommendation: 'URGENTE: Rotacione TODAS as chaves. Chaves privadas de pagamento nunca devem ser expostas no frontend ou API pública.'
      }
    });
  }

  // Documents (CPF, CNPJ, SSN)
  const docs = byCategory['Documento'] || [];
  if (docs.length > 0) {
    results.push({
      check: 'Dados — Documentos Pessoais (CPF/CNPJ/RG)',
      status: 'FAIL',
      severity: 'critical',
      message: `${docs.length} tipo(s) de documento pessoal encontrado(s) expostos (CPF, CNPJ, RG, SSN)!`,
      details: {
        findings: docs,
        recommendation: 'Dados de documentos são protegidos pela LGPD/GDPR. Configure RLS e mascaramento.'
      }
    });
  }

  // Financial
  const financial = byCategory['Financeiro'] || [];
  if (financial.length > 0) {
    results.push({
      check: 'Dados — Informações Financeiras',
      status: 'FAIL',
      severity: 'critical',
      message: `💰 ${financial.length} tipo(s) de dado financeiro exposto(s) (cartão de crédito, conta bancária, PIX)!`,
      details: {
        findings: financial,
        recommendation: 'Dados financeiros são PCI-DSS regulados. Nunca exponha números de cartão ou contas.'
      }
    });
  }

  // PII (emails, phones)
  const pii = byCategory['PII'] || [];
  if (pii.length > 0) {
    results.push({
      check: 'Dados — PII (Email, Telefone, Endereço)',
      status: 'FAIL',
      severity: 'high',
      message: `${pii.length} tipo(s) de dado pessoal exposto(s) (emails, telefones, CEPs).`,
      details: {
        findings: pii,
        recommendation: 'Proteja dados pessoais conforme LGPD. Configure RLS para limitar acesso.'
      }
    });
  }

  // API Keys
  const apiKeys = byCategory['API Key'] || [];
  if (apiKeys.length > 0) {
    results.push({
      check: 'Credenciais — API Keys Expostas',
      status: 'FAIL',
      severity: 'critical',
      message: `${apiKeys.length} API key(s) de terceiros encontrada(s) (AWS, OpenAI, SendGrid, GitHub, etc.)`,
      details: {
        findings: apiKeys,
        recommendation: 'Rotacione todas as API keys expostas. Use variáveis de ambiente no servidor.'
      }
    });
  }

  // Database
  const db = byCategory['Database'] || [];
  if (db.length > 0) {
    results.push({
      check: 'Credenciais — URLs de Database',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${db.length} connection string(s) de banco de dados exposta(s)!`,
      details: { findings: db, recommendation: 'URGENTE: Mude a senha do banco imediatamente.' }
    });
  }

  // Supabase
  const supa = byCategory['Supabase'] || [];
  if (supa.length > 0) {
    results.push({
      check: 'Credenciais — Supabase Service Key',
      status: 'FAIL',
      severity: 'critical',
      message: `${supa.length} credencial(is) Supabase sensível(is) exposta(s)!`,
      details: { findings: supa, recommendation: 'Rotacione no Dashboard: Settings > API > Regenerate service_role key.' }
    });
  }

  // Auth
  const auth = byCategory['Auth'] || [];
  if (auth.length > 0) {
    results.push({
      check: 'Credenciais — Auth Admin Exposto',
      status: 'FAIL',
      severity: 'critical',
      message: `${auth.length} endpoint(s) administrativo(s) de auth acessível(is) sem permissão.`,
      details: { findings: auth }
    });
  }

  // All clean
  if (deduped.length === 0) {
    results.push({
      check: 'Credential/PII — Análise Completa',
      status: 'PASS',
      severity: 'info',
      message: `✓ Nenhuma credencial ou dado pessoal detectado. ${REST_TABLES.length} tabelas, bundles e endpoints analisados.`,
      details: { surfacesScanned: REST_TABLES.length + 50 }
    });
  } else {
    results.push({
      check: 'Credential/PII — Resumo',
      status: 'INFO',
      severity: 'info',
      message: `Total: ${deduped.length} achados. ${Object.entries(byCategory).map(([k,v]) => `${k}: ${v.length}`).join(' | ')}`,
      details: { total: deduped.length, byCategory: Object.fromEntries(Object.entries(byCategory).map(([k,v]) => [k, v.length])) }
    });
  }

  return results;
}

function scanText(text, source, findings, emit) {
  const content = text.substring(0, 500000);

  for (const pat of [...CREDENTIAL_PATTERNS, ...PII_PATTERNS]) {
    const matches = content.match(pat.regex);
    if (!matches) continue;

    let unique = [...new Set(matches)];
    if (pat.validate) unique = unique.filter(m => pat.validate(m));
    unique = unique.filter(m => !isFP(m, pat.name));

    if (unique.length > 0) {
      findings.push({
        type: pat.name,
        category: pat.category,
        severity: pat.severity,
        source,
        count: unique.length,
        samples: unique.slice(0, 3).map(m => mask(m)),
      });

      if (pat.severity === 'critical') {
        emit({ type: 'log', level: 'warn', message: `[Credential/PII] 🚨 ${pat.name} em ${source}` });
      }
    }
  }
}

function mask(value) {
  if (!value || value.length < 6) return '***';
  if (value.length <= 12) return value.substring(0, 3) + '***' + value.substring(value.length - 2);
  return value.substring(0, 5) + '***...' + value.substring(value.length - 4);
}

function isFP(match, name) {
  if (name === 'Email') {
    if (match.match(/@(example|test|placeholder|localhost|email|domain|sentry)\./i)) return true;
    if (match.match(/^(noreply|no-reply|admin|info|support|hello)@/i)) return true;
  }
  if (name === 'CEP') {
    if (match === '00000-000' || match === '00000000') return true;
  }
  if (match.includes('example') || match.includes('YOUR_') || match.includes('xxxx')) return true;
  return false;
}

function validateCPF(cpf) {
  const digits = cpf.replace(/\D/g, '');
  if (digits.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(digits)) return false; // all same digit

  let sum = 0;
  for (let i = 0; i < 9; i++) sum += parseInt(digits[i]) * (10 - i);
  let check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  if (parseInt(digits[9]) !== check) return false;

  sum = 0;
  for (let i = 0; i < 10; i++) sum += parseInt(digits[i]) * (11 - i);
  check = 11 - (sum % 11);
  if (check >= 10) check = 0;
  return parseInt(digits[10]) === check;
}

function deduplicateFindings(findings) {
  const seen = new Set();
  return findings.filter(f => {
    const key = `${f.type}:${f.source}:${(f.samples || []).join(',')}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function extractScripts(html, baseUrl) {
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
  return [...new Set(urls)];
}

module.exports = { deepCredentialPIIDetector };
