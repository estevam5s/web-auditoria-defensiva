/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Sensitive Data Detector
    Scans API responses, HTML, JS bundles for PII, credentials,
    tokens, financial data, health records indicators, and more
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// PIl / Sensitive patterns
const SENSITIVE_PATTERNS = [
  { name: 'CPF (Brasil)',        regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g,              severity: 'critical', category: 'PII' },
  { name: 'CNPJ (Brasil)',       regex: /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g,       severity: 'critical', category: 'PII' },
  { name: 'RG (Brasil)',         regex: /\b\d{2}\.\d{3}\.\d{3}-[\dxX]\b/g,              severity: 'high',     category: 'PII' },
  { name: 'SSN (USA)',           regex: /\b\d{3}-\d{2}-\d{4}\b/g,                       severity: 'critical', category: 'PII' },
  { name: 'Credit Card Visa',   regex: /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: 'critical', category: 'Financial' },
  { name: 'Credit Card MC',     regex: /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, severity: 'critical', category: 'Financial' },
  { name: 'Email Address',      regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g, severity: 'medium', category: 'PII' },
  { name: 'Phone BR',           regex: /\b(?:\+55\s?)?(?:\(?\d{2}\)?\s?)?(?:9\s?)?\d{4}[\s-]?\d{4}\b/g, severity: 'medium', category: 'PII' },
  { name: 'Phone International',regex: /\b\+\d{1,3}[\s-]?\(?\d{1,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b/g, severity: 'medium', category: 'PII' },
  { name: 'IPv4 Address',       regex: /\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g, severity: 'low', category: 'Infrastructure' },
  { name: 'Private IP',         regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g, severity: 'high', category: 'Infrastructure' },
  { name: 'AWS ARN',            regex: /arn:aws:[a-zA-Z0-9-]+:[a-zA-Z0-9-]*:\d{12}:[^\s"']+/g, severity: 'high', category: 'Cloud' },
  { name: 'Database URL',       regex: /(?:postgres|mysql|mongodb|redis):\/\/[^\s"'<>]+/gi, severity: 'critical', category: 'Credentials' },
  { name: 'API Key Generic',    regex: /(?:api[_-]?key|apikey|api_secret|api_token)\s*[=:]\s*["']?[A-Za-z0-9_\-]{16,}["']?/gi, severity: 'high', category: 'Credentials' },
  { name: 'JWT Token',          regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+/g, severity: 'high', category: 'Credentials' },
  { name: 'Bearer Token',       regex: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, severity: 'high', category: 'Credentials' },
  { name: 'Password in URL',    regex: /(?:password|passwd|pwd|pass)\s*[=:]\s*["']?[^\s"'&<>]{3,}["']?/gi, severity: 'critical', category: 'Credentials' },
  { name: 'Base64 Long',        regex: /[A-Za-z0-9+\/]{40,}={0,2}/g, severity: 'low', category: 'Encoded' },
  { name: 'Google Maps Key',    regex: /AIza[A-Za-z0-9_\-]{35}/g, severity: 'medium', category: 'API Key' },
  { name: 'Stripe Key',         regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}/g, severity: 'critical', category: 'Financial API' },
  { name: 'Webhook URL',        regex: /https?:\/\/[^\s"']*(?:webhook|hook|callback|notify)[^\s"']*/gi, severity: 'medium', category: 'Infrastructure' },
  { name: 'Internal URL',       regex: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|internal|staging|dev\.)[\w:\/.-]*/gi, severity: 'high', category: 'Infrastructure' },
];

// Supabase REST endpoints to scan for data exposure
const SUPABASE_DATA_ENDPOINTS = [
  '/rest/v1/',
  '/rest/v1/users',
  '/rest/v1/profiles',
  '/rest/v1/accounts',
  '/rest/v1/customers',
  '/rest/v1/orders',
  '/rest/v1/payments',
  '/rest/v1/transactions',
  '/rest/v1/auth.users',
  '/rest/v1/logs',
  '/rest/v1/events',
  '/rest/v1/sessions',
  '/rest/v1/messages',
  '/rest/v1/notifications',
  '/rest/v1/documents',
  '/rest/v1/files',
  '/rest/v1/settings',
  '/rest/v1/config',
  '/rest/v1/permissions',
  '/rest/v1/roles',
];

// Fields that should never be publicly exposed
const SENSITIVE_FIELDS = [
  'password', 'passwd', 'pwd', 'hash', 'salt', 'secret',
  'ssn', 'cpf', 'cnpj', 'rg', 'social_security',
  'credit_card', 'card_number', 'cvv', 'cvc', 'expiry',
  'bank_account', 'routing_number', 'account_number',
  'api_key', 'api_secret', 'access_token', 'refresh_token',
  'private_key', 'encryption_key', 'master_key',
  'phone', 'telefone', 'celular', 'mobile',
  'address', 'endereco', 'cep', 'zipcode',
  'date_of_birth', 'dob', 'nascimento', 'birthday',
  'salary', 'salario', 'income', 'renda',
  'medical', 'health', 'diagnosis', 'prescription',
  'ip_address', 'user_agent', 'device_id',
];

async function deepSensitiveDataDetector(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);
  const findings = [];

  emit({ type: 'log', level: 'info', message: `[Sensitive Data] Iniciando detecção de dados sensíveis...` });

  // ═══════════ 1. Scan Main Page & JS Bundles ═══════════
  emit({ type: 'log', level: 'info', message: `[Sensitive Data] Escaneando página principal e bundles JS...` });
  
  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  if (mainPage.ok && mainPage.text) {
    // Scan main page
    scanContent(mainPage.text, baseUrl, findings);
    
    // Extract and scan JS bundles
    const scripts = extractScriptUrls(mainPage.text, baseUrl);
    emit({ type: 'log', level: 'info', message: `[Sensitive Data] ${scripts.length} scripts encontrados para análise...` });
    
    const BATCH_SIZE = 5;
    let scanned = 0;
    for (let i = 0; i < scripts.length && i < 50; i += BATCH_SIZE) {
      const batch = scripts.slice(i, i + BATCH_SIZE);
      const fetches = batch.map(url => safeFetch(url, { timeout: 8000 }));
      const responses = await Promise.all(fetches);
      
      for (let j = 0; j < responses.length; j++) {
        scanned++;
        if (responses[j].ok && responses[j].text) {
          scanContent(responses[j].text, batch[j], findings);
        }
      }
      
      if (scanned % 10 === 0) {
        emit({ type: 'log', level: 'info', message: `[Sensitive Data] ${scanned}/${scripts.length} assets escaneados...` });
      }
    }
  }

  // ═══════════ 2. Scan Supabase API Responses ═══════════
  if (config.anonKey) {
    emit({ type: 'log', level: 'info', message: `[Sensitive Data] Escaneando respostas da API Supabase...` });
    
    for (const endpoint of SUPABASE_DATA_ENDPOINTS) {
      const url = baseUrl + endpoint + '?select=*&limit=5';
      const res = await safeFetch(url, {
        headers: { ...headers, 'Accept': 'application/json', 'Range': '0-4' },
        timeout: 8000
      });
      
      if (res.ok && res.json) {
        const data = Array.isArray(res.json) ? res.json : [res.json];
        
        if (data.length > 0) {
          emit({ type: 'log', level: 'warn', message: `[Sensitive Data] Tabela acessível: ${endpoint} (${data.length} registros)` });
          
          // Check for sensitive field names
          const fields = Object.keys(data[0] || {});
          const exposedSensitive = fields.filter(f => 
            SENSITIVE_FIELDS.some(sf => f.toLowerCase().includes(sf))
          );
          
          if (exposedSensitive.length > 0) {
            findings.push({
              type: 'Exposed Sensitive Fields',
              source: endpoint,
              severity: 'critical',
              matches: exposedSensitive,
              sampleRecord: sanitizeRecord(data[0]),
              recordCount: data.length,
              note: 'Campos sensíveis expostos via API REST sem RLS adequado'
            });
          }
          
          // Scan field values for PII
          for (const record of data) {
            const jsonStr = JSON.stringify(record);
            scanContent(jsonStr, endpoint, findings);
          }
        }
      }
    }

    // ═══════════ 3. Scan Auth Endpoints ═══════════
    emit({ type: 'log', level: 'info', message: `[Sensitive Data] Verificando endpoints de autenticação...` });
    
    const authEndpoints = [
      '/auth/v1/settings',
      '/auth/v1/admin/users',
      '/auth/v1/admin/audit',
    ];
    
    for (const ep of authEndpoints) {
      const res = await safeFetch(baseUrl + ep, { headers, timeout: 5000 });
      if (res.ok && res.text) {
        scanContent(res.text, ep, findings);
        
        if (ep.includes('admin')) {
          findings.push({
            type: 'Admin Endpoint Exposed',
            source: ep,
            severity: 'critical',
            note: 'Endpoint administrativo acessível com anon key!'
          });
        }
      }
    }
  }

  // ═══════════ 4. Scan Storage Buckets ═══════════
  emit({ type: 'log', level: 'info', message: `[Sensitive Data] Verificando storage buckets...` });
  
  if (config.anonKey) {
    const bucketsRes = await safeFetch(baseUrl + '/storage/v1/bucket', { headers, timeout: 8000 });
    if (bucketsRes.ok && bucketsRes.json) {
      const buckets = Array.isArray(bucketsRes.json) ? bucketsRes.json : [];
      
      for (const bucket of buckets) {
        if (bucket.public) {
          const files = await safeFetch(
            `${baseUrl}/storage/v1/object/list/${bucket.name}?limit=20`,
            { headers, timeout: 8000 }
          );
          
          if (files.ok && files.json) {
            const fileList = Array.isArray(files.json) ? files.json : [];
            const sensitiveFiles = fileList.filter(f => {
              const name = (f.name || '').toLowerCase();
              return name.match(/\.(pdf|doc|docx|xls|xlsx|csv|sql|bak|env|key|pem|pfx|p12)/);
            });
            
            if (sensitiveFiles.length > 0) {
              findings.push({
                type: 'Sensitive Files in Public Bucket',
                source: `storage/${bucket.name}`,
                severity: 'critical',
                matches: sensitiveFiles.map(f => f.name),
                note: `${sensitiveFiles.length} arquivo(s) potencialmente sensível(is) em bucket público`
              });
            }
          }
        }
      }
    }
  }

  // ═══════════ 5. Check robots.txt for sensitive paths ═══════════
  emit({ type: 'log', level: 'info', message: `[Sensitive Data] Analisando robots.txt...` });
  
  const robots = await safeFetch(baseUrl + '/robots.txt', { timeout: 5000 });
  if (robots.ok && robots.text) {
    const disallowed = robots.text.match(/Disallow:\s*([^\s]+)/gi) || [];
    const sensitiveDisallowed = disallowed
      .map(d => d.replace(/Disallow:\s*/i, '').trim())
      .filter(p => p.match(/admin|secret|private|internal|backup|config|api|dashboard|panel|debug/i));
    
    if (sensitiveDisallowed.length > 0) {
      findings.push({
        type: 'Sensitive Paths in robots.txt',
        source: '/robots.txt',
        severity: 'medium',
        matches: sensitiveDisallowed,
        note: 'robots.txt revela caminhos sensíveis (pode guiar atacantes)'
      });
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[Sensitive Data] Análise concluída. ${findings.length} achado(s).` });

  // Group by severity
  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const highFindings = findings.filter(f => f.severity === 'high');
  const mediumFindings = findings.filter(f => f.severity === 'medium');
  const lowFindings = findings.filter(f => f.severity === 'low');

  if (criticalFindings.length > 0) {
    results.push({
      check: 'Sensitive Data — Critical Exposures',
      status: 'FAIL',
      severity: 'critical',
      message: `${criticalFindings.length} exposição(ões) CRÍTICA(S) de dados sensíveis!`,
      details: {
        findings: criticalFindings.slice(0, 20),
        recommendation: 'URGENTE: Remova dados sensíveis do frontend, implemente RLS e reveja permissões.'
      }
    });
  }

  if (highFindings.length > 0) {
    results.push({
      check: 'Sensitive Data — High Risk Exposures',
      status: 'FAIL',
      severity: 'high',
      message: `${highFindings.length} exposição(ões) de alto risco.`,
      details: { findings: highFindings.slice(0, 15) }
    });
  }

  if (mediumFindings.length > 0) {
    results.push({
      check: 'Sensitive Data — Medium Risk',
      status: 'WARN',
      severity: 'medium',
      message: `${mediumFindings.length} achado(s) de risco médio.`,
      details: { findings: mediumFindings.slice(0, 10) }
    });
  }

  if (findings.length === 0) {
    results.push({
      check: 'Sensitive Data — Overall',
      status: 'PASS',
      severity: 'info',
      message: 'Nenhum dado sensível exposto detectado.',
      details: { note: 'Scan cobriu HTML, JS bundles, API REST, Storage e robots.txt.' }
    });
  } else {
    results.push({
      check: 'Sensitive Data — Summary',
      status: 'INFO',
      severity: 'info',
      message: `Total: ${findings.length} achado(s) — ${criticalFindings.length} críticos, ${highFindings.length} altos, ${mediumFindings.length} médios, ${lowFindings.length} baixos.`,
      details: {
        total: findings.length,
        bySeverity: { critical: criticalFindings.length, high: highFindings.length, medium: mediumFindings.length, low: lowFindings.length },
        byCategory: groupByCategory(findings)
      }
    });
  }

  return results;
}

function scanContent(content, source, findings) {
  if (!content || content.length < 10) return;
  
  // Limit scan size for performance
  const text = content.substring(0, 500000);
  
  for (const pattern of SENSITIVE_PATTERNS) {
    const matches = text.match(pattern.regex);
    if (matches && matches.length > 0) {
      // Deduplicate
      const unique = [...new Set(matches)];
      
      // Filter false positives
      const filtered = unique.filter(m => !isFalsePositive(m, pattern.name));
      
      if (filtered.length > 0) {
        findings.push({
          type: pattern.name,
          source: source.length > 200 ? source.substring(0, 200) + '...' : source,
          severity: pattern.severity,
          category: pattern.category,
          count: filtered.length,
          samples: filtered.slice(0, 3).map(m => maskSensitive(m)),
        });
      }
    }
  }
}

function isFalsePositive(match, patternName) {
  // Common false positive filters
  if (patternName === 'Email Address') {
    // Filter out common non-PII emails
    if (match.match(/@(example\.com|test\.com|placeholder|localhost|email\.com|domain\.com)$/i)) return true;
    if (match.match(/^(noreply|no-reply|admin|info|support|hello|contact|help)@/i)) return true;
  }
  
  if (patternName === 'IPv4 Address') {
    // Filter out common non-sensitive IPs
    if (match === '0.0.0.0' || match === '255.255.255.255' || match.startsWith('127.')) return true;
  }
  
  if (patternName === 'Base64 Long') {
    // Filter out common CSS/hash values
    if (match.match(/^[A-Fa-f0-9]+$/)) return true; // Pure hex
  }
  
  if (patternName === 'Phone BR' || patternName === 'Phone International') {
    // Very short numbers are likely false positives
    if (match.replace(/\D/g, '').length < 8) return true;
  }
  
  return false;
}

function maskSensitive(value) {
  if (!value || value.length < 6) return '***';
  const len = value.length;
  if (len <= 10) return value.substring(0, 2) + '*'.repeat(len - 4) + value.substring(len - 2);
  return value.substring(0, 4) + '*'.repeat(Math.min(len - 8, 20)) + value.substring(len - 4);
}

function sanitizeRecord(record) {
  const sanitized = {};
  for (const [key, value] of Object.entries(record || {})) {
    if (typeof value === 'string' && value.length > 4) {
      sanitized[key] = maskSensitive(value);
    } else {
      sanitized[key] = typeof value;
    }
  }
  return sanitized;
}

function extractScriptUrls(html, baseUrl) {
  const urls = [];
  const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
  let match;
  
  while ((match = scriptRegex.exec(html)) !== null) {
    let src = match[1];
    if (src.startsWith('//')) src = 'https:' + src;
    else if (src.startsWith('/')) src = baseUrl + src;
    else if (!src.startsWith('http')) src = baseUrl + '/' + src;
    urls.push(src);
  }
  
  // Also check for CSS files (can leak via @import or background images)
  const cssRegex = /<link[^>]*href=["']([^"']+\.css[^"']*)["'][^>]*>/gi;
  while ((match = cssRegex.exec(html)) !== null) {
    let href = match[1];
    if (href.startsWith('//')) href = 'https:' + href;
    else if (href.startsWith('/')) href = baseUrl + href;
    else if (!href.startsWith('http')) href = baseUrl + '/' + href;
    urls.push(href);
  }
  
  return urls;
}

function groupByCategory(findings) {
  const groups = {};
  for (const f of findings) {
    const cat = f.category || f.type || 'Other';
    if (!groups[cat]) groups[cat] = 0;
    groups[cat]++;
  }
  return groups;
}

module.exports = { deepSensitiveDataDetector };
