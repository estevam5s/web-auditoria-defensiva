/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Source Code Analyzer
    Crawls all reachable JS/HTML/CSS/JSON assets and analyzes them
    for sensitive data, hardcoded secrets, insecure patterns, and errors
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch } = require('../helpers/http');

// Regex patterns for secret detection in source code
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'AWS Secret Key', pattern: /(?:aws_secret_access_key|AWS_SECRET)\s*[=:]\s*["']?([A-Za-z0-9\/+=]{40})["']?/gi, severity: 'critical' },
  { name: 'Supabase Service Role Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]+/g, severity: 'critical', validate: (match) => {
    try { const p = JSON.parse(Buffer.from(match.split('.')[1], 'base64').toString()); return p.role === 'service_role'; } catch { return false; }
  }},
  { name: 'Generic API Key', pattern: /(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["']([a-zA-Z0-9_\-]{20,})["']/gi, severity: 'high' },
  { name: 'Private Key (PEM)', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, severity: 'critical' },
  { name: 'Database URL', pattern: /(?:postgres|mysql|mongodb|redis):\/\/[^\s"'<>]{10,}/gi, severity: 'critical' },
  { name: 'Stripe Secret Key', pattern: /sk_live_[a-zA-Z0-9]{24,}/g, severity: 'critical' },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[a-zA-Z0-9]{24,}/g, severity: 'medium' },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48,}/g, severity: 'critical' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'Slack Token', pattern: /xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+/g, severity: 'critical' },
  { name: 'Firebase Key', pattern: /AIza[0-9A-Za-z\\-_]{35}/g, severity: 'high' },
  { name: 'Twilio SID', pattern: /AC[a-f0-9]{32}/g, severity: 'high' },
  { name: 'SendGrid API Key', pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g, severity: 'critical' },
  { name: 'Mailgun API Key', pattern: /key-[a-f0-9]{32}/g, severity: 'critical' },
  { name: 'JWT Secret Hardcoded', pattern: /(?:jwt[_-]?secret|JWT_SECRET)\s*[=:]\s*["']([^"']{8,})["']/gi, severity: 'critical' },
  { name: 'Password Hardcoded', pattern: /(?:password|passwd|pwd|senha)\s*[=:]\s*["']([^"']{4,})["']/gi, severity: 'high' },
  { name: 'Bearer Token', pattern: /Bearer\s+[A-Za-z0-9_\-\.]{20,}/g, severity: 'high' },
  { name: 'Basic Auth', pattern: /Basic\s+[A-Za-z0-9+\/=]{10,}/g, severity: 'high' },
  { name: 'Hardcoded IP', pattern: /(?:https?:\/\/)?(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?/g, severity: 'medium' },
  { name: 'Email Address', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'low' },
  { name: 'Phone Number', pattern: /(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,5}[-.\s]?\d{4}/g, severity: 'low' },
  { name: 'Credit Card Number', pattern: /(?:\d{4}[-\s]?){3}\d{4}/g, severity: 'critical' },
  { name: 'Social Security / CPF', pattern: /\d{3}[\s.-]\d{3}[\s.-]\d{3}[\s.-]\d{2}/g, severity: 'critical' },
  { name: 'Encryption Key Hex', pattern: /(?:encryption[_-]?key|aes[_-]?key|secret[_-]?key)\s*[=:]\s*["']([a-fA-F0-9]{32,})["']/gi, severity: 'critical' },
];

// Insecure code patterns
const INSECURE_PATTERNS = [
  { name: 'eval() Usage', pattern: /\beval\s*\(/g, severity: 'high', recommendation: 'eval() pode executar código arbitrário. Substitua por alternativas seguras.' },
  { name: 'innerHTML Assignment', pattern: /\.innerHTML\s*=/g, severity: 'medium', recommendation: 'innerHTML pode causar XSS. Use textContent ou sanitização.' },
  { name: 'document.write', pattern: /document\.write\s*\(/g, severity: 'medium', recommendation: 'document.write pode ser explorado para XSS.' },
  { name: 'Insecure HTTP URL', pattern: /["']http:\/\/(?!localhost)/g, severity: 'medium', recommendation: 'Use HTTPS para todas as comunicações externas.' },
  { name: 'Console.log in Production', pattern: /console\.(log|debug|info)\s*\(/g, severity: 'low', recommendation: 'Remova console.log do código de produção para evitar vazamento de informações.' },
  { name: 'localStorage Sensitive Data', pattern: /localStorage\.(setItem|getItem)\s*\(\s*["'](?:token|password|secret|key|auth)/gi, severity: 'high', recommendation: 'Evite armazenar dados sensíveis em localStorage. Use httpOnly cookies.' },
  { name: 'Disabled SSL Verification', pattern: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0/g, severity: 'critical', recommendation: 'Nunca desabilite verificação SSL em produção.' },
  { name: 'SQL Injection Risk', pattern: /(?:query|execute)\s*\(\s*[`"'].*\$\{|(?:query|execute)\s*\(\s*.*\+\s*(?:req\.|params\.|body\.)/g, severity: 'critical', recommendation: 'Use prepared statements / parameterized queries.' },
  { name: 'Dangerously Set Inner HTML (React)', pattern: /dangerouslySetInnerHTML/g, severity: 'medium', recommendation: 'dangerouslySetInnerHTML pode causar XSS. Sanitize o HTML antes.' },
  { name: 'CORS Wildcard in Code', pattern: /(?:Access-Control-Allow-Origin|cors.*origin)\s*[=:]\s*["']\*["']/gi, severity: 'high', recommendation: 'Não use wildcard (*) em CORS. Defina origens específicas.' },
  { name: 'Weak Crypto (MD5/SHA1)', pattern: /(?:createHash|crypto\.subtle\.digest)\s*\(\s*["'](?:md5|sha-?1)["']/gi, severity: 'medium', recommendation: 'Use SHA-256 ou superior. MD5 e SHA1 são vulneráveis a colisões.' },
  { name: 'Hardcoded DEBUG Mode', pattern: /(?:DEBUG|debug)\s*[=:]\s*(?:true|1|["']true["'])/g, severity: 'medium', recommendation: 'Desabilite o modo debug em produção.' },
  { name: 'Exposed Source Map', pattern: /\/\/[#@]\s*sourceMappingURL\s*=\s*\S+\.map/g, severity: 'medium', recommendation: 'Source maps expõem código original. Remova em produção.' },
  { name: 'setTimeout/setInterval String', pattern: /(?:setTimeout|setInterval)\s*\(\s*["']/g, severity: 'medium', recommendation: 'setTimeout/setInterval com string é similar a eval. Use funções.' },
  { name: 'Prototype Pollution Risk', pattern: /__proto__|Object\.assign\s*\(\s*\{\}/g, severity: 'high', recommendation: 'Verifique inputs para prevenir prototype pollution.' },
  { name: 'Open Redirect', pattern: /(?:window\.location|location\.href|location\.assign)\s*=\s*(?:req\.|params\.|query\.|\$)/g, severity: 'high', recommendation: 'Valide URLs de redirecionamento para evitar open redirect.' },
  { name: 'Exposed Stack Trace', pattern: /(?:err|error)\.stack|stackTrace|stack_trace/g, severity: 'medium', recommendation: 'Não exponha stack traces para o cliente em produção.' },
];

// Extract linked assets from HTML
function extractAssets(html, baseUrl) {
  const assets = new Set();
  
  // Script tags
  const scriptRegex = /<script[^>]+src=["']([^"']+)["']/gi;
  let match;
  while ((match = scriptRegex.exec(html)) !== null) {
    assets.add(resolveUrl(match[1], baseUrl));
  }

  // Link stylesheet
  const linkRegex = /<link[^>]+href=["']([^"']+\.(?:css|json))["']/gi;
  while ((match = linkRegex.exec(html)) !== null) {
    assets.add(resolveUrl(match[1], baseUrl));
  }

  // Inline script analysis (source mapping URLs, imports)
  const mapRegex = /sourceMappingURL=([^\s*]+\.map)/g;
  while ((match = mapRegex.exec(html)) !== null) {
    assets.add(resolveUrl(match[1], baseUrl));
  }

  // Dynamic imports
  const importRegex = /import\s*\(\s*["']([^"']+)["']\s*\)/g;
  while ((match = importRegex.exec(html)) !== null) {
    assets.add(resolveUrl(match[1], baseUrl));
  }

  return [...assets];
}

function resolveUrl(href, base) {
  try {
    if (href.startsWith('http://') || href.startsWith('https://') || href.startsWith('//')) {
      return href.startsWith('//') ? 'https:' + href : href;
    }
    const url = new URL(href, base);
    return url.href;
  } catch {
    return base + '/' + href.replace(/^\//, '');
  }
}

async function deepSourceCodeAnalysis(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const analyzedUrls = new Set();
  const allFindings = { secrets: [], insecure: [], errors: [] };

  emit({ type: 'log', level: 'info', message: `[Source Analyzer] Buscando página principal: ${baseUrl}` });

  // ─── Phase 1: Fetch main page and discover assets ─────────
  const mainPage = await safeFetch(baseUrl, { timeout: 15000 });
  if (!mainPage.ok) {
    results.push({
      check: 'Source Code — Main Page',
      status: 'ERROR',
      severity: 'info',
      message: `Não foi possível acessar a página principal: ${mainPage.statusText}`,
      details: { url: baseUrl, status: mainPage.status }
    });
    return results;
  }

  analyzedUrls.add(baseUrl);
  
  // Analyze main HTML
  analyzeContent(mainPage.text, baseUrl, 'HTML (main)', allFindings);
  emit({ type: 'log', level: 'info', message: `[Source Analyzer] Página principal: ${mainPage.text.length} bytes analisados` });

  // Extract all linked assets
  const assets = extractAssets(mainPage.text, baseUrl);
  
  // Common additional paths to check
  const extraPaths = [
    '/manifest.json', '/package.json', '/robots.txt', '/sitemap.xml',
    '/.well-known/security.txt', '/humans.txt',
    '/sw.js', '/service-worker.js', '/workbox-*.js',
    '/favicon.ico', '/browserconfig.xml',
    '/_next/data', '/api/health', '/api/status', '/api/version',
    '/graphql', '/api/graphql', '/.env', '/.env.local',
    '/wp-json', '/wp-admin', '/admin', '/dashboard',
    '/static/js/main.js', '/static/js/app.js', '/static/js/vendor.js',
    '/assets/index.js', '/build/bundle.js', '/dist/main.js',
    '/_next/static/chunks/webpack.js', '/_next/static/chunks/main.js',
    '/_next/static/chunks/pages/_app.js', '/_next/static/chunks/pages/index.js',
    '/js/app.js', '/js/main.js', '/js/bundle.js', '/js/vendor.js',
    '/css/app.css', '/css/main.css', '/css/style.css',
  ];

  for (const p of extraPaths) {
    assets.push(baseUrl + p);
  }

  emit({ type: 'log', level: 'info', message: `[Source Analyzer] ${assets.length} assets descobertos para análise` });

  // ─── Phase 2: Fetch and analyze each asset ────────────────
  let analyzed = 0;
  let totalAssets = assets.length;

  // Process in batches up to concurrency=5
  const BATCH_SIZE = 5;
  for (let i = 0; i < assets.length; i += BATCH_SIZE) {
    const batch = assets.slice(i, i + BATCH_SIZE);
    const promises = batch.map(async (url) => {
      if (analyzedUrls.has(url)) return;
      analyzedUrls.add(url);
      
      try {
        const res = await safeFetch(url, { timeout: 8000 });
        if (!res.ok || !res.text || res.text.length === 0) return;
        
        // Skip very large files (> 5MB) and binary/image files
        if (res.text.length > 5 * 1024 * 1024) return;
        const ct = (res.headers?.['content-type'] || '').toLowerCase();
        if (ct.includes('image') || ct.includes('font') || ct.includes('audio') || ct.includes('video')) return;

        const fileType = guessFileType(url, ct);
        analyzeContent(res.text, url, fileType, allFindings);
        analyzed++;

        // Discover more JS chunks from the content
        if (fileType.includes('JS') || fileType.includes('HTML')) {
          const newAssets = extractMoreAssets(res.text, url);
          for (const na of newAssets) {
            if (!analyzedUrls.has(na) && assets.length < 200) {
              assets.push(na);
              totalAssets++;
            }
          }
        }
      } catch {}
    });

    await Promise.all(promises);

    if (analyzed > 0 && analyzed % 10 === 0) {
      emit({ type: 'log', level: 'info', message: `[Source Analyzer] ${analyzed}/${totalAssets} assets analisados...` });
    }
  }

  emit({ type: 'log', level: 'info', message: `[Source Analyzer] Análise completa: ${analyzed} assets processados` });

  // ─── Phase 3: Compile results ─────────────────────────────
  
  // Secrets found
  if (allFindings.secrets.length > 0) {
    const criticals = allFindings.secrets.filter(s => s.severity === 'critical');
    const grouped = groupFindings(allFindings.secrets);

    results.push({
      check: 'Source Code — Secrets Detected',
      status: 'FAIL',
      severity: criticals.length > 0 ? 'critical' : 'high',
      message: `${allFindings.secrets.length} secret(s)/dado(s) sensível(is) encontrado(s) no código fonte! ${criticals.length} crítico(s).`,
      details: {
        totalSecrets: allFindings.secrets.length,
        summary: grouped,
        findings: allFindings.secrets.slice(0, 50).map(s => ({
          type: s.type,
          severity: s.severity,
          source: s.source,
          preview: s.preview,
          line: s.line
        })),
        recommendation: 'URGENTE: Remova e rotacione todas as chaves/segredos expostos no código fonte.'
      }
    });
  } else {
    results.push({
      check: 'Source Code — Secrets',
      status: 'PASS',
      severity: 'info',
      message: `Nenhum segredo hardcoded encontrado em ${analyzed} assets analisados.`,
      details: { assetsAnalyzed: analyzed }
    });
  }

  // Insecure patterns
  if (allFindings.insecure.length > 0) {
    const grouped = groupFindings(allFindings.insecure);

    results.push({
      check: 'Source Code — Insecure Patterns',
      status: 'WARN',
      severity: allFindings.insecure.some(i => i.severity === 'critical') ? 'high' : 'medium',
      message: `${allFindings.insecure.length} padrão(ões) inseguro(s) encontrado(s) no código fonte.`,
      details: {
        totalIssues: allFindings.insecure.length,
        summary: grouped,
        findings: allFindings.insecure.slice(0, 40).map(f => ({
          type: f.type,
          severity: f.severity,
          source: f.source,
          preview: f.preview,
          recommendation: f.recommendation,
          line: f.line
        })),
        recommendation: 'Revise e corrija os padrões inseguros identificados.'
      }
    });
  } else {
    results.push({
      check: 'Source Code — Patterns',
      status: 'PASS',
      severity: 'info',
      message: `Nenhum padrão inseguro detectado em ${analyzed} assets.`,
      details: null
    });
  }

  // Source maps
  const sourceMaps = allFindings.insecure.filter(f => f.type === 'Exposed Source Map');
  if (sourceMaps.length > 0) {
    results.push({
      check: 'Source Code — Source Maps Exposed',
      status: 'WARN',
      severity: 'medium',
      message: `${sourceMaps.length} source map(s) exposto(s). Código original pode ser reconstruído.`,
      details: {
        maps: sourceMaps.map(m => m.source),
        recommendation: 'Remova sourceMapingURL de bundles em produção para evitar exposição do código original.'
      }
    });
  }

  // Compilation/syntax errors found in responses
  if (allFindings.errors.length > 0) {
    results.push({
      check: 'Source Code — Errors Detected',
      status: 'WARN',
      severity: 'medium',
      message: `${allFindings.errors.length} erro(s) detectado(s) em respostas/código.`,
      details: {
        errors: allFindings.errors.slice(0, 20),
        recommendation: 'Corrija os erros para evitar comportamento inesperado e possíveis brechas.'
      }
    });
  }

  return results;
}

function analyzeContent(text, sourceUrl, fileType, findings) {
  if (!text || text.length === 0) return;
  
  const lines = text.split('\n');
  const isMinified = lines.length < 10 && text.length > 1000;

  // ── Secret detection ──────────────────────────────────────
  for (const pattern of SECRET_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    let match;
    while ((match = regex.exec(text)) !== null) {
      // Validate if needed
      if (pattern.validate && !pattern.validate(match[0])) continue;
      
      // Skip false positives
      if (isLikelyFalsePositive(match[0], pattern.name)) continue;

      const lineNum = isMinified ? 1 : getLineNumber(text, match.index);
      const context = getContext(text, match.index, 60);
      
      findings.secrets.push({
        type: pattern.name,
        severity: pattern.severity,
        source: sourceUrl,
        preview: redact(context),
        line: lineNum,
        fileType
      });
    }
  }

  // ── Insecure pattern detection ────────────────────────────
  for (const pattern of INSECURE_PATTERNS) {
    const regex = new RegExp(pattern.pattern.source, pattern.pattern.flags);
    let match;
    let count = 0;
    while ((match = regex.exec(text)) !== null && count < 5) {
      const lineNum = isMinified ? 1 : getLineNumber(text, match.index);
      const context = getContext(text, match.index, 80);
      
      findings.insecure.push({
        type: pattern.name,
        severity: pattern.severity,
        source: sourceUrl,
        preview: context,
        recommendation: pattern.recommendation,
        line: lineNum,
        fileType
      });
      count++;
    }
  }

  // ── Error / stack trace detection in responses ────────────
  const errorPatterns = [
    /(?:SyntaxError|TypeError|ReferenceError|RangeError):\s*(.{10,80})/g,
    /(?:Internal Server Error|500 Error|503 Service Unavailable)/gi,
    /(?:Traceback|at\s+\w+\s+\(\/[^\)]+\))/g,
    /(?:FATAL|PANIC|ERROR)\s*:\s*(.{10,100})/g,
    /(?:exception|stack_trace|stackTrace)\s*[=:]\s*/gi,
    /Warning:\s*(?:pg_|mysql_|mysqli_)/g,
    /PHP (?:Fatal|Parse|Warning) error/gi,
    /(?:Uncaught|Unhandled)\s+(?:Error|Exception|Promise)/g
  ];

  for (const errPat of errorPatterns) {
    let m;
    while ((m = errPat.exec(text)) !== null) {
      findings.errors.push({
        type: 'Runtime Error',
        source: sourceUrl,
        preview: m[0].substring(0, 150),
        line: getLineNumber(text, m.index)
      });
    }
  }
}

function extractMoreAssets(text, baseUrl) {
  const found = [];
  
  // Look for chunk references in webpack/vite bundles
  const chunkPatterns = [
    /["']([^"']*\.(?:js|mjs|css|json))["']/g,
    /(?:src|href|import)\s*[=:(]\s*["']([^"']+\.(?:js|css|json))["']/gi,
    /\/_next\/static\/[a-zA-Z0-9/_-]+\.js/g,
    /\/static\/(?:js|css)\/[a-zA-Z0-9._-]+\.(?:js|css)/g,
    /\/assets\/[a-zA-Z0-9._-]+\.(?:js|css)/g,
  ];

  for (const pat of chunkPatterns) {
    let m;
    while ((m = pat.exec(text)) !== null) {
      const href = m[1] || m[0];
      if (href.includes('node_modules') || href.length > 200) continue;
      try {
        found.push(resolveUrl(href, baseUrl));
      } catch {}
    }
  }

  return found.slice(0, 30); // Limit discovery
}

function guessFileType(url, contentType) {
  if (contentType.includes('javascript') || url.match(/\.m?js(\?|$)/)) return 'JS';
  if (contentType.includes('html') || url.match(/\.html?(\?|$)/)) return 'HTML';
  if (contentType.includes('css') || url.endsWith('.css')) return 'CSS';
  if (contentType.includes('json') || url.endsWith('.json')) return 'JSON';
  if (url.endsWith('.map')) return 'SourceMap';
  if (url.endsWith('.xml') || contentType.includes('xml')) return 'XML';
  if (url.endsWith('.txt')) return 'TXT';
  return 'Other';
}

function isLikelyFalsePositive(match, type) {
  // Filter out common false positives
  if (type === 'Email Address') {
    const fakeDomains = ['example.com', 'test.com', 'localhost', 'placeholder.com', 'email.com', 'your-'];
    return fakeDomains.some(d => match.includes(d));
  }
  if (type === 'Hardcoded IP') {
    const safe = ['0.0.0.0', '127.0.0.1', '192.168.', '10.0.', '172.16.', '255.255'];
    return safe.some(s => match.includes(s)) || match.length < 8;
  }
  if (type === 'Phone Number' && match.replace(/\D/g, '').length < 10) return true;
  if (type === 'Credit Card Number') {
    const digits = match.replace(/\D/g, '');
    return !luhnCheck(digits);
  }
  return false;
}

function luhnCheck(num) {
  let sum = 0, alt = false;
  for (let i = num.length - 1; i >= 0; i--) {
    let n = parseInt(num[i], 10);
    if (alt && (n *= 2) > 9) n -= 9;
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function getLineNumber(text, index) {
  return text.substring(0, index).split('\n').length;
}

function getContext(text, index, radius) {
  return text.substring(Math.max(0, index - radius), Math.min(text.length, index + radius)).replace(/\n/g, ' ').trim();
}

function redact(str) {
  // Redact long alphanumeric sequences (likely keys/tokens)
  return str.replace(/[a-zA-Z0-9_\-]{20,}/g, (m) => m.substring(0, 6) + '...[REDACTED]');
}

function groupFindings(findings) {
  const groups = {};
  for (const f of findings) {
    if (!groups[f.type]) groups[f.type] = { count: 0, severity: f.severity, sources: new Set() };
    groups[f.type].count++;
    groups[f.type].sources.add(f.source);
  }
  return Object.entries(groups).map(([type, data]) => ({
    type, count: data.count, severity: data.severity, sources: [...data.sources].slice(0, 5)
  }));
}

module.exports = { deepSourceCodeAnalysis };
