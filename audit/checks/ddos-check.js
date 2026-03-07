/*  ═══════════════════════════════════════════════════════════════════
    DDoS / DoS RESILIENCE CHECK + REAL-TIME ATTACK DETECTION
    Tests rate limiting, CDN/WAF protection, response time stability,
    concurrent request handling, and DDoS mitigation infrastructure.
    Includes real-time attack detection during audit.
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');
const tls   = require('tls');

/**
 * Makes a single request and returns {status, headers, ms, error, body}
 */
function httpGet(rawUrl, timeoutMs = 6000, options = {}) {
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
          'User-Agent': options.userAgent || 'SupabaseGuard-SecurityAudit/3.0',
          'Accept': 'application/json, text/html, */*',
          ...options.headers
        },
        rejectUnauthorized: false,
        timeout: timeoutMs
      }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          finish({ status: res.statusCode, headers: res.headers, error: null, body });
        });
      });
      req.on('error', e => finish({ status: 0, headers: {}, error: e.message }));
      req.on('timeout', () => { req.destroy(); finish({ status: 0, headers: {}, error: 'timeout' }); });
    } catch (e) {
      finish({ status: 0, headers: {}, error: e.message });
    }
  });
}

/**
 * Makes N sequential requests and returns array of results
 */
async function sequentialProbe(url, count, delayMs = 100, options = {}) {
  const results = [];
  for (let i = 0; i < count; i++) {
    results.push(await httpGet(url, options.timeoutMs || 6000, options));
    if (i < count - 1 && delayMs > 0) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  return results;
}

/**
 * Makes N concurrent requests (burst)
 */
function concurrentProbe(url, count, timeoutMs = 5000) {
  return Promise.all(Array.from({ length: count }, () => httpGet(url, timeoutMs)));
}

/**
 * Sustained load test - simulates prolonged attack
 */
async function sustainedLoadTest(url, durationMs = 10000, rps = 5) {
  const results = [];
  const endTime = Date.now() + durationMs;
  const intervalMs = 1000 / rps;
  
  while (Date.now() < endTime) {
    const batch = await Promise.all([
      httpGet(url, 5000),
      httpGet(url, 5000)
    ]);
    results.push(...batch);
    await new Promise(r => setTimeout(r, intervalMs));
  }
  
  return results;
}

// ── Header helpers ────────────────────────────────────────────────

function hasCDN(headers) {
  const h = JSON.stringify(headers).toLowerCase();
  const indicators = [
    'cloudflare', 'cf-ray', 'cf-cache-status', 'x-amz-cf-pop', 'fastly',
    'x-served-by', 'x-cache', 'x-varnish', 'via', 'akamai', 'x-cdn',
    'x-edge-location', 'x-azure-ref', 'x-ms-ref', 'x-amz-request-id',
    'x-goog-', 'x-gfe-', 'netlify', 'vercel', 'x-vercel', 'x-now-'
  ];
  return indicators.some(i => h.includes(i));
}

function hasWAF(headers, status) {
  const h = JSON.stringify(headers).toLowerCase();
  const wafSignals = [
    'x-waf-', 'x-sucuri', 'x-qrator', 'x-ddos', 'x-imperva', 'x-incapsula',
    'x-mod-security', 'x-akamai-transformed', '__cfruid', 'cf-mitigated',
    'x-amzn-waf', 'x-firewall', 'x-guard', 'x-sds', 'x-cdn'
  ];
  const wafStatusCodes = [403, 406, 429, 503];
  return wafSignals.some(s => h.includes(s)) || (wafStatusCodes.includes(status) && h.includes('cloudflare'));
}

function hasRateLimit(headers) {
  const keys = Object.keys(headers || {}).map(k => k.toLowerCase());
  const rateLimitHeaders = [
    'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset',
    'ratelimit-limit', 'ratelimit-remaining', 'ratelimit-reset',
    'retry-after', 'x-retry-after', 'x-rate-limit', 'x-rate-limit-limit',
    'x-throttle-wait-seconds', 'x-app-rate-limit'
  ];
  return rateLimitHeaders.some(h => keys.includes(h));
}

function detectCDNProvider(headers) {
  const h = JSON.stringify(headers).toLowerCase();
  if (h.includes('cf-ray') || h.includes('cloudflare')) return 'Cloudflare';
  if (h.includes('x-amz-cf-pop') || h.includes('x-amz-request-id')) return 'AWS CloudFront';
  if (h.includes('x-goog-') || h.includes('x-gfe-')) return 'Google Cloud CDN';
  if (h.includes('x-azure-ref')) return 'Azure CDN / Front Door';
  if (h.includes('x-vercel') || h.includes('x-now-')) return 'Vercel Edge';
  if (h.includes('netlify')) return 'Netlify Edge';
  if (h.includes('fastly')) return 'Fastly CDN';
  if (h.includes('x-sucuri')) return 'Sucuri WAF';
  if (h.includes('x-imperva') || h.includes('x-incapsula')) return 'Imperva / Incapsula';
  if (h.includes('akamai') || h.includes('x-akamai')) return 'Akamai';
  if (h.includes('via') || h.includes('x-cache')) return 'Proxy/CDN genérico';
  return null;
}

// ── SSL/TLS Analysis ────────────────────────────────────────────────

async function analyzeSSL(hostname, port = 443) {
  return new Promise(resolve => {
    const result = {
      secure: false,
      version: null,
      cipher: null,
      certValid: false,
      certExpiry: null,
      certDaysRemaining: null,
      issues: []
    };

    const options = {
      host: hostname,
      port,
      servername: hostname,
      rejectUnauthorized: false
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      const tlsVersion = socket.getProtocol();
      
      result.secure = socket.authorized || false;
      result.version = tlsVersion;
      result.cipher = socket.getCipher()?.name;
      
      if (cert && cert.valid_to) {
        result.certExpiry = cert.valid_to;
        const expiryDate = new Date(cert.valid_to);
        const now = new Date();
        const daysRemaining = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
        result.certDaysRemaining = daysRemaining;
        result.certValid = daysRemaining > 0;
        
        if (daysRemaining < 0) {
          result.issues.push('Certificate expired');
        } else if (daysRemaining < 30) {
          result.issues.push(`Certificate expires in ${daysRemaining} days`);
        }
      }

      if (!result.secure) {
        result.issues.push('Certificate not authorized');
      }

      if (tlsVersion === 'SSLv3' || tlsVersion === 'TLSv1' || tlsVersion === 'TLSv1.1') {
        result.issues.push(`Deprecated TLS version: ${tlsVersion}`);
      }

      socket.end();
      resolve(result);
    });

    socket.on('error', (err) => {
      result.issues.push(`Connection error: ${err.message}`);
      resolve(result);
    });

    socket.setTimeout(5000, () => {
      result.issues.push('Connection timeout');
      socket.destroy();
      resolve(result);
    });
  });
}

// ── Real-time Attack Detection ─────────────────────────────────────

function detectAttackInProgress(probes) {
  const indicators = {
    high503Rate: false,
    timeoutRate: false,
    latencyDegradation: false,
    inconsistentResponses: false
  };

  const total = probes.length;
  if (total === 0) return { detected: false, indicators };

  const status503 = probes.filter(p => p.status === 503).length;
  const timeouts = probes.filter(p => p.error === 'timeout').length;
  const successful = probes.filter(p => p.status >= 200 && p.status < 500).length;
  
  const responseTimes = probes.filter(p => p.ms > 0).map(p => p.ms);
  const avgLatency = responseTimes.length > 0 
    ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length 
    : 0;
  const maxLatency = Math.max(...responseTimes, 0);

  // High 503 rate (>30%)
  indicators.high503Rate = (status503 / total) > 0.3;
  
  // High timeout rate (>20%)
  indicators.timeoutRate = (timeouts / total) > 0.2;
  
  // Extreme latency (>10 seconds average)
  indicators.latencyDegradation = avgLatency > 10000;
  
  // Inconsistent responses (high variance)
  if (responseTimes.length > 2) {
    const variance = responseTimes.reduce((sum, t) => sum + Math.pow(t - avgLatency, 2), 0) / responseTimes.length;
    const stdDev = Math.sqrt(variance);
    indicators.inconsistentResponses = stdDev > avgLatency * 0.5;
  }

  const detected = indicators.high503Rate || indicators.timeoutRate || 
                   indicators.latencyDegradation || indicators.inconsistentResponses;

  return { detected, indicators, stats: { status503, timeouts, successful, avgLatency, maxLatency } };
}

// ── Main export ───────────────────────────────────────────────────

async function checkDDoSResilience(config, emit) {
  const baseUrl = config.projectUrl;
  const results = [];

  if (emit) emit({ type: 'progress-detail', message: '🌐 Iniciando análise de resiliência DDoS/DoS...' });

  // Extract hostname for SSL analysis
  let hostname = null;
  try {
    const u = new URL(baseUrl);
    hostname = u.hostname;
  } catch (e) {
    hostname = baseUrl.replace(/^https?:\/\//, '').split('/')[0];
  }

  // ── 0. SSL/TLS Analysis ───────────────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🔒 Analisando configuração SSL/TLS...' });
  
  const sslResult = await analyzeSSL(hostname);
  {
    let sev, status, msg;
    if (sslResult.secure && sslResult.issues.length === 0) {
      sev = 'info'; status = 'PASS';
      msg = `SSL/TLS seguro: ${sslResult.version} com cipher ${sslResult.cipher}. Certificado válido por ${sslResult.certDaysRemaining} dias.`;
    } else if (sslResult.issues.some(i => i.includes('expired'))) {
      sev = 'critical'; status = 'FAIL';
      msg = `CERTIFICADO SSL EXPIRADO! ${sslResult.issues.join(', ')}`;
    } else if (sslResult.issues.some(i => i.includes('Deprecated'))) {
      sev = 'high'; status = 'FAIL';
      msg = `Versão TLS insegura: ${sslResult.version}. ${sslResult.issues.join(', ')}`;
    } else {
      sev = 'medium'; status = 'WARN';
      msg = `Problemas SSL/TLS: ${sslResult.issues.join(', ')}`;
    }
    results.push({
      check: '🔒 DDoS — SSL/TLS Security',
      status, severity: sev, message: msg,
      details: { 
        secure: sslResult.secure, 
        version: sslResult.version, 
        cipher: sslResult.cipher,
        certDaysRemaining: sslResult.certDaysRemaining,
        issues: sslResult.issues
      }
    });
  }

  // ── 1. Baseline latency measurement ─────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '⏱ Medindo latência de baseline (10 requisições)...' });
  const baselineProbes = await sequentialProbe(baseUrl, 10, 200);
  const validProbes    = baselineProbes.filter(p => p.ms > 0 && !p.error);
  const avgMs          = validProbes.length
    ? Math.round(validProbes.reduce((s, p) => s + p.ms, 0) / validProbes.length)
    : null;
  const maxMs          = validProbes.length ? Math.max(...validProbes.map(p => p.ms)) : null;
  const jitter         = validProbes.length > 1
    ? Math.round(Math.sqrt(validProbes.reduce((s, p) => s + Math.pow(p.ms - avgMs, 2), 0) / validProbes.length))
    : 0;

  // ── 2. Concurrent burst test (20 simultaneous requests) ─────────
  if (emit) emit({ type: 'progress-detail', message: '⚡ Testando burst concorrentes (20 req simultâneas)...' });
  const burstProbes    = await concurrentProbe(baseUrl, 20);
  const burst429       = burstProbes.filter(p => p.status === 429).length;
  const burst503       = burstProbes.filter(p => p.status === 503).length;
  const burstErrors    = burstProbes.filter(p => p.error && p.error !== 'timeout').length;
  const burstTimeouts  = burstProbes.filter(p => p.error === 'timeout').length;
  const avgBurstMs    = burstProbes.filter(p => p.ms > 0).length
    ? Math.round(burstProbes.filter(p => p.ms > 0).reduce((s, p) => s + p.ms, 0) / burstProbes.filter(p => p.ms > 0).length)
    : null;

  // ── 3. Real-time attack detection ───────────────────────────────
  if (emit) emit({ type: 'progress-detail', message: '🎯 Verificando ataques em tempo real...' });
  const attackDetection = detectAttackInProgress(burstProbes);

  // ── 4. Protection headers analysis ──────────────────────────────
  const firstProbe = baselineProbes.find(p => !p.error) || burstProbes.find(p => !p.error);
  const headers    = firstProbe?.headers || {};
  const cdnPresent = hasCDN(headers);
  const wafPresent = hasWAF(headers, firstProbe?.status);
  const rateLimitPresent = hasRateLimit(headers) || burst429 > 0;
  const cdnProvider = detectCDNProvider(headers);

  // ── 5. Throttling detection ─────────────────────────────────────
  const burstGotThrottled = burst429 > 0 || burst503 > 0;
  const latencyDegradation = avgMs && avgBurstMs && avgBurstMs > avgMs * 2;

  // ═══════════════════════════════════════════════════════════════
  // RESULTS
  // ═══════════════════════════════════════════════════════════════

  // 5a. Real-time attack detection
  {
    let status, sev, msg;
    if (attackDetection.detected) {
      const reasons = [];
      if (attackDetection.indicators.high503Rate) reasons.push('alta taxa de 503');
      if (attackDetection.indicators.timeoutRate) reasons.push('timeouts frequentes');
      if (attackDetection.indicators.latencyDegradation) reasons.push('latência extrema');
      if (attackDetection.indicators.inconsistentResponses) reasons.push('respostas inconsistentes');
      
      status = 'FAIL'; sev = 'critical';
      msg = `⚠️ POSSÍVEL ATAQUE DDoS DETECTADO! Indicadores: ${reasons.join(', ')}. Taxa de sucesso: ${attackDetection.stats.successful}/20 requisições.`;
    } else {
      status = 'PASS'; sev = 'info';
      msg = `Nenhum ataque DDoS/DoS detectado em tempo real. Servidor respondedendo normalmente.`;
    }
    results.push({
      check: '🎯 DDoS — Detecção de Ataque em Tempo Real',
      status, severity: sev, message: msg,
      details: { 
        detected: attackDetection.detected,
        indicators: attackDetection.indicators,
        stats: attackDetection.stats
      }
    });
  }

  // 5b. Baseline latency
  if (avgMs !== null) {
    let sev, status, msg;
    if (avgMs > 3000) {
      sev = 'high'; status = 'WARN';
      msg = `Latência muito alta: ${avgMs}ms (máx: ${maxMs}ms, jitter: ±${jitter}ms) — possível degradação por carga ou ataque em curso`;
    } else if (avgMs > 1500) {
      sev = 'medium'; status = 'WARN';
      msg = `Latência elevada: ${avgMs}ms (máx: ${maxMs}ms) — monitorar para detectar ataques de lentidão (slowloris)`;
    } else {
      sev = 'info'; status = 'PASS';
      msg = `Latência estável: ${avgMs}ms médio (máx: ${maxMs}ms, jitter: ±${jitter}ms)`;
    }
    results.push({
      check: '🌐 DDoS — Latência & Estabilidade',
      status, severity: sev, message: msg,
      details: { avgMs, maxMs, jitter, probes: validProbes.length, sampleTimes: validProbes.map(p => p.ms) }
    });
  }

  // 5c. CDN / Edge Protection
  {
    const sev = cdnPresent ? 'info' : 'medium';
    const status = cdnPresent ? 'PASS' : 'WARN';
    const msg = cdnPresent
      ? `CDN/proxy detectado: ${cdnProvider || 'Provedor identificado'} — mitigação DDoS de borda ativa`
      : 'Nenhum CDN ou proxy de borda detectado — servidor origin exposto diretamente';
    results.push({
      check: '🛡️ DDoS — Proteção CDN & Borda',
      status, severity: sev, message: msg,
      details: { cdnPresent, cdnProvider, cdnHeaders: Object.fromEntries(Object.entries(headers).filter(([k]) => ['cf-ray','cf-cache-status','via','x-cache','x-amz-cf-pop','x-vercel','x-azure-ref'].includes(k.toLowerCase()))) }
    });
  }

  // 5d. WAF
  {
    const status = wafPresent ? 'PASS' : 'WARN';
    const sev    = wafPresent ? 'info' : 'medium';
    const msg    = wafPresent
      ? 'WAF (Web Application Firewall) detectado — camada de proteção contra ataques de aplicação ativa'
      : 'Nenhum WAF detectado — aplicação exposta sem proteção de camada 7';
    results.push({
      check: '🔥 DDoS — WAF (Web Application Firewall)',
      status, severity: sev, message: msg,
      details: { wafPresent, server: headers['server'] || headers['x-powered-by'] || 'N/A' }
    });
  }

  // 5e. Rate Limiting
  {
    const status = rateLimitPresent ? 'PASS' : 'FAIL';
    const sev    = rateLimitPresent ? 'info' : 'high';
    const msg    = rateLimitPresent
      ? `Rate limiting ativo — ${burst429} de 20 burst requests bloqueadas com 429`
      : 'Rate limiting NÃO detectado — endpoint aceita requisições ilimitadas (vulnerável a DoS por volume)';
    results.push({
      check: '⏱ DDoS — Rate Limiting',
      status, severity: sev, message: msg,
      details: {
        rateLimitPresent, burst429, burst503,
        rateLimitHeaders: Object.fromEntries(Object.entries(headers).filter(([k]) => k.toLowerCase().startsWith('x-ratelimit') || k.toLowerCase() === 'retry-after'))
      }
    });
  }

  // 5f. Behavior under burst
  {
    let status, sev, msg;
    if (burstGotThrottled) {
      status = 'PASS'; sev = 'info';
      msg = `Servidor aplicou throttling sob burst: ${burst429} × 429, ${burst503} × 503 — proteção ativa contra inundação`;
    } else if (burstTimeouts >= 5) {
      status = 'FAIL'; sev = 'high';
      msg = `${burstTimeouts}/20 requisições concorrentes deram timeout — servidor pode estar sobrecarregado ou sem queue adequada`;
    } else if (latencyDegradation) {
      status = 'WARN'; sev = 'medium';
      msg = `Degradação de latência sob carga detectada: baseline ${avgMs}ms → burst ${avgBurstMs}ms (+${Math.round((avgBurstMs/avgMs - 1)*100)}%) — sem proteção de autoscaling`;
    } else if (burstErrors >= 8) {
      status = 'WARN'; sev = 'medium';
      msg = `${burstErrors}/20 requisições concorrentes retornaram erro — servidor instável sob carga`;
    } else {
      status = 'PASS'; sev = 'info';
      msg = `Servidor respondeu a 20 requisições concorrentes sem degradação significativa (${avgBurstMs}ms médio)`;
    }
    results.push({
      check: '⚡ DDoS — Comportamento sob Carga (Burst Test)',
      status, severity: sev, message: msg,
      details: { burstCount: 20, burst429, burst503, burstErrors, burstTimeouts, avgBurstMs, avgBaselineMs: avgMs }
    });
  }

  // 5g. General protection analysis
  {
    const protections = [cdnPresent, wafPresent, rateLimitPresent, burstGotThrottled].filter(Boolean).length;
    let status, sev, msg;
    if (protections >= 3) {
      status = 'PASS'; sev = 'info';
      msg = `Múltiplas camadas de proteção DDoS detectadas (${protections}/4): CDN, WAF, rate limiting — postura robusta`;
    } else if (protections >= 2) {
      status = 'PASS'; sev = 'low';
      msg = `Proteção DDoS básica detectada (${protections}/4 camadas) — recomenda-se adicionar proteções adicionais`;
    } else if (protections === 1) {
      status = 'FAIL'; sev = 'high';
      msg = `Proteção DDoS mínima (${protections}/4 camadas) — aplicação vulnerável a ataques de volume e aplicação`;
    } else {
      status = 'FAIL'; sev = 'critical';
      msg = 'NENHUMA proteção DDoS/DoS detectada — servidor origin exposto sem CDN, WAF ou rate limiting';
    }
    results.push({
      check: '🚨 DDoS — Análise de Proteção Geral',
      status, severity: sev, message: msg,
      details: { protections, cdnPresent, wafPresent, rateLimitPresent, throttlingDetected: burstGotThrottled, cdnProvider }
    });
  }

  return results;
}

module.exports = { checkDDoSResilience };
