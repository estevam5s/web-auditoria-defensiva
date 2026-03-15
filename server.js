/* ═══════════════════════════════════════════════════════════════════
    SUPABASE GUARD — Defensive Audit Server
    Engine: Express + Node.js
    Evidence: SHA-256
    Checks: 25+ hardening controls
    Reports: PDF, HTML, JSON, ZIP
    ═══════════════════════════════════════════════════════════════════ */

// Load environment variables FIRST
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { runFullAudit } = require('./audit/engine');
const { generatePDFReport } = require('./audit/report-pdf');
const { generateHTMLReport } = require('./audit/report-html');
const { lightScrape } = require('./audit/scraper');
const { runOSINT } = require('./audit/osint');
const { runDarkWebScan, classifyThreat } = require('./audit/dark-web');
const { createDDoSTest } = require('./audit/ddos-engine');
const { createBruteforceTest, BUILTIN_WORDLIST, parseWordlist } = require('./audit/bruteforce-engine');

const { generateSupabaseCatalog, generateCatalogHTML } = require('./audit/report-supabase-catalog');
const { askGrok, askGrokStream, generateFixPrompt } = require('./audit/grok-ai');
const { saveAuditToSupabase, getAuditHistory, getAuditById, supabaseFetch, getVulnerabilitiesByAudit } = require('./audit/supabase-db');
const { analyzeGitHistory, checkForExposedSecrets } = require('./audit/git-analyzer');
const { generateChecklistHTML } = require('./audit/checklist-generator');
const { generateConsultingReport } = require('./audit/report-consulting');
const { generateCredentialsReport } = require('./audit/report-credentials');
const { generatePythonScripts } = require('./audit/python-scripts-generator');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 2998;
const APP_VERSION = '3.3.0';

// ─── Map Supabase DB row → auditData format ──────────────────────
// getAuditById returns { success, data: <snake_case DB row> }.
// All report routes expect camelCase fields (projectUrl, results, etc.).
function mapDbRowToAuditData(row) {
  const gradeColors = { 'A+':'#22c55e','A':'#22c55e','A-':'#86efac','B+':'#84cc16','B':'#a3e635','B-':'#bef264','C+':'#eab308','C':'#fbbf24','C-':'#fcd34d','D':'#f97316','F':'#ef4444' };
  return {
    projectUrl:  row.project_url,
    projectRef:  row.project_ref  || null,
    score:       row.score        || 0,
    grade:       { grade: row.grade || 'F', label: row.grade_label || row.grade || 'F', color: gradeColors[row.grade] || '#ef4444' },
    results:     Array.isArray(row.results_json) ? row.results_json : [],
    catalogData: row.catalog_data_json || {},
    duration:    row.duration     || null,
    totalChecks: row.total_checks || 0,
    passed:      row.passed_count || 0,
    failed:      row.failed_count || 0,
    warnings:    row.warnings_count || 0,
    errors:      row.errors_count   || 0,
    info:        row.info_count     || 0,
    evidence: {
      auditId:   row.audit_id,
      sha256:    row.evidence_sha256    || null,
      timestamp: row.evidence_timestamp || new Date().toISOString(),
    },
  };
}

// Helper: fetch audit from store or DB, returning a normalised auditData object.
async function resolveAudit(id) {
  let data = auditStore.get(id);
  if (!data) {
    try {
      const dbResult = await getAuditById(id);
      if (dbResult.success && dbResult.data) {
        data = mapDbRowToAuditData(dbResult.data);
      }
    } catch (_) {}
  }
  return data || null;
}

// ─── Build hash: estável por versão, muda apenas em novo deploy ──
// Usa só APP_VERSION + npm_package_version (sem Date.now).
// Em produção, defina BUILD_HASH via variável de ambiente no CI/CD.
// Isso evita que reinícios do servidor em dev disparem reload no browser.
const BUILD_HASH = process.env.BUILD_HASH ||
  crypto.createHash('sha256')
    .update(APP_VERSION + (process.env.npm_package_version || ''))
    .digest('hex')
    .slice(0, 12);

console.log(`[Cache] Build hash: ${BUILD_HASH} (versão: ${APP_VERSION})`);

// ─── CORS — wildcard em dev, restrito em produção ─────────────────
const isDev = process.env.NODE_ENV !== 'production';

function parseCorsOrigins(raw) {
  if (!raw) return false;
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

if (!isDev && !process.env.CORS_ORIGIN) {
  console.warn('[CORS] Produção sem CORS_ORIGIN definido — todas origens externas bloqueadas.');
}

app.use(cors({
  origin: isDev
    ? '*'
    : (req, callback) => {
        const allowed = parseCorsOrigins(process.env.CORS_ORIGIN);
        if (allowed === false) return callback(null, false);
        const origin = req.headers.origin;
        callback(null, allowed.includes(origin) ? origin : false);
      }
}));

// ─── Rate Limiters ────────────────────────────────────────────────
function createRateLimiter(maxReq, windowMs) {
  const counts = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of counts.entries()) {
      if (now > entry.reset) counts.delete(ip);
    }
  }, windowMs);

  return (req, res, next) => {
    const ip = (req.headers['x-forwarded-for'] || req.ip || 'unknown').split(',')[0].trim();
    const now = Date.now();
    const entry = counts.get(ip) || { count: 0, reset: now + windowMs };
    if (now > entry.reset) { entry.count = 0; entry.reset = now + windowMs; }
    entry.count++;
    counts.set(ip, entry);
    if (entry.count > maxReq) {
      const retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader('Retry-After', retryAfter);
      return res.status(429).json({ error: 'Rate limit exceeded', retryAfter, limit: maxReq, window: `${windowMs / 1000}s` });
    }
    next();
  };
}

const auditLimiter  = createRateLimiter(5, 60_000);   // 5 req/min por IP
const aiLimiter     = createRateLimiter(20, 60_000);  // 20 req/min por IP
const osintLimiter  = createRateLimiter(3, 60_000);   // 3 req/min por IP (OSINT é pesado)

app.use(express.json({ limit: '1mb' }));

// ─── Security Headers ─────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (!isDev) {
    res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  }
  next();
});

// ─── Cache-control: no-cache para arquivos que mudam a cada deploy ─
// O SW também usa /api/version para invalidar automaticamente
app.use((req, res, next) => {
  const ext = path.extname(req.path);
  if (['.html', '.js', '.css'].includes(ext) || req.path === '/') {
    // Força revalidação — nunca serve versão obsoleta do cache HTTP
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Build-Hash', BUILD_HASH);
  } else if (['.woff', '.woff2', '.ttf', '.svg', '.png', '.ico'].includes(ext)) {
    // Fontes e imagens podem ser cacheadas por mais tempo
    res.setHeader('Cache-Control', 'public, max-age=86400'); // 1 dia
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/isos', express.static(path.join(__dirname, 'isos')));

// ─── ISO Standards metadata endpoint ──────────────────────────────
app.get('/api/iso/standards', (req, res) => {
  const isoDir = path.join(__dirname, 'isos');
  const standards = [
    { id: '27001', file: '27001.pdf', title: 'ISO/IEC 27001:2022', topic: 'Information Security Management Systems', controls: 93 },
    { id: '27002', file: '27002.pdf', title: 'ISO/IEC 27002:2022', topic: 'Information Security Controls', controls: 93 },
    { id: '27005', file: '27005.pdf', title: 'ISO/IEC 27005:2022', topic: 'Information Security Risk Management', controls: null },
    { id: '38500', file: '38500.pdf', title: 'ISO/IEC 38500:2015', topic: 'IT Governance', controls: 6 },
  ].map(s => ({
    ...s,
    available: fs.existsSync(path.join(isoDir, s.file)),
    downloadUrl: fs.existsSync(path.join(isoDir, s.file)) ? `/isos/${s.file}` : null
  }));
  res.json({ standards });
});

// ─── Endpoint de versão para o Service Worker ────────────────────
// O SW polling chama este endpoint e invalida o cache local quando
// o buildHash muda (ou seja, quando o servidor foi reiniciado/deployado)
app.get('/api/version', (req, res) => {
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.json({
    version: APP_VERSION,
    buildHash: BUILD_HASH,
    startedAt: new Date().toISOString(),
    uptime: Math.floor(process.uptime()),
  });
});

// ─── In-memory audit store (latest per URL hash) ─────────────────
const auditStore = new Map();

function storeAudit(data, userIp = null, userAgent = null) {
  if (!data || !data.evidence?.auditId) {
    console.error('[Audit] Cannot store: missing data or auditId');
    return;
  }
  auditStore.set(data.evidence.auditId, data);
  // Keep only last 20
  if (auditStore.size > 20) {
    const oldest = auditStore.keys().next().value;
    auditStore.delete(oldest);
  }

  console.log(`[Audit] Stored ${data.evidence.auditId} | Score: ${data.score} | IP: ${userIp}`);

  if (process.env.NODE_ENV !== 'production') {
    console.log(`[Audit Debug] ${data.projectUrl} | ${data.grade?.grade} | checks: ${data.totalChecks} | passed: ${data.passed} | failed: ${data.failed}`);
  }

  saveAuditToSupabase(data, userIp, userAgent)
    .then(result => {
      if (result.success) console.log(`[Supabase] Audit saved: ${result.auditId}`);
      else if (result.error !== 'Supabase não configurado') console.error(`[Supabase] Save failed: ${result.error}`);
    })
    .catch(err => console.error(`[Supabase] Exception: ${err.message}`));
}

// ─── Helpers ──────────────────────────────────────────────────────
function resolveAuditData(auditId, auditData) {
  return auditData || (auditId ? auditStore.get(auditId) : null);
}

// ─── API Routes ───────────────────────────────────────────────────

// Start audit (SSE stream)
app.post('/api/audit', auditLimiter, async (req, res) => {
  const { url, anonKey, options } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL do projeto Supabase é obrigatória' });
  }

  // Basic input validation — reject obviously invalid or dangerous inputs
  const trimmedUrl = url.trim();
  if (trimmedUrl.length > 2048) {
    return res.status(400).json({ error: 'URL muito longa' });
  }
  // Block private/loopback addresses to prevent SSRF
  if (/^(https?:\/\/)?(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(trimmedUrl)) {
    return res.status(400).json({ error: 'URL de destino não permitida' });
  }

  try {
    let projectUrl = trimmedUrl.replace(/\/+$/, '');
    if (!projectUrl.startsWith('http')) {
      projectUrl = 'https://' + projectUrl;
    }

    // Validate URL structure
    try { new URL(projectUrl); } catch {
      return res.status(400).json({ error: 'URL inválida' });
    }

    const supabaseMatch = projectUrl.match(/https?:\/\/([a-z0-9]+)\.supabase\.co/);
    const projectRef = supabaseMatch ? supabaseMatch[1] : null;

    const auditConfig = {
      projectUrl,
      projectRef,
      anonKey: anonKey || null,
      options: {
        checkREST: true, checkRPC: true, checkGraphQL: true, checkStorage: true,
        checkEdgeFunctions: true, checkRealtime: true, checkAuth: true,
        checkEnvExposure: true, checkRLS: true, checkCORS: true,
        checkDDoS: true, checkBruteForce: true, checkSecurityHeaders: true,
        guestMode: true, userMode: options?.userMode || false,
        ...options
      }
    };

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent({ type: 'start', message: 'Iniciando auditoria defensiva...' });

    const results = await runFullAudit(auditConfig, sendEvent);

    // Store the audit (with user info)
    const userIp = req.ip || req.connection?.remoteAddress || req.headers['x-forwarded-for'];
    const userAgent = req.headers['user-agent'];
    storeAudit(results, userIp, userAgent);

    sendEvent({ type: 'complete', results });
    res.end();

  } catch (err) {
    console.error('Audit error:', err);
    res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
    res.end();
  }
});

// ─── PDF Report ───────────────────────────────────────────────────
app.post('/api/report/pdf', async (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  try {
    const filename = `supabase-guard-report-${auditData.evidence?.auditId || Date.now()}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    await generatePDFReport(auditData, res);
  } catch (err) {
    console.error('PDF error:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// ─── HTML Report ──────────────────────────────────────────────────
app.post('/api/report/html', (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  try {
    const html = generateHTMLReport(auditData);
    const filename = `supabase-guard-report-${auditData.evidence?.auditId || Date.now()}.html`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(html);
  } catch (err) {
    console.error('HTML report error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── HTML Report (view in browser) ───────────────────────────────
app.post('/api/report/html/view', async (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  // Resolve IP and detect hosting
  const networkInfo = {};
  try {
    const dns = require('dns').promises;
    const urlObj = new URL(auditData.projectUrl);
    networkInfo.hostname = urlObj.hostname;
    const { address } = await dns.lookup(urlObj.hostname);
    networkInfo.ip = address;
    // Extract hosting from stack detection results
    const stackResult = (auditData.results || []).find(r => r.check === 'Stack Detection');
    networkInfo.hosting = (stackResult?.details?.categories?.Hosting || [])[0] || null;
  } catch { /* DNS lookup optional */ }

  try {
    const html = generateHTMLReport(auditData, networkInfo);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (err) {
    console.error('HTML view error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Site Source Code Scraper (ZIP) ───────────────────────────────
app.post('/api/scrape', async (req, res) => {
  const { url, auditId } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  let targetUrl = url.trim().replace(/\/+$/, '');
  if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

  // Optionally embed audit results inside the ZIP
  const auditData = auditId ? auditStore.get(auditId) : null;

  try {
    const domain   = targetUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '-').slice(0, 40);
    const filename = `${domain}-source.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    await lightScrape(targetUrl, res, (msg) => {
      console.log(`[Scraper] ${msg}`);
    }, auditData || null);
  } catch (err) {
    console.error('Scrape error:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// ─── Audit Info Route (detailed page for developer) ──────────────
app.get('/api/audit/:id', (req, res) => {
  const data = auditStore.get(req.params.id);
  if (!data) return res.status(404).json({ error: 'Audit not found. Re-run the audit first.' });
  res.json(data);
});

app.get('/api/audits', (req, res) => {
  const list = [];
  for (const [id, data] of auditStore.entries()) {
    list.push({
      auditId: id,
      projectUrl: data.projectUrl,
      score: data.score,
      grade: data.grade,
      duration: data.duration,
      timestamp: data.evidence?.timestamp,
      totalChecks: data.totalChecks,
      failed: data.failed,
    });
  }
  res.json(list.reverse());
});

// ─── Hacker Academy ───────────────────────────────────────────────
app.get('/learn', (req, res) => res.sendFile(path.join(__dirname, 'public', 'learn.html')));

// ─── Security Terminal ────────────────────────────────────────────
app.get('/terminal/:auditId', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'terminal.html'));
});

// Terminal AI endpoint — calls Groq and returns analysis
app.post('/api/terminal/:auditId/ai', async (req, res) => {
  const data = auditStore.get(req.params.auditId);
  if (!data) return res.status(404).json({ error: 'Auditoria não encontrada. Execute novamente.' });

  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'question é obrigatório' });

  try {
    const result = await askGrok(data, question);
    res.json(result);
  } catch (err) {
    console.error('[Terminal AI] Error:', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Audit Detail Dashboard (live page, fetches /api/audit/:id) ──
app.get('/audit/:id', (req, res) => {
  // Serve the interactive dashboard; data loaded client-side via /api/audit/:id
  res.sendFile(path.join(__dirname, 'public', 'audit-detail.html'));
});

// Health check
app.get('/api/health', async (req, res) => {
  // Test Supabase connection
  let supabaseStatus = 'not_configured';
  let supabaseAuditsCount = 0;
  
  if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
    try {
      const testResult = await getAuditHistory(1);
      supabaseStatus = testResult.success ? 'connected' : 'error';
      const countResult = await supabaseFetch('audits?select=id', {});
      supabaseAuditsCount = countResult.success ? (countResult.data?.length || 0) : 0;
    } catch (e) {
      supabaseStatus = 'error: ' + e.message;
    }
  }

  res.json({
    status: 'ok',
    engine: 'supabase-guard',
    version: '3.3.0',
    features: ['pdf-report', 'html-report', 'site-scraper', 'stack-detection', 'deep-analysis-v2', 'auto-detect', 'openapi-introspection', 'rest-scan-deep', 'relationship-rls', 'graphql-scan', 'auth-settings-deep', 'supabase-catalog', 'supabase-db-save', 'git-history-analysis', 'audit-history', 'ddos-check', 'brute-force-check', 'ssl-analysis', 'security-headers', 'hydra-simulation', 'tailscale-network-check', 'dos-advanced-slowloris-redos', 'route-discovery-expanded'],
    storedAudits: auditStore.size,
    supabase: {
      configured: !!(process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY),
      status: supabaseStatus,
      url: process.env.SUPABASE_URL ? process.env.SUPABASE_URL.substring(0, 30) + '...' : null,
      auditsInDb: supabaseAuditsCount
    }
  });
});

// ─── Supabase Database Routes ─────────────────────────────────────

// Get audit history from Supabase
app.get('/api/db/audits', async (req, res) => {
  const result = await getAuditHistory(50);
  res.json(result);
});

// Get specific audit from Supabase
app.get('/api/db/audit/:id', async (req, res) => {
  const result = await getAuditById(req.params.id);
  res.json(result);
});

// Get combined audit history (local + Supabase)
app.get('/api/audits/history', async (req, res) => {
  try {
    // Get local audits
    const localAudits = [];
    for (const [id, data] of auditStore.entries()) {
      localAudits.push({
        source: 'local',
        auditId: id,
        projectUrl: data.projectUrl,
        score: data.score,
        grade: data.grade,
        duration: data.duration,
        timestamp: data.evidence?.timestamp,
        totalChecks: data.totalChecks,
        passed: data.passed,
        failed: data.failed,
        warnings: data.warnings
      });
    }

    // Get Supabase audits
    const supabaseResult = await getAuditHistory(50);
    const supabaseAudits = supabaseResult.success ? supabaseResult.data.map(a => ({
      source: 'supabase',
      auditId: a.audit_id,
      projectUrl: a.project_url,
      score: a.score,
      grade: { grade: a.grade, label: a.grade_label },
      duration: a.duration,
      timestamp: a.evidence_timestamp,
      totalChecks: a.total_checks,
      passed: a.passed_count,
      failed: a.failed_count,
      warnings: a.warnings_count,
      userIp: a.user_ip,
      userMachine: a.user_machine,
      userOs: a.user_os,
      userRegion: a.user_region
    })) : [];

    // Combine and sort by timestamp
    const allAudits = [...localAudits, ...supabaseAudits].sort((a, b) => 
      new Date(b.timestamp) - new Date(a.timestamp)
    );

    res.json({
      success: true,
      localCount: localAudits.length,
      supabaseCount: supabaseAudits.length,
      totalCount: allAudits.length,
      audits: allAudits
    });
  } catch (err) {
    console.error('Error fetching audit history:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get full audit details from Supabase by audit_id
app.get('/api/audits/db/full/:auditId', async (req, res) => {
  try {
    const { auditId } = req.params;
    
    // Get main audit data
    const auditResult = await getAuditById(auditId);
    if (!auditResult.success) {
      return res.status(404).json({ success: false, error: 'Audit not found' });
    }

    const audit = auditResult.data;

    if (!audit?.id) {
      return res.status(404).json({ success: false, error: 'Audit data incomplete' });
    }

    // Get individual results
    const resultsResult = await supabaseFetch(
      `audit_results?audit_id=eq.${audit.id}&select=*&order=severity asc`
    );

    // Get vulnerabilities
    const vulnResult = await getVulnerabilitiesByAudit(audit.id);

    res.json({
      success: true,
      audit: {
        id: audit.id,
        auditId: audit.audit_id,
        projectUrl: audit.project_url,
        projectRef: audit.project_ref,
        score: audit.score,
        grade: audit.grade,
        gradeLabel: audit.grade_label,
        totalChecks: audit.total_checks,
        passed: audit.passed_count,
        failed: audit.failed_count,
        warnings: audit.warnings_count,
        errors: audit.errors_count,
        info: audit.info_count,
        duration: audit.duration,
        evidence: {
          sha256: audit.evidence_sha256,
          timestamp: audit.evidence_timestamp,
          auditId: audit.audit_id
        },
        results: resultsResult.success ? resultsResult.data : [],
        vulnerabilities: vulnResult.success ? vulnResult.data : [],
        user: {
          ip: audit.user_ip,
          machine: audit.user_machine,
          os: audit.user_os,
          browser: audit.user_browser,
          region: audit.user_region
        },
        createdAt: audit.created_at
      }
    });
  } catch (err) {
    console.error('Error fetching full audit:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Git Analysis Routes ───────────────────────────────────────

// Analyze local git repository
app.post('/api/analyze/git', async (req, res) => {
  const { projectPath } = req.body;
  
  if (!projectPath) {
    return res.status(400).json({ error: 'projectPath is required' });
  }
  
  try {
    const results = await analyzeGitHistory(projectPath);
    res.json({ success: true, data: results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Check for exposed secrets
app.post('/api/analyze/secrets', async (req, res) => {
  const { projectPath } = req.body;
  
  if (!projectPath) {
    return res.status(400).json({ error: 'projectPath is required' });
  }
  
  try {
    const results = await checkForExposedSecrets(projectPath);
    res.json({ success: true, data: results });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Supabase Catalog Report ─────────────────────────────────────
app.post('/api/report/catalog', (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  try {
    const catalog = generateSupabaseCatalog(
      { projectUrl: auditData.projectUrl, projectRef: auditData.projectRef },
      auditData.catalogData || {}
    );
    res.json(catalog);
  } catch (err) {
    console.error('Catalog error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── Supabase Catalog HTML Report ─────────────────────────────────
app.post('/api/report/catalog/html', (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  try {
    const catalog = generateSupabaseCatalog(
      { projectUrl: auditData.projectUrl, projectRef: auditData.projectRef },
      auditData.catalogData || {}
    );
    const html = generateCatalogHTML(catalog);
    const filename = `supabase-catalog-${auditData.evidence?.auditId || Date.now()}.html`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(html);
  } catch (err) {
    console.error('Catalog HTML error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ─── AI Chat Endpoint ───────────────────────────────────────────────
app.post('/api/ai/chat', aiLimiter, async (req, res) => {
  const { auditId, question, history, auditData } = req.body;

  if (!question) {
    return res.status(400).json({ error: 'Question is required' });
  }

  const auditDataToUse = resolveAuditData(auditId, auditData);
  if (!auditDataToUse) {
    return res.status(404).json({ error: 'Audit not found. Please run an audit first.' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    await askGrokStream(auditDataToUse, question, (chunk) => {
      if (chunk.error) {
        res.write(`data: ${JSON.stringify({ type: 'error', message: chunk.error })}\n\n`);
      } else if (chunk.done) {
        res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
        res.end();
      } else {
        res.write(`data: ${JSON.stringify({ type: 'chunk', content: chunk.content })}\n\n`);
      }
    });
  } catch (err) {
    res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
    res.end();
  }
});

// ─── AI Chat Non-Stream ─────────────────────────────────────────────
app.post('/api/ai/chat/simple', aiLimiter, async (req, res) => {
  const { auditId, question, auditData } = req.body;

  if (!question) {
    return res.status(400).json({ error: 'Question is required' });
  }

  const auditDataToUse = resolveAuditData(auditId, auditData);
  if (!auditDataToUse) {
    return res.status(404).json({ error: 'Audit not found. Please run an audit first.' });
  }

  try {
    const result = await askGrok(auditDataToUse, question);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── AI Fix Prompt Generator ────────────────────────────────────────
app.post('/api/ai/fix-prompt', aiLimiter, async (req, res) => {
  const { auditId, auditData } = req.body;

  const auditDataToUse = resolveAuditData(auditId, auditData);
  if (!auditDataToUse) {
    return res.status(404).json({ error: 'Audit not found. Run an audit first.' });
  }

  try {
    const result = await generateFixPrompt(auditDataToUse);
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── Get Audit Full Data for AI ─────────────────────────────────────
app.get('/api/ai/audit/:id', (req, res) => {
  const data = auditStore.get(req.params.id);
  if (!data) {
    return res.status(404).json({ error: 'Audit not found' });
  }
  res.json({
    auditId: data.evidence?.auditId,
    projectUrl: data.projectUrl,
    score: data.score,
    grade: data.grade,
    results: data.results,
    catalogData: data.catalogData,
    evidence: data.evidence,
    duration: data.duration
  });
});

// ─── Checklist Routes ──────────────────────────────────────────────

// Serve checklist page (fetches data client-side via /api/audit/:id)
app.get('/checklist/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'checklist.html'));
});

// Serve ISO compliance page (fetches data client-side via /api/audit/:id)
app.get('/iso/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'iso.html'));
});

// Export checklist as standalone HTML (no server dependency)
app.get('/api/checklist/:id/export', (req, res) => {
  const { id } = req.params;
  const data = auditStore.get(id);
  if (!data) {
    return res.status(404).json({ error: 'Auditoria não encontrada. Execute uma nova auditoria.' });
  }
  try {
    const html = generateChecklistHTML(data);
    const filename = `checklist-security-${id.substring(0, 8)}.html`;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(html);
  } catch (err) {
    console.error('Checklist export error:', err.message);
    res.status(500).json({ error: 'Erro ao gerar checklist: ' + err.message });
  }
});

// ─── Bug Bounty Report Routes ─────────────────────────────────────

// ─── Consulting Proposal ──────────────────────────────────────────
app.get('/consulting/:id', async (req, res) => {
  const { id } = req.params;

  const auditData = await resolveAudit(id);
  if (!auditData) {
    return res.status(404).send(`<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>Auditoria não encontrada</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f7fa;color:#1f2937}
.box{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:40px;text-align:center;max-width:400px}
h1{color:#dc2626;margin-bottom:8px}p{color:#6b7280}</style>
</head><body><div class="box">
<h1>Auditoria não encontrada</h1>
<p>Nenhuma auditoria com ID <code>${id.replace(/[^a-zA-Z0-9-]/g, '')}</code> foi encontrada.</p>
<p>Execute uma auditoria primeiro e acesse este relatório através do painel principal.</p>
</div></body></html>`);
  }

  function safePrice(val, fallback) {
    const n = parseInt(val, 10);
    return (Number.isFinite(n) && n > 0 && n <= 999999) ? n : fallback;
  }

  const q = req.query;
  const consultingConfig = {
    name:    process.env.CONSULTANT_NAME    || 'Consultor de Segurança',
    email:   process.env.CONSULTANT_EMAIL   || '',
    phone:   process.env.CONSULTANT_PHONE   || '',
    company: process.env.CONSULTANT_COMPANY || '',
    prices: {
      rls:     safePrice(q.price_rls,     parseInt(process.env.CONSULTING_PRICE_RLS)     || 3500),
      auth:    safePrice(q.price_auth,    parseInt(process.env.CONSULTING_PRICE_AUTH)    || 2800),
      env:     safePrice(q.price_env,     parseInt(process.env.CONSULTING_PRICE_ENV)     || 2000),
      headers: safePrice(q.price_headers, parseInt(process.env.CONSULTING_PRICE_HEADERS) || 1500),
      pentest: safePrice(q.price_pentest, parseInt(process.env.CONSULTING_PRICE_PENTEST) || 8000),
      hourly:  safePrice(q.price_hourly,  parseInt(process.env.CONSULTING_PRICE_HOURLY)  || 350),
    }
  };

  // Run dark web scan with a 25s timeout so the report still loads if APIs are slow
  let darkWebIntel = null;
  try {
    const timeout = new Promise(resolve => setTimeout(() => resolve(null), 25000));
    darkWebIntel = await Promise.race([runDarkWebScan(auditData), timeout]);
  } catch (_) { /* dark web scan is optional — never block the consulting report */ }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(generateConsultingReport(auditData, consultingConfig, darkWebIntel));
});

// ─── Credentials & Sensitive Data Exposure Report ──────────────────
app.get('/credentials/:id', async (req, res) => {
  const { id } = req.params;

  const auditData = await resolveAudit(id);
  if (!auditData) {
    return res.status(404).send(`<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="UTF-8">
<title>Auditoria não encontrada</title>
<style>body{font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#030308;color:#c8c8d4}
.box{background:#0a0a12;border:1px solid rgba(255,255,255,.07);border-radius:12px;padding:40px;text-align:center;max-width:420px}
h1{color:#ef4444;margin-bottom:8px}p{color:#6b7280}a{color:#00d4ff;text-decoration:none}</style>
</head><body><div class="box">
<h1>🔑 Auditoria não encontrada</h1>
<p>ID <code>${id.replace(/[^a-zA-Z0-9-]/g, '')}</code> não encontrado.</p>
<p style="margin-top:12px"><a href="/">← Voltar ao Início</a></p>
</div></body></html>`);
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(generateCredentialsReport(auditData));
});

// Serve the bug bounty reporting page
app.get('/bugbounty/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bugbounty.html'));
});

app.get('/bugbounty', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bugbounty.html'));
});

// Generate a complete bug bounty report from audit data
app.post('/api/bugbounty/generate', async (req, res) => {
  const { auditId, auditData, reporterInfo } = req.body;
  const auditDataToUse = resolveAuditData(auditId, auditData);
  if (!auditDataToUse) return res.status(404).json({ error: 'Audit not found. Run an audit first.' });

  try {
    const GROQ_API_KEY = process.env.GROQ_API_KEY || process.env.GROK_API_KEY;
    const { projectUrl, results = [], score, grade, evidence } = auditDataToUse;

    const criticalFindings = results.filter(r => r.status === 'FAIL' || r.severity === 'critical' || r.severity === 'high');
    const findingsSummary = criticalFindings.slice(0, 10).map(r =>
      `- [${(r.severity || r.status || 'UNKNOWN').toUpperCase()}] ${r.check}: ${r.message}`
    ).join('\n');

    const prompt = `Você é um especialista em Bug Bounty e segurança ofensiva/defensiva.
Com base nos resultados desta auditoria de segurança, gere um relatório profissional de bug bounty.

Site auditado: ${projectUrl}
Score de Segurança: ${score}/100 (${grade?.grade || 'N/A'} — ${grade?.label || ''})
Audit ID: ${evidence?.auditId || 'N/A'}
SHA-256: ${evidence?.sha256 || 'N/A'}

Vulnerabilidades encontradas:
${findingsSummary || '- Sem vulnerabilidades críticas encontradas'}

Gere um relatório profissional em português com:
1. EXECUTIVE SUMMARY (2-3 parágrafos)
2. IMPACT ASSESSMENT (impacto de negócio de cada vuln crítica)
3. CVSS SCORES estimados para cada vulnerabilidade principal
4. PROOF OF CONCEPT (como reproduzir — sem código malicioso, apenas descrição técnica)
5. REMEDIATION STEPS detalhados
6. RECOMMENDED BOUNTY TIER (P1/P2/P3/P4 conforme HackerOne/Bugcrowd)
7. DISCLOSURE TIMELINE sugerido

Seja técnico e profissional, como se fosse enviado para um programa de bug bounty real.`;

    let aiReport = '';
    if (GROQ_API_KEY) {
      const groqRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${GROQ_API_KEY}` },
        body: JSON.stringify({
          model: 'llama-3.3-70b-versatile',
          messages: [
            { role: 'system', content: 'Você é um especialista em Bug Bounty e penetration testing. Escreva relatórios técnicos profissionais.' },
            { role: 'user', content: prompt }
          ],
          temperature: 0.3,
          max_tokens: 3000,
        }),
      });
      if (groqRes.ok) {
        const groqData = await groqRes.json();
        aiReport = groqData.choices?.[0]?.message?.content || '';
      }
    }

    // Build known bug bounty platforms for this target
    const domain = (() => { try { return new URL(projectUrl).hostname; } catch { return projectUrl; } })();
    const platforms = [
      { name: 'HackerOne', url: 'https://hackerone.com/directory/programs', match: domain },
      { name: 'Bugcrowd', url: 'https://bugcrowd.com/programs', match: domain },
      { name: 'Intigriti', url: 'https://app.intigriti.com/programs', match: domain },
      { name: 'Synack', url: 'https://www.synack.com/', match: domain },
      { name: 'YesWeHack', url: 'https://yeswehack.com/programs', match: domain },
    ];

    // Classify vulnerabilities by bounty tier
    const tierMapping = criticalFindings.map(f => {
      const sev = (f.severity || '').toLowerCase();
      const msg = (f.message || '').toLowerCase();
      let tier = 'P4';
      if (sev === 'critical' || msg.includes('rce') || msg.includes('sql injection') || msg.includes('jwt') && msg.includes('none')) tier = 'P1';
      else if (sev === 'high' || msg.includes('xss') || msg.includes('ssrf') || msg.includes('credentials')) tier = 'P2';
      else if (sev === 'medium' || msg.includes('cors') || msg.includes('csrf') || msg.includes('redirect')) tier = 'P3';
      return { check: f.check, message: f.message?.slice(0, 100), tier, severity: f.severity || f.status };
    });

    res.json({
      success: true,
      targetUrl: projectUrl,
      domain,
      auditId: evidence?.auditId,
      score,
      grade,
      sha256: evidence?.sha256,
      generatedAt: new Date().toISOString(),
      criticalCount: criticalFindings.length,
      aiReport,
      tierMapping,
      platforms,
      reporterInfo: reporterInfo || {},
    });
  } catch (err) {
    console.error('Bug bounty generation error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Export bug bounty report as Markdown
app.post('/api/bugbounty/export/md', (req, res) => {
  const { reportData, reporterInfo } = req.body;
  if (!reportData) return res.status(400).json({ error: 'reportData required' });

  const { targetUrl, domain, auditId, score, grade, sha256, aiReport, tierMapping, generatedAt } = reportData;
  const reporter = reporterInfo || {};

  const md = `# Bug Bounty Report — ${domain}
**Reporter:** ${reporter.name || 'Security Researcher'}
**Email:** ${reporter.email || 'N/A'}
**Date:** ${new Date(generatedAt).toLocaleDateString('pt-BR')}
**Audit ID:** \`${auditId || 'N/A'}\`
**SHA-256 Evidence:** \`${sha256 || 'N/A'}\`

---

## Target
- **URL:** ${targetUrl}
- **Security Score:** ${score}/100 (${grade?.grade || 'N/A'} — ${grade?.label || ''})
- **Findings:** ${tierMapping?.length || 0} vulnerabilities

---

## Vulnerability Summary

| Check | Severity | Bounty Tier |
|-------|----------|-------------|
${(tierMapping || []).map(t => `| ${t.check} | ${t.severity} | **${t.tier}** |`).join('\n')}

---

## AI Analysis Report

${aiReport || 'N/A'}

---

## Evidence

This report was generated by **Supabase Guard v${APP_VERSION}** — Defensive Audit Console.
- Audit ID: \`${auditId}\`
- SHA-256: \`${sha256}\`
- Generated: ${generatedAt}

*This report is for authorized security testing only. The researcher has permission to test this target.*
`;

  const filename = `bugbounty-${domain}-${Date.now()}.md`;
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.send(md);
});

// ─── Python Blue Team Scripts Routes ───────────────────────────────

// Serve scripts page for a given audit
app.get('/scripts/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'scripts.html'));
});

// Generate Python scripts from audit data using Groq AI
app.post('/api/ai/generate-scripts', aiLimiter, async (req, res) => {
  const { auditId, auditData } = req.body;

  const auditDataToUse = resolveAuditData(auditId, auditData);
  if (!auditDataToUse) {
    return res.status(404).json({ error: 'Audit not found. Run an audit first.' });
  }

  try {
    const result = await generatePythonScripts(auditDataToUse);
    res.json(result);
  } catch (err) {
    console.error('Python scripts generation error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Download a single Python script
app.post('/api/ai/scripts/download', (req, res) => {
  const { scriptId, code, filename } = req.body;
  if (!code) return res.status(400).json({ error: 'code required' });

  const safeFilename = (filename || `${scriptId || 'script'}.py`).replace(/[^a-zA-Z0-9._-]/g, '_');
  res.setHeader('Content-Type', 'text/x-python; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
  res.send(code);
});

// Download all scripts as a ZIP
app.post('/api/ai/scripts/download-zip', async (req, res) => {
  const { scripts, targetUrl } = req.body;
  if (!scripts || !Array.isArray(scripts)) {
    return res.status(400).json({ error: 'scripts array required' });
  }

  try {
    const archiver = require('archiver');
    const archive = archiver('zip', { zlib: { level: 9 } });

    const safeName = (targetUrl || 'audit').replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-').slice(0, 30);
    const filename = `blue-team-scripts-${safeName}-${Date.now()}.zip`;

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    archive.pipe(res);

    // Add each script
    for (const script of scripts) {
      if (script.code) {
        const fname = (script.filename || `${script.id || 'script'}.py`).replace(/[^a-zA-Z0-9._-]/g, '_');
        archive.append(script.code, { name: fname });
      }
    }

    // Add a README
    const readme = `# Blue Team Defense Scripts
# Generated by Supabase Guard — ${new Date().toISOString()}
# Target: ${targetUrl || 'unknown'}
#
# IMPORTANT: These scripts are for DEFENSIVE testing only.
# Use only on systems you have explicit written permission to test.
#
# Scripts included:
${scripts.map(s => `#   - ${s.filename || s.id + '.py'}: ${s.name || s.id}`).join('\n')}
#
# Requirements: pip install requests
# Usage: python <script_name>.py [target_url]
`;
    archive.append(readme, { name: 'README.md' });

    await archive.finalize();
  } catch (err) {
    console.error('ZIP generation error:', err);
    if (!res.headersSent) res.status(500).json({ error: err.message });
  }
});

// ─── OSINT / Internet Footprint (SSE stream) ───────────────────────
app.post('/api/footprint', osintLimiter, async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL é obrigatória' });
  }

  const trimmedUrl = url.trim();
  if (trimmedUrl.length > 2048) {
    return res.status(400).json({ error: 'URL muito longa' });
  }
  if (/^(https?:\/\/)?(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/i.test(trimmedUrl)) {
    return res.status(400).json({ error: 'URL de destino não permitida' });
  }

  let targetUrl = trimmedUrl;
  if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;
  try { new URL(targetUrl); } catch {
    return res.status(400).json({ error: 'URL inválida' });
  }

  // SSE headers — must be set BEFORE flushHeaders
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no'); // disable Nginx buffering
  res.flushHeaders(); // send headers immediately so client knows the stream started

  const sendEvent = (data) => {
    try {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
      // Force flush for environments that buffer
      if (typeof res.flush === 'function') res.flush();
    } catch (e) {
      console.warn('[OSINT] write error:', e.message);
    }
  };

  // Keep-alive ping every 15s so the browser doesn't close an idle connection
  const pingInterval = setInterval(() => {
    try { res.write(': ping\n\n'); } catch { clearInterval(pingInterval); }
  }, 15000);

  console.log(`[OSINT] Starting scan: ${targetUrl}`);
  try {
    await runOSINT(targetUrl, sendEvent);
    console.log(`[OSINT] Scan complete: ${targetUrl}`);
  } catch (err) {
    console.error('[OSINT] Error:', err);
    sendEvent({ type: 'error', message: err.message });
  }

  clearInterval(pingInterval);
  res.end();
});

// ─── Dark Web Intelligence Page ────────────────────────────────────
app.get('/darkweb/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'darkweb.html'));
});

// ─── Dark Web Intelligence API ─────────────────────────────────────
app.post('/api/darkweb', auditLimiter, async (req, res) => {
  const { auditId, auditData } = req.body;
  const data = auditData || (auditId ? await resolveAudit(auditId) : null);
  if (!data) return res.status(404).json({ error: 'Auditoria não encontrada. Execute uma auditoria primeiro.' });

  try {
    console.log(`[DarkWeb] Starting scan for: ${data.projectUrl}`);
    const timeout30s = new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 30000));
    const intel = await Promise.race([runDarkWebScan(data), timeout30s]);
    console.log(`[DarkWeb] Done. Threat level: ${intel.threatLevel} | Risk: ${intel.riskScore}`);
    res.json({ success: true, intel });
  } catch (err) {
    console.error('[DarkWeb] Error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/darkweb/classify/:id', async (req, res) => {
  const data = await resolveAudit(req.params.id);
  if (!data) return res.status(404).json({ error: 'Not found' });
  const level = classifyThreat(data.score, { hibp: { domainBreaches: [] }, otx: { malwareCount: 0, pulseCount: 0 }, urlscan: { malicious: 0 }, virustotal: null });
  res.json({ level, score: data.score, projectUrl: data.projectUrl });
});

// ─── DDoS Resilience Test — Page ──────────────────────────────────
app.get('/ddos/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'ddos.html'));
});

// ─── DDoS Resilience Test — Audit Info ────────────────────────────
app.get('/api/ddos/info/:id', async (req, res) => {
  const data = await resolveAudit(req.params.id);
  if (!data) return res.status(404).json({ success: false, error: 'Auditoria não encontrada.' });
  res.json({
    success:    true,
    projectUrl: data.projectUrl,
    score:      data.score,
    grade:      data.grade,
  });
});

// ─── DDoS Resilience Test — SSE Stream ────────────────────────────
// No rate limiter here — long-running SSE, one connection per audit
app.get('/api/ddos/stream', async (req, res) => {
  const { auditId, profiles } = req.query;

  const data = auditId ? await resolveAudit(auditId) : null;
  if (!data) {
    res.status(404).json({ error: 'Auditoria não encontrada.' });
    return;
  }

  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = obj => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(obj)}\n\n`);
  };

  const profileList = profiles
    ? profiles.split(',').map(p => p.trim()).filter(Boolean)
    : undefined;

  const { emitter, run } = createDDoSTest(data, { profiles: profileList });

  emitter.on('start',          d => send({ type: 'start',          ...d }));
  emitter.on('phase_start',    d => send({ type: 'phase_start',    ...d }));
  emitter.on('tick',           d => send({ type: 'tick',           ...d }));
  emitter.on('phase_complete', d => send({ type: 'phase_complete', ...d }));
  emitter.on('complete',       d => send({ type: 'complete',       ...d }));
  emitter.on('error',         msg => send({ type: 'error', message: typeof msg === 'string' ? msg : msg.message }));

  req.on('close', () => { /* client disconnected — workers will finish naturally */ });

  try {
    await run();
    if (!res.writableEnded) res.end();
  } catch (err) {
    send({ type: 'error', message: err.message });
    if (!res.writableEnded) res.end();
  }
});

// ─── Brute Force Resilience Test ──────────────────────────────────
const bruteforceSessionStore = new Map();

// Page
app.get('/bruteforce/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'bruteforce.html'));
});

// Audit info + detected login routes
app.get('/api/bruteforce/info/:id', async (req, res) => {
  const data = await resolveAudit(req.params.id);
  if (!data) return res.status(404).json({ success: false, error: 'Auditoria não encontrada.' });

  // Extract login-related routes from audit results
  const loginRoutes = [];
  (data.results || []).forEach(r => {
    if (r.route && (
      r.route.includes('/auth') || r.route.includes('/login') ||
      r.route.includes('/signin') || r.route.includes('/token')
    )) loginRoutes.push(r.route);
  });

  // Always offer the Supabase auth endpoint for the scanned project
  const base = (data.projectUrl || '').replace(/\/$/, '');
  if (base.startsWith('http')) {
    loginRoutes.unshift(`${base}/auth/v1/token?grant_type=password`);
  }

  res.json({
    success:      true,
    projectUrl:   data.projectUrl,
    score:        data.score,
    grade:        data.grade,
    loginRoutes:  [...new Set(loginRoutes)].slice(0, 8),
    wordlistSize: BUILTIN_WORDLIST.length,
  });
});

// Prepare session — store config, return sessionId
app.post('/api/bruteforce/prepare', express.json({ limit: '3mb' }), async (req, res) => {
  const { auditId, loginUrl, wordlistType, wordlistContent, delayMs, stopOnSuccess } = req.body || {};
  if (!loginUrl) return res.status(400).json({ error: 'loginUrl obrigatório.' });

  const data = auditId ? await resolveAudit(auditId) : null;

  let credentials;
  if (wordlistType === 'custom' && wordlistContent) {
    credentials = parseWordlist(wordlistContent);
    if (!credentials.length) return res.status(400).json({ error: 'Wordlist vazia ou inválida.' });
  } else {
    credentials = [...BUILTIN_WORDLIST];
  }

  // Extract anonKey if available
  let anonKey = null;
  if (data?.catalogData?.anonKey) anonKey = data.catalogData.anonKey;

  const sessionId = crypto.randomBytes(12).toString('hex');
  bruteforceSessionStore.set(sessionId, {
    loginUrl,
    credentials,
    anonKey,
    delayMs:       Math.max(50, Math.min(2000, Number(delayMs) || 150)),
    stopOnSuccess: stopOnSuccess !== false,
    createdAt:     Date.now(),
  });

  // Prune old sessions (>10 min)
  for (const [id, s] of bruteforceSessionStore) {
    if (Date.now() - s.createdAt > 10 * 60 * 1000) bruteforceSessionStore.delete(id);
  }

  res.json({ success: true, sessionId, total: credentials.length });
});

// SSE stream — runs the attack
app.get('/api/bruteforce/stream/:sessionId', async (req, res) => {
  const session = bruteforceSessionStore.get(req.params.sessionId);
  if (!session) return res.status(404).json({ error: 'Sessão não encontrada ou expirada.' });

  bruteforceSessionStore.delete(req.params.sessionId); // consume once

  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = obj => { if (!res.writableEnded) res.write(`data: ${JSON.stringify(obj)}\n\n`); };

  const abortCtrl = new AbortController();
  req.on('close', () => abortCtrl.abort());

  const { emitter, run } = createBruteforceTest({ ...session, signal: abortCtrl.signal });

  emitter.on('start',        d => send({ type: 'start',        ...d }));
  emitter.on('attempt',      d => send({ type: 'attempt',      ...d }));
  emitter.on('hit_found',    d => send({ type: 'hit_found',    ...d }));
  emitter.on('blocked_hard', d => send({ type: 'blocked_hard', ...d }));
  emitter.on('aborted',      d => send({ type: 'aborted',      ...d }));
  emitter.on('complete',     d => send({ type: 'complete',     ...d }));
  emitter.on('error',       msg => send({ type: 'error', message: String(msg) }));

  try {
    await run();
  } catch (e) {
    send({ type: 'error', message: e.message });
  }
  if (!res.writableEnded) res.end();
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   SUPABASE GUARD — Audit Console v${APP_VERSION}  ║`);
  console.log(`  ║   Running on http://localhost:${PORT}        ║`);
  console.log(`  ║                                          ║`);
  console.log(`  ║   Features v${APP_VERSION}:                     ║`);
  console.log(`  ║   🔱 Hydra Credential Attack Simulation   ║`);
  console.log(`  ║   🕸️ Tailscale/VPN/Network Security       ║`);
  console.log(`  ║   🌊 Advanced DoS (Slowloris/ReDoS/HTTP2) ║`);
  console.log(`  ║   🗺️ Expanded Route Discovery (+80 paths) ║`);
  console.log(`  ║   🌐 DDoS/DoS Resilience Check            ║`);
  console.log(`  ║   🔓 Brute Force Login Check               ║`);
  console.log(`  ║   🛡️ Security Headers Analysis             ║`);
  console.log(`  ║   🔒 Enhanced SSL/TLS Analysis             ║`);
  console.log(`  ║                                          ║`);
  console.log(`  ║   Routes:                                ║`);
  console.log(`  ║   POST /api/audit        — Run audit     ║`);
  console.log(`  ║   POST /api/ai/chat     — AI Chat        ║`);
  console.log(`  ║   POST /api/report/pdf   — PDF report    ║`);
  console.log(`  ║   POST /api/report/html  — HTML report   ║`);
  console.log(`  ║   POST /api/report/catalog — JSON catalog║`);
  console.log(`  ║   POST /api/scrape       — Site ZIP      ║`);
  console.log(`  ║   GET  /api/audits       — List audits   ║`);
  console.log(`  ║   GET  /api/ai/audit/:id — AI Audit Data ║`);
  console.log(`  ║   GET  /audit/:id        — View report   ║`);
  console.log(`  ║   GET  /scripts/:id      — Python scripts║`);
  console.log(`  ║   POST /api/ai/generate-scripts          ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
