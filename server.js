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

const { generateSupabaseCatalog, generateCatalogHTML } = require('./audit/report-supabase-catalog');
const { askGrok, askGrokStream, generateFixPrompt } = require('./audit/grok-ai');
const { saveAuditToSupabase, getAuditHistory, getAuditById } = require('./audit/supabase-db');
const { analyzeGitHistory, checkForExposedSecrets } = require('./audit/git-analyzer');
const { generateChecklistHTML } = require('./audit/checklist-generator');

const app = express();
const PORT = process.env.PORT || 2998;
const APP_VERSION = '3.2.0';

// ─── Build hash: muda toda vez que o servidor inicia ─────────────
// Combina a versão + timestamp de boot para invalidar cache no deploy
const BUILD_HASH = process.env.BUILD_HASH ||
  crypto.createHash('sha256')
    .update(APP_VERSION + process.env.npm_package_version + Date.now().toString())
    .digest('hex')
    .slice(0, 12);

console.log(`[Cache] Build hash: ${BUILD_HASH}`);

app.use(cors());
app.use(express.json({ limit: '50mb' }));

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
    console.error('❌ Cannot store audit: missing data or auditId');
    return;
  }
  auditStore.set(data.evidence.auditId, data);
  // Keep only last 20
  if (auditStore.size > 20) {
    const oldest = auditStore.keys().next().value;
    auditStore.delete(oldest);
  }
  
  // Debug log
  console.log('\n============================================');
  console.log('=== STORING AUDIT ===');
  console.log('============================================');
  console.log('Audit ID:', data.evidence.auditId);
  console.log('Project URL:', data.projectUrl);
  console.log('Score:', data.score, `(${data.grade?.grade} - ${data.grade?.label})`);
  console.log('Total Checks:', data.totalChecks);
  console.log('Passed:', data.passed, '| Failed:', data.failed, '| Warnings:', data.warnings);
  console.log('Results count:', data.results?.length || 0);
  console.log('Has catalogData:', !!data.catalogData);
  console.log('Evidence SHA256:', data.evidence?.sha256);
  console.log('User IP:', userIp);
  console.log('User Agent:', userAgent ? userAgent.substring(0, 100) : 'N/A');
  console.log('SUPABASE_URL set:', !!process.env.SUPABASE_URL);
  console.log('SUPABASE_ANON_KEY set:', !!process.env.SUPABASE_ANON_KEY);
  console.log('============================================\n');
  
  // Try to save to Supabase
  const supabaseUrl = process.env.SUPABASE_URL || 'https://qmrceufksvlfdwnwftst.supabase.co';
  const supabaseKey = process.env.SUPABASE_ANON_KEY || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFtcmNldWZrc3ZsZmR3bndmdHN0Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzI4NzQ0ODEsImV4cCI6MjA4ODQ1MDQ4MX0.NXX4jvBXumkAp2L8z56q5pLXoXJaVUNPnjBwn4XUPPE';
  
  console.log('Using Supabase URL:', supabaseUrl);
  console.log('Calling saveAuditToSupabase...\n');
  
  saveAuditToSupabase(data, userIp, userAgent)
    .then(result => {
      console.log('\n============================================');
      console.log('=== SAVE RESULT ===');
      console.log('============================================');
      console.log('Success:', result.success);
      if (result.success) {
        console.log(`✅ AUDIT SAVED TO SUPABASE: ${result.auditId}`);
        console.log('You can view this audit at:');
        console.log(`   Local: http://localhost:${PORT}/audit/${data.evidence.auditId}`);
        console.log(`   API:   http://localhost:${PORT}/api/db/audit/${result.auditId}`);
      } else {
        console.error('❌ Failed to save:', result.error);
      }
      console.log('============================================\n');
    })
    .catch(err => {
      console.error('\n============================================');
      console.error('=== SAVE EXCEPTION ===');
      console.error('============================================');
      console.error('Exception saving audit:', err.message);
      console.error('Stack:', err.stack);
      console.error('============================================\n');
    });
}

// ─── API Routes ───────────────────────────────────────────────────

// Start audit (SSE stream)
app.post('/api/audit', async (req, res) => {
  const { url, anonKey, options } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL do projeto Supabase é obrigatória' });
  }

  try {
    let projectUrl = url.trim().replace(/\/+$/, '');
    if (!projectUrl.startsWith('http')) {
      projectUrl = 'https://' + projectUrl;
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
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });

  let targetUrl = url.trim().replace(/\/+$/, '');
  if (!targetUrl.startsWith('http')) targetUrl = 'https://' + targetUrl;

  try {
    const filename = `source-${targetUrl.replace(/https?:\/\//, '').replace(/[^a-zA-Z0-9]/g, '-')}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    await lightScrape(targetUrl, res, (msg) => {
      console.log(`[Scraper] ${msg}`);
    });
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
    version: '3.2.0',
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
app.post('/api/ai/chat', async (req, res) => {
  const { auditId, question, history, auditData } = req.body;
  
  if (!question) {
    return res.status(400).json({ error: 'Question is required' });
  }

  let auditDataToUse = null;
  
  // First try: use auditData passed directly (for Vercel/production)
  if (auditData) {
    auditDataToUse = auditData;
  }
  // Second try: use auditId to look up in memory store (for local dev)
  else if (auditId) {
    auditDataToUse = auditStore.get(auditId);
  }

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
app.post('/api/ai/chat/simple', async (req, res) => {
  const { auditId, question, auditData } = req.body;
  
  if (!question) {
    return res.status(400).json({ error: 'Question is required' });
  }

  let auditDataToUse = null;
  
  if (auditData) {
    auditDataToUse = auditData;
  } else if (auditId) {
    auditDataToUse = auditStore.get(auditId);
  }

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
app.post('/api/ai/fix-prompt', async (req, res) => {
  const { auditId, auditData } = req.body;

  let auditDataToUse = auditData || auditStore.get(auditId);

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

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   SUPABASE GUARD — Audit Console v3.2    ║`);
  console.log(`  ║   Running on http://localhost:${PORT}        ║`);
  console.log(`  ║                                          ║`);
  console.log(`  ║   NEW Features v3.2:                      ║`);
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
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
