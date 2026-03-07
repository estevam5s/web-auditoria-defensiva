/*  ═══════════════════════════════════════════════════════════════════
    SUPABASE GUARD — Defensive Audit Server
    Engine: Express + Node.js
    Evidence: SHA-256
    Checks: 25+ hardening controls
    Reports: PDF, HTML, JSON, ZIP
    ═══════════════════════════════════════════════════════════════════ */

const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { runFullAudit } = require('./audit/engine');
const { generatePDFReport } = require('./audit/report-pdf');
const { generateHTMLReport } = require('./audit/report-html');
const { lightScrape } = require('./audit/scraper');

const { generateSupabaseCatalog, generateCatalogHTML } = require('./audit/report-supabase-catalog');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── In-memory audit store (latest per URL hash) ─────────────────
const auditStore = new Map();

function storeAudit(data) {
  if (!data || !data.evidence?.auditId) return;
  auditStore.set(data.evidence.auditId, data);
  // Keep only last 20
  if (auditStore.size > 20) {
    const oldest = auditStore.keys().next().value;
    auditStore.delete(oldest);
  }
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

    // Store the audit
    storeAudit(results);

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
app.post('/api/report/html/view', (req, res) => {
  const { auditData } = req.body;
  if (!auditData) return res.status(400).json({ error: 'auditData required' });

  try {
    const html = generateHTMLReport(auditData);
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

// ─── Audit Detail HTML Page ──────────────────────────────────────
app.get('/audit/:id', (req, res) => {
  const data = auditStore.get(req.params.id);
  if (!data) {
    return res.send(`<html><body style="background:#0a0a0f;color:#fff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh">
      <div style="text-align:center"><h1 style="color:#ff0040">Audit Not Found</h1><p>ID: ${req.params.id}</p><a href="/" style="color:#00ff41">Voltar</a></div></body></html>`);
  }
  const html = generateHTMLReport(data);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(html);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    engine: 'supabase-guard',
    version: '3.0.0',
    features: ['pdf-report', 'html-report', 'site-scraper', 'stack-detection', 'deep-analysis-v2', 'auto-detect', 'openapi-introspection', 'rest-scan-deep', 'relationship-rls', 'graphql-scan', 'auth-settings-deep', 'supabase-catalog'],
    storedAudits: auditStore.size,
  });
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

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   SUPABASE GUARD — Audit Console v2.0    ║`);
  console.log(`  ║   Running on http://localhost:${PORT}        ║`);
  console.log(`  ║                                          ║`);
  console.log(`  ║   Routes:                                ║`);
  console.log(`  ║   POST /api/audit        — Run audit     ║`);
  console.log(`  ║   POST /api/report/pdf   — PDF report    ║`);
  console.log(`  ║   POST /api/report/html  — HTML report   ║`);
  console.log(`  ║   POST /api/scrape       — Site ZIP      ║`);
  console.log(`  ║   GET  /api/audits       — List audits   ║`);
  console.log(`  ║   GET  /audit/:id        — View report   ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
