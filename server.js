/*  ═══════════════════════════════════════════════════════════════════
    SUPABASE GUARD — Defensive Audit Server
    Engine: Express + Node.js
    Evidence: SHA-256
    Checks: 14+ hardening controls
    ═══════════════════════════════════════════════════════════════════ */

const express = require('express');
const cors = require('cors');
const path = require('path');
const { runFullAudit } = require('./audit/engine');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── API Routes ───────────────────────────────────────────────────

// Start audit
app.post('/api/audit', async (req, res) => {
  const { url, anonKey, options } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL do projeto Supabase é obrigatória' });
  }

  try {
    // Normalize URL
    let projectUrl = url.trim().replace(/\/+$/, '');
    if (!projectUrl.startsWith('http')) {
      projectUrl = 'https://' + projectUrl;
    }

    // Extract project ref if full URL provided
    const supabaseMatch = projectUrl.match(/https?:\/\/([a-z0-9]+)\.supabase\.co/);
    const projectRef = supabaseMatch ? supabaseMatch[1] : null;

    const auditConfig = {
      projectUrl,
      projectRef,
      anonKey: anonKey || null,
      options: {
        checkREST: true,
        checkRPC: true,
        checkGraphQL: true,
        checkStorage: true,
        checkEdgeFunctions: true,
        checkRealtime: true,
        checkAuth: true,
        checkEnvExposure: true,
        checkRLS: true,
        checkCORS: true,
        guestMode: true,
        userMode: options?.userMode || false,
        ...options
      }
    };

    // Stream-like response using SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    const sendEvent = (data) => {
      res.write(`data: ${JSON.stringify(data)}\n\n`);
    };

    sendEvent({ type: 'start', message: 'Iniciando auditoria defensiva...' });

    const results = await runFullAudit(auditConfig, sendEvent);

    sendEvent({ type: 'complete', results });
    res.end();

  } catch (err) {
    console.error('Audit error:', err);
    res.write(`data: ${JSON.stringify({ type: 'error', message: err.message })}\n\n`);
    res.end();
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', engine: 'supabase-guard', version: '1.0.0' });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n  ╔══════════════════════════════════════════╗`);
  console.log(`  ║   SUPABASE GUARD — Audit Console         ║`);
  console.log(`  ║   Running on http://localhost:${PORT}        ║`);
  console.log(`  ╚══════════════════════════════════════════╝\n`);
});
