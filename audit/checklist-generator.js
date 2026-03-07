/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Checklist Standalone HTML Generator
   Generates a self-contained HTML file with embedded data,
   CSS, JS and Chart.js (CDN) for offline client distribution.
   ═══════════════════════════════════════════════════════════════════ */

const fs = require('fs');
const path = require('path');

function generateChecklistHTML(auditData) {
  const css = fs.readFileSync(path.join(__dirname, '../public/checklist.css'), 'utf-8');
  const js  = fs.readFileSync(path.join(__dirname, '../public/checklist.js'),  'utf-8');

  const { projectUrl, score, grade, evidence } = auditData;
  const auditId = evidence?.auditId || 'standalone';
  const g = grade || {};

  // Safely serialize audit data — strip circular references & huge fields
  const safeData = JSON.stringify(sanitizeAuditData(auditData));

  // Build standalone JS: override fetch to use embedded data instead of /api/*
  const standaloneInit = `
const EMBEDDED_AUDIT_DATA = ${safeData};
const EMBEDDED_AUDIT_ID = ${JSON.stringify(auditId)};

// Override init to use embedded data
document.addEventListener('DOMContentLoaded', function() {
  auditId = EMBEDDED_AUDIT_ID;
  const saved = localStorage.getItem('checklist-' + auditId);
  checkedItems = saved ? JSON.parse(saved) : {};
  auditData = EMBEDDED_AUDIT_DATA;
  render();
});
`;

  // Strip the original DOMContentLoaded from JS (we replace it)
  const jsPatched = js
    .replace(/document\.addEventListener\('DOMContentLoaded',\s*init\s*\)\s*;/, '// DOMContentLoaded overridden by standalone mode')
    .replace(/async function init\(\) \{[\s\S]*?^}/m, 'async function init() { /* replaced */ }');

  const dateStr = evidence?.timestamp
    ? new Date(evidence.timestamp).toLocaleString('pt-BR')
    : new Date().toLocaleString('pt-BR');

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Relatório de Segurança — ${esc(projectUrl || 'Supabase Guard')}</title>
  <meta name="description" content="Relatório de segurança Supabase Guard gerado em ${dateStr}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"></script>
  <style>
${css}
  </style>
</head>
<body>

<!-- STANDALONE MODE — dados embarcados, sem dependência de servidor -->

<div id="loadingScreen">
  <div class="loader-wrap">
    <svg class="loader-icon spin" viewBox="0 0 24 24" fill="none" stroke="#00ff41" stroke-width="2" width="48" height="48">
      <path d="M21 12a9 9 0 11-6.219-8.56"/>
    </svg>
    <p>Carregando relatório...</p>
  </div>
</div>

<div id="errorScreen" style="display:none">
  <div class="error-wrap">
    <svg viewBox="0 0 24 24" fill="none" stroke="#ff0040" stroke-width="2" width="56" height="56">
      <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
    <h2>Erro ao carregar relatório</h2>
    <p id="errorMsg">Ocorreu um erro ao processar os dados do relatório.</p>
  </div>
</div>

<div id="mainContent" style="display:none">

  <header class="cl-header">
    <div class="cl-header-inner">
      <div class="cl-logo-wrap">
        <svg viewBox="0 0 60 60" width="40" height="40">
          <defs>
            <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#00ff41"/>
              <stop offset="100%" style="stop-color:#00bfff"/>
            </linearGradient>
          </defs>
          <path d="M30 4 L52 14 L52 32 C52 44 42 54 30 58 C18 54 8 44 8 32 L8 14 Z" fill="url(#shieldGrad)" opacity="0.15" stroke="url(#shieldGrad)" stroke-width="1.5"/>
          <path d="M30 12 L46 20 L46 32 C46 41 39 49 30 52 C21 49 14 41 14 32 L14 20 Z" fill="url(#shieldGrad)" opacity="0.2"/>
          <text x="30" y="37" text-anchor="middle" fill="url(#shieldGrad)" font-size="16" font-weight="700" font-family="monospace">SG</text>
        </svg>
        <div>
          <div class="cl-brand">Supabase Guard</div>
          <div class="cl-subtitle">Relatório de Segurança</div>
        </div>
      </div>
      <div class="cl-header-meta">
        <div class="cl-project-url" id="headerUrl">—</div>
        <div class="cl-header-right">
          <div class="cl-score-badge" id="headerScoreBadge">—</div>
          <button class="cl-btn cl-btn-print" onclick="window.print()">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16">
              <polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2"/><rect x="6" y="14" width="12" height="8"/>
            </svg>
            Imprimir / PDF
          </button>
        </div>
      </div>
    </div>
    <div class="cl-header-bar" id="headerBar">
      <span id="headerDate">—</span>
      <span class="cl-sep">·</span>
      <span>Audit ID: <code id="headerAuditId">—</code></span>
      <span class="cl-sep">·</span>
      <span id="headerDuration">—</span>
      <span class="cl-sep">·</span>
      <span id="headerChecks">—</span>
    </div>
  </header>

  <div class="cl-container">

    <section class="cl-section">
      <h2 class="cl-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
          <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
        </svg>
        Resumo Executivo
      </h2>
      <div class="cl-stats-grid" id="statsGrid"></div>
    </section>

    <section class="cl-section">
      <h2 class="cl-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
          <line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>
        </svg>
        Análise Visual
      </h2>
      <div class="cl-charts-grid">
        <div class="cl-chart-card">
          <h3 class="cl-chart-title">Distribuição por Severidade</h3>
          <div class="cl-chart-wrap"><canvas id="chartSeverity"></canvas></div>
        </div>
        <div class="cl-chart-card">
          <h3 class="cl-chart-title">Vulnerabilidades por Categoria</h3>
          <div class="cl-chart-wrap cl-chart-wrap--bar"><canvas id="chartCategory"></canvas></div>
        </div>
        <div class="cl-chart-card">
          <h3 class="cl-chart-title">Status Geral das Verificações</h3>
          <div class="cl-chart-wrap"><canvas id="chartStatus"></canvas></div>
        </div>
      </div>
    </section>

    <section class="cl-section">
      <h2 class="cl-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
          <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        Matriz de Prioridade — Top Vulnerabilidades
      </h2>
      <div class="cl-table-wrap">
        <table class="cl-table" id="priorityTable">
          <thead>
            <tr>
              <th>#</th><th>Severidade</th><th>Verificação</th><th>Problema Identificado</th><th>Impacto</th>
            </tr>
          </thead>
          <tbody id="priorityTableBody"></tbody>
        </table>
      </div>
    </section>

    <section class="cl-section">
      <h2 class="cl-section-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
          <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
        </svg>
        Checklist de Correções
        <span class="cl-progress-pill" id="progressPill">0 / 0 corrigido(s)</span>
      </h2>
      <div class="cl-progress-bar-wrap">
        <div class="cl-progress-bar" id="progressBar" style="width:0%"></div>
      </div>
      <div id="checklistContainer"></div>
    </section>

    <footer class="cl-footer">
      <div class="cl-footer-brand"><strong>Supabase Guard</strong> — Plataforma de Auditoria de Segurança</div>
      <div class="cl-footer-meta">
        <span>Gerado em: <span id="footerDate">—</span></span>
        <span class="cl-sep">·</span>
        <span>ID: <code id="footerAuditId">—</code></span>
        <span class="cl-sep">·</span>
        <span>SHA-256: <code id="footerHash">—</code></span>
      </div>
      <div class="cl-footer-notice">
        Este relatório contém informações confidenciais de segurança. Não compartilhe com pessoas não autorizadas.
      </div>
    </footer>

  </div>
</div>

<script>
${jsPatched}

${standaloneInit}
</script>
</body>
</html>`;
}

function sanitizeAuditData(data) {
  // Keep only what the checklist page needs, limit sizes
  return {
    projectUrl: data.projectUrl,
    projectRef: data.projectRef,
    score: data.score,
    grade: data.grade,
    totalChecks: data.totalChecks,
    passed: data.passed,
    failed: data.failed,
    warnings: data.warnings,
    duration: data.duration,
    evidence: data.evidence ? {
      sha256: data.evidence.sha256,
      timestamp: data.evidence.timestamp,
      auditId: data.evidence.auditId
    } : null,
    results: (data.results || []).map(r => ({
      check: r.check,
      status: r.status,
      severity: r.severity,
      message: r.message,
      details: r.details ? sanitizeDetails(r.details) : null
    }))
  };
}

function sanitizeDetails(details) {
  if (!details || typeof details !== 'object') return null;
  const safe = {};
  const allowedKeys = ['recommendation', 'hint', 'url', 'missing', 'functions', 'tables', 'files'];
  for (const key of allowedKeys) {
    if (details[key] !== undefined) {
      const val = details[key];
      // Limit array sizes
      if (Array.isArray(val)) {
        safe[key] = val.slice(0, 20).map(item =>
          typeof item === 'object' ? { name: item.name || item.table || item.file || String(item) } : String(item)
        );
      } else if (typeof val === 'string') {
        safe[key] = val.substring(0, 500);
      } else {
        safe[key] = val;
      }
    }
  }
  return Object.keys(safe).length > 0 ? safe : null;
}

function esc(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

module.exports = { generateChecklistHTML };
