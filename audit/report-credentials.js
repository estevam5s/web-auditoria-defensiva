'use strict';

/* ═══════════════════════════════════════════════════════════════════
   CREDENTIALS & SENSITIVE DATA REPORT GENERATOR
   Generates a dark-themed professional HTML page showing all
   exposed credentials, .env data, and site metadata from an audit.
   ═══════════════════════════════════════════════════════════════════ */

// ── Helpers ────────────────────────────────────────────────────────

function esc(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function severityColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return '#ef4444';
  if (s === 'high')     return '#f97316';
  if (s === 'medium')   return '#eab308';
  if (s === 'low')      return '#3b82f6';
  return '#a855f7'; // info / unknown
}

function severityBg(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'rgba(239,68,68,0.12)';
  if (s === 'high')     return 'rgba(249,115,22,0.12)';
  if (s === 'medium')   return 'rgba(234,179,8,0.12)';
  if (s === 'low')      return 'rgba(59,130,246,0.12)';
  return 'rgba(168,85,247,0.12)';
}

function severityBadge(sev) {
  const label = (sev || 'info').toUpperCase();
  const color = severityColor(sev);
  const bg    = severityBg(sev);
  return `<span class="sev-badge" style="color:${color};background:${bg};border-color:${color}33;">${esc(label)}</span>`;
}

function fmtDetails(details) {
  if (!details) return '';
  if (typeof details === 'string') return esc(details);
  try { return esc(JSON.stringify(details, null, 2)); } catch { return esc(String(details)); }
}

function matchesAny(str, patterns) {
  const s = str || '';
  return patterns.some(p => new RegExp(p, 'i').test(s));
}

function credCategory(check) {
  const c = (check || '').toLowerCase();
  if (/stripe|payment|billing|checkout/.test(c))     return 'Payment Gateway';
  if (/supabase|anon|service.key|service_role/.test(c)) return 'Supabase';
  if (/database|postgres|mysql|mongo|redis|db.url/.test(c)) return 'Database';
  if (/jwt|token|bearer|oauth|session/.test(c))      return 'Auth Token';
  if (/private.key|rsa|ecdsa|pem|pkcs/.test(c))      return 'Crypto Key';
  if (/api.key|apikey|api_key/.test(c))               return 'API Key';
  return 'Credential';
}

function categoryIcon(cat) {
  const icons = {
    'Payment Gateway': '💳',
    'Supabase':        '⚡',
    'Database':        '🗄️',
    'Auth Token':      '🔑',
    'Crypto Key':      '🔐',
    'API Key':         '🔒',
    'Credential':      '⚠️',
  };
  return icons[cat] || '⚠️';
}

function groupBy(arr, keyFn) {
  return arr.reduce((acc, item) => {
    const k = keyFn(item);
    if (!acc[k]) acc[k] = [];
    acc[k].push(item);
    return acc;
  }, {});
}

// ── Section builders ───────────────────────────────────────────────

function buildHeader(auditData) {
  const { projectUrl, score, grade, evidence } = auditData;
  const scanDate = evidence?.timestamp
    ? new Date(evidence.timestamp).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })
    : new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

  const gradeColor = grade?.color || '#ef4444';
  const gradeLabel = grade?.grade || '?';
  const scoreVal   = typeof score === 'number' ? score : '—';

  return `
  <!-- PRINT BUTTON -->
  <button class="print-btn no-print" onclick="window.print()" title="Exportar PDF">
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
    Exportar PDF
  </button>

  <!-- TOP NAV BAR -->
  <nav class="top-nav no-print">
    <a href="/" class="top-nav-back">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="15 18 9 12 15 6"/></svg>
      Painel
    </a>
    <div class="top-nav-breadcrumb">
      <span>Supabase Guard</span>
      <span class="sep">/</span>
      <span class="crumb-active">Credenciais Expostas</span>
    </div>
    <div class="top-nav-status">
      <span class="status-dot"></span>
      <span>RELATÓRIO CONFIDENCIAL</span>
    </div>
  </nav>

  <!-- HEADER BANNER -->
  <header class="site-header">
    <div class="header-bg-grid"></div>
    <div class="header-bg-glow"></div>
    <div class="header-inner">
      <div class="header-icon-wrap">
        <div class="header-icon-ring"></div>
        <svg class="header-icon-svg" width="44" height="44" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 1L3 5v6c0 5.25 3.75 10.14 9 11.25C17.25 21.14 21 16.25 21 11V5L12 1Z" fill="rgba(239,68,68,0.15)" stroke="#ef4444" stroke-width="1.5"/>
          <path d="M12 8v4m0 4h.01" stroke="#ef4444" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="header-text">
        <div class="header-eyebrow">
          <span class="eyebrow-pill">OFENSIVO</span>
          RELATÓRIO DE SEGURANÇA · DADOS SENSÍVEIS
        </div>
        <h1 class="header-title">EXPOSIÇÃO DE CREDENCIAIS<br><span class="title-accent">&amp; DADOS SENSÍVEIS</span></h1>
        <div class="header-url">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
          <span>${esc(projectUrl || '—')}</span>
        </div>
        <div class="header-meta">
          <span class="meta-chip">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
            ${esc(scanDate)}
          </span>
          <span class="score-badge" style="color:${esc(gradeColor)};border-color:${esc(gradeColor)}55;background:${esc(gradeColor)}18;box-shadow:0 0 12px ${esc(gradeColor)}22;">
            Score: <strong>${esc(String(scoreVal))}</strong> &nbsp;|&nbsp; Grade: <strong>${esc(gradeLabel)}</strong>
          </span>
        </div>
      </div>
    </div>
    <div class="header-bottom-line"></div>
  </header>`;
}

function buildSummaryRow(results) {
  const criticalCount = results.filter(r => (r.severity || '').toLowerCase() === 'critical').length;
  const highCount     = results.filter(r => (r.severity || '').toLowerCase() === 'high').length;

  const credPatterns = ['Credential','PII','Bundle Key','Service Key','API Key','Database URL','Redis','Supabase','Stripe','Password','Private Key','JWT','Token'];
  const credLeaks    = results.filter(r => matchesAny(r.check, credPatterns)).length;

  const piiPatterns  = ['CPF','CNPJ','RG','SSN','Email','Phone','Credit Card','PIX','CEP','Documento','Financeiro'];
  const piiCount     = results.filter(r => matchesAny(r.check, piiPatterns)).length;

  const stats = [
    { label: 'Críticos',        value: criticalCount, color: '#ef4444', icon: '🔴', desc: 'Achados críticos' },
    { label: 'Alto Risco',      value: highCount,     color: '#f97316', icon: '🟠', desc: 'Achados de alto risco' },
    { label: 'Credenciais',     value: credLeaks,     color: '#a855f7', icon: '🔑', desc: 'Vazamentos detectados' },
    { label: 'PII Detectado',   value: piiCount,      color: '#3b82f6', icon: '👤', desc: 'Dados pessoais expostos' },
  ];

  const cards = stats.map(s => `
    <div class="stat-card" style="border-color:${s.color}33;">
      <div class="stat-icon" style="color:${s.color};">${s.icon}</div>
      <div class="stat-number" style="color:${s.color};">${s.value}</div>
      <div class="stat-label">${esc(s.label)}</div>
      <div class="stat-desc">${esc(s.desc)}</div>
    </div>`).join('');

  return `
  <section class="summary-row fade-in">
    <div class="stats-grid">
      ${cards}
    </div>
  </section>`;
}

function buildCredentialSection(results) {
  const patterns = ['Credential','PII','Bundle Key','Service Key','API Key','Database URL','Redis','Supabase','Stripe','Password','Private Key','JWT','Token'];
  const items    = results.filter(r => matchesAny(r.check, patterns));

  if (!items.length) {
    return `
    <section class="report-section fade-in">
      <div class="section-header">
        <div class="section-icon accent">🔑</div>
        <h2>Credenciais &amp; Chaves Expostas</h2>
      </div>
      <div class="empty-card green">
        <span>✅</span>
        <span>Nenhuma credencial exposta encontrada</span>
      </div>
    </section>`;
  }

  const grouped = groupBy(items, r => credCategory(r.check));
  let catBlocks = '';

  for (const [cat, findings] of Object.entries(grouped)) {
    const icon = categoryIcon(cat);
    const rows = findings.map((f, i) => {
      const hasDetails = f.details != null && f.details !== '';
      const detailId   = `cred-detail-${cat.replace(/\s/g,'')}-${i}`;
      return `
        <div class="finding-row" style="border-left-color:${severityColor(f.severity)};">
          <div class="finding-top">
            ${severityBadge(f.severity)}
            <span class="finding-name">${esc(f.check)}</span>
            ${hasDetails ? `<button class="toggle-btn no-print" onclick="toggleDetail('${detailId}')">detalhes ▾</button>` : ''}
          </div>
          <div class="finding-msg">${esc(f.message)}</div>
          ${hasDetails ? `<div id="${detailId}" class="detail-panel" style="display:none;"><pre>${fmtDetails(f.details)}</pre></div>` : ''}
        </div>`;
    }).join('');

    catBlocks += `
      <div class="category-block">
        <div class="category-title">
          <span class="cat-icon">${icon}</span>
          ${esc(cat)}
          <span class="cat-count">${findings.length}</span>
        </div>
        ${rows}
      </div>`;
  }

  return `
  <section class="report-section fade-in">
    <div class="section-header">
      <div class="section-icon red">🔑</div>
      <h2>Credenciais &amp; Chaves Expostas</h2>
      <span class="section-count red">${items.length} achado${items.length !== 1 ? 's' : ''}</span>
    </div>
    ${catBlocks}
  </section>`;
}

function buildEnvSection(results) {
  const patterns = ['\\.env','ENV','Environment','Key Exposure','env-exposure','dotenv','env file'];
  const items    = results.filter(r => matchesAny(r.check, patterns));

  if (!items.length) {
    return `
    <section class="report-section fade-in">
      <div class="section-header">
        <div class="section-icon accent">📄</div>
        <h2>Arquivos .env e Variáveis de Ambiente Expostas</h2>
      </div>
      <div class="empty-card green">
        <span>✅</span>
        <span>Nenhum arquivo .env exposto encontrado</span>
      </div>
    </section>`;
  }

  const rows = items.map((f, i) => {
    const hasDetails = f.details != null && f.details !== '';
    const detailId   = `env-detail-${i}`;
    return `
      <div class="finding-row env-row" style="border-left-color:${severityColor(f.severity)};">
        <div class="finding-top">
          ${severityBadge(f.severity)}
          <span class="finding-name">${esc(f.check)}</span>
          ${hasDetails ? `<button class="toggle-btn no-print" onclick="toggleDetail('${detailId}')">detalhes ▾</button>` : ''}
        </div>
        <div class="finding-msg">${esc(f.message)}</div>
        ${hasDetails ? `<div id="${detailId}" class="detail-panel" style="display:none;"><pre>${fmtDetails(f.details)}</pre></div>` : ''}
      </div>`;
  }).join('');

  return `
  <section class="report-section fade-in">
    <div class="section-header">
      <div class="section-icon orange">📄</div>
      <h2>Arquivos .env e Variáveis de Ambiente Expostas</h2>
      <span class="section-count orange">${items.length} arquivo${items.length !== 1 ? 's' : ''}</span>
    </div>
    <div class="env-grid">
      ${rows}
    </div>
  </section>`;
}

function buildMetadataSection(auditData) {
  const { projectUrl, score, grade, evidence, duration, results, catalogData } = auditData;

  const techPatterns = ['Stack','Tech','Detector','Framework','CMS','CDN','Server','Headers','DNS','SSL','TLS'];
  const techItems    = (results || []).filter(r => matchesAny(r.check, techPatterns));

  const scanDate = evidence?.timestamp
    ? new Date(evidence.timestamp).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })
    : '—';

  // Core metadata rows
  const coreRows = [
    { icon: '🌐', key: 'URL Analisada',        value: projectUrl || '—' },
    { icon: '📅', key: 'Data do Scan',          value: scanDate },
    { icon: '⏱️', key: 'Duração',               value: duration || '—' },
    { icon: '📊', key: 'Score de Segurança',    value: typeof score === 'number' ? `${score}/100` : '—' },
    { icon: '🏷️', key: 'Grade',                 value: grade ? `${grade.grade} — ${grade.label}` : '—' },
    { icon: '🔍', key: 'Total de Verificações', value: (results || []).length },
  ];

  if (catalogData) {
    if (catalogData.tablesCount   != null) coreRows.push({ icon: '🗄️', key: 'Tabelas no Banco',    value: catalogData.tablesCount });
    if (catalogData.rpcCount      != null) coreRows.push({ icon: '⚙️', key: 'Funções RPC',         value: catalogData.rpcCount });
    if (catalogData.policiesCount != null) coreRows.push({ icon: '🛡️', key: 'Políticas RLS',       value: catalogData.policiesCount });
    if (catalogData.buckets       != null) coreRows.push({ icon: '📦', key: 'Storage Buckets',      value: Array.isArray(catalogData.buckets) ? catalogData.buckets.length : catalogData.buckets });
    // generic extra keys
    for (const [k, v] of Object.entries(catalogData)) {
      if (['tablesCount','rpcCount','policiesCount','buckets'].includes(k)) continue;
      if (typeof v === 'string' || typeof v === 'number') {
        coreRows.push({ icon: '📌', key: esc(k), value: v });
      }
    }
  }

  const metaRowsHtml = coreRows.map(r => `
    <div class="meta-row">
      <span class="meta-icon">${r.icon}</span>
      <span class="meta-key">${esc(String(r.key))}</span>
      <span class="meta-val">${esc(String(r.value))}</span>
    </div>`).join('');

  let techHtml = '';
  if (techItems.length) {
    techHtml = `
      <div class="tech-block">
        <div class="category-title">
          <span class="cat-icon">🔭</span>
          Tecnologias &amp; Infraestrutura Detectadas
          <span class="cat-count">${techItems.length}</span>
        </div>
        ${techItems.map((f, i) => {
          const hasDetails = f.details != null && f.details !== '';
          const detailId   = `tech-detail-${i}`;
          return `
          <div class="finding-row" style="border-left-color:${severityColor(f.severity)};">
            <div class="finding-top">
              ${severityBadge(f.severity)}
              <span class="finding-name">${esc(f.check)}</span>
              ${hasDetails ? `<button class="toggle-btn no-print" onclick="toggleDetail('${detailId}')">detalhes ▾</button>` : ''}
            </div>
            <div class="finding-msg">${esc(f.message)}</div>
            ${hasDetails ? `<div id="${detailId}" class="detail-panel" style="display:none;"><pre>${fmtDetails(f.details)}</pre></div>` : ''}
          </div>`;
        }).join('')}
      </div>`;
  }

  return `
  <section class="report-section fade-in">
    <div class="section-header">
      <div class="section-icon blue">🖥️</div>
      <h2>Metadados do Site Analisado</h2>
    </div>
    <div class="meta-grid">
      ${metaRowsHtml}
    </div>
    ${techHtml}
  </section>`;
}

function buildPIISection(results) {
  const patterns = ['CPF','CNPJ','RG','SSN','Email','Phone','Credit Card','PIX','CEP','Documento','Financeiro'];
  const items    = results.filter(r => matchesAny(r.check, patterns));

  if (!items.length) {
    return `
    <section class="report-section fade-in">
      <div class="section-header">
        <div class="section-icon blue">👤</div>
        <h2>Dados Pessoais (PII) Detectados</h2>
      </div>
      <div class="empty-card green">
        <span>✅</span>
        <span>Nenhum dado pessoal (PII) exposto detectado</span>
      </div>
    </section>`;
  }

  const tableRows = items.map(f => `
    <tr>
      <td class="pii-check">${esc(f.check)}</td>
      <td>${severityBadge(f.severity)}</td>
      <td class="pii-msg">${esc(f.message)}</td>
    </tr>`).join('');

  return `
  <section class="report-section fade-in">
    <div class="section-header">
      <div class="section-icon red">👤</div>
      <h2>Dados Pessoais (PII) Detectados</h2>
      <span class="section-count red">${items.length} registro${items.length !== 1 ? 's' : ''}</span>
    </div>
    <div class="table-wrap">
      <table class="pii-table">
        <thead>
          <tr>
            <th>Verificação</th>
            <th>Severidade</th>
            <th>Mensagem</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    </div>
  </section>`;
}

function buildFooter(evidence) {
  const auditId   = evidence?.auditId   || '—';
  const sha256    = evidence?.sha256    || '—';
  const timestamp = evidence?.timestamp
    ? new Date(evidence.timestamp).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })
    : new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' });

  return `
  <footer class="site-footer">
    <div class="footer-inner">
      <div class="footer-brand">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 1L3 5v6c0 5.25 3.75 10.14 9 11.25C17.25 21.14 21 16.25 21 11V5L12 1Z" fill="rgba(0,212,255,0.1)" stroke="#00d4ff" stroke-width="1.5"/>
          <path d="M9 12l2 2 4-4" stroke="#00d4ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        <span>Supabase Guard</span>
      </div>
      <div class="footer-evidence">
        <div class="evidence-row">
          <span class="evidence-label">Audit ID</span>
          <code class="evidence-val">${esc(auditId)}</code>
        </div>
        <div class="evidence-row">
          <span class="evidence-label">SHA-256</span>
          <code class="evidence-val hash">${esc(sha256)}</code>
        </div>
        <div class="evidence-row">
          <span class="evidence-label">Gerado em</span>
          <code class="evidence-val">${esc(timestamp)}</code>
        </div>
      </div>
      <div class="footer-nav no-print">
        <a href="/" class="footer-link">← Voltar ao painel principal</a>
      </div>
    </div>
    <div class="footer-disclaimer">
      Este relatório é confidencial e destinado exclusivamente ao proprietário do sistema auditado.
      Uso indevido ou distribuição não autorizada é proibida.
    </div>
  </footer>`;
}

// ── CSS ────────────────────────────────────────────────────────────

function buildCSS() {
  return `
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
  /* ── CSS Variables ── */
  :root {
    --dark:    #030308;
    --card:    #0a0a12;
    --border:  rgba(255,255,255,.07);
    --red:     #ef4444;
    --orange:  #f97316;
    --yellow:  #eab308;
    --green:   #22c55e;
    --blue:    #3b82f6;
    --purple:  #a855f7;
    --accent:  #00d4ff;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'Inter', sans-serif;
    --text:    #c8c8d4;
    --text-dim:#6b6b80;
    --radius:  12px;
    --radius-sm: 6px;
  }

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }

  body {
    background: var(--dark);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanlines overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,0,0,0.03) 2px,
      rgba(0,0,0,0.03) 4px
    );
    pointer-events: none;
    z-index: 0;
  }

  /* Ambient glow blob */
  body::after {
    content: '';
    position: fixed;
    top: -20vh;
    left: 50%;
    transform: translateX(-50%);
    width: 80vw;
    height: 50vh;
    background: radial-gradient(ellipse, rgba(0,212,255,0.04) 0%, transparent 70%);
    pointer-events: none;
    z-index: 0;
  }

  .page-wrap {
    position: relative;
    z-index: 1;
    max-width: 1160px;
    margin: 0 auto;
    padding: 0 1.5rem 4rem;
  }

  /* ── Print Button ── */
  .print-btn {
    position: fixed;
    top: 1.25rem;
    right: 1.5rem;
    z-index: 999;
    display: inline-flex;
    align-items: center;
    gap: .5rem;
    padding: .55rem 1.1rem;
    background: rgba(0,212,255,0.1);
    border: 1px solid rgba(0,212,255,0.35);
    border-radius: 8px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.78rem;
    cursor: pointer;
    transition: background .2s, box-shadow .2s;
    backdrop-filter: blur(10px);
  }
  .print-btn:hover {
    background: rgba(0,212,255,0.18);
    box-shadow: 0 0 18px rgba(0,212,255,0.25);
  }

  /* ── Header ── */
  .site-header {
    position: relative;
    padding: 3.5rem 0 2.5rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2.5rem;
    overflow: hidden;
  }
  .header-glow {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--accent), transparent);
    opacity: .5;
  }
  .header-inner {
    display: flex;
    align-items: flex-start;
    gap: 1.5rem;
  }
  .header-icon svg { filter: drop-shadow(0 0 14px rgba(0,212,255,0.5)); }
  .header-text { flex: 1; }
  .header-tag {
    font-family: var(--mono);
    font-size: 0.68rem;
    letter-spacing: .18em;
    color: var(--accent);
    text-transform: uppercase;
    margin-bottom: .5rem;
    opacity: .8;
  }
  .header-title {
    font-family: var(--mono);
    font-size: clamp(1.1rem, 3vw, 1.6rem);
    font-weight: 700;
    color: #f0f0f8;
    letter-spacing: .04em;
    line-height: 1.25;
    margin-bottom: .65rem;
    text-shadow: 0 0 30px rgba(0,212,255,0.2);
  }
  .header-url {
    display: inline-flex;
    align-items: center;
    gap: .4rem;
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--accent);
    opacity: .85;
    margin-bottom: .75rem;
    word-break: break-all;
  }
  .header-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    font-size: 0.78rem;
    color: var(--text-dim);
  }
  .header-meta span {
    display: inline-flex;
    align-items: center;
    gap: .35rem;
  }
  .score-badge {
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: .2rem .7rem;
    border: 1px solid;
    border-radius: 20px;
  }

  /* ── Summary Stats ── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }
  .stat-card {
    background: rgba(10,10,18,.8);
    backdrop-filter: blur(12px);
    border: 1px solid;
    border-radius: var(--radius);
    padding: 1.4rem 1.25rem;
    text-align: center;
    transition: transform .2s, box-shadow .2s;
  }
  .stat-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 32px rgba(0,0,0,.4);
  }
  .stat-icon { font-size: 1.5rem; margin-bottom: .4rem; }
  .stat-number {
    font-family: var(--mono);
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: .3rem;
  }
  .stat-label {
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: #f0f0f8;
    margin-bottom: .2rem;
  }
  .stat-desc { font-size: 0.7rem; color: var(--text-dim); }

  /* ── Report Sections ── */
  .report-section {
    margin-bottom: 3rem;
  }
  .section-header {
    display: flex;
    align-items: center;
    gap: .75rem;
    margin-bottom: 1.25rem;
    padding-bottom: .75rem;
    border-bottom: 1px solid var(--border);
  }
  .section-header h2 {
    font-family: var(--mono);
    font-size: 1rem;
    font-weight: 600;
    color: #e8e8f0;
    letter-spacing: .04em;
    flex: 1;
  }
  .section-icon {
    width: 32px;
    height: 32px;
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1rem;
    flex-shrink: 0;
  }
  .section-icon.red    { background: rgba(239,68,68,.12);  }
  .section-icon.orange { background: rgba(249,115,22,.12); }
  .section-icon.accent { background: rgba(0,212,255,.1);   }
  .section-icon.blue   { background: rgba(59,130,246,.12); }
  .section-count {
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: .15rem .55rem;
    border-radius: 20px;
    font-weight: 600;
    border: 1px solid;
  }
  .section-count.red    { color: var(--red);    border-color: rgba(239,68,68,.3);   background: rgba(239,68,68,.1);   }
  .section-count.orange { color: var(--orange); border-color: rgba(249,115,22,.3);  background: rgba(249,115,22,.1);  }

  /* ── Category Blocks ── */
  .category-block, .tech-block {
    background: rgba(10,10,18,.8);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .category-title {
    display: flex;
    align-items: center;
    gap: .6rem;
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 600;
    color: #d0d0e0;
    letter-spacing: .06em;
    text-transform: uppercase;
    margin-bottom: 1rem;
    padding-bottom: .6rem;
    border-bottom: 1px solid var(--border);
  }
  .cat-icon { font-size: 1rem; }
  .cat-count {
    margin-left: auto;
    font-size: 0.7rem;
    color: var(--text-dim);
    background: rgba(255,255,255,.06);
    padding: .1rem .45rem;
    border-radius: 10px;
  }

  /* ── Finding Rows ── */
  .finding-row {
    border-left: 3px solid;
    padding: .75rem 1rem;
    margin-bottom: .6rem;
    background: rgba(255,255,255,.02);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    transition: background .15s;
  }
  .finding-row:last-child { margin-bottom: 0; }
  .finding-row:hover { background: rgba(255,255,255,.04); }
  .finding-top {
    display: flex;
    align-items: center;
    gap: .6rem;
    flex-wrap: wrap;
    margin-bottom: .3rem;
  }
  .finding-name {
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 500;
    color: #e0e0f0;
    flex: 1;
  }
  .finding-msg {
    font-size: 0.8rem;
    color: var(--text-dim);
    line-height: 1.5;
  }

  /* ── Severity Badges ── */
  .sev-badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: .08em;
    padding: .15rem .5rem;
    border-radius: 4px;
    border: 1px solid;
    flex-shrink: 0;
  }

  /* ── Toggle / Detail Panel ── */
  .toggle-btn {
    margin-left: auto;
    background: rgba(255,255,255,.06);
    border: 1px solid rgba(255,255,255,.1);
    border-radius: 4px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.65rem;
    padding: .15rem .5rem;
    cursor: pointer;
    transition: background .15s;
    flex-shrink: 0;
  }
  .toggle-btn:hover { background: rgba(0,212,255,.12); }
  .detail-panel {
    margin-top: .7rem;
    background: rgba(0,0,0,.4);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    animation: slideDown .2s ease;
  }
  .detail-panel pre {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: #9999b8;
    padding: .9rem 1rem;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
    overflow-x: auto;
  }
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ── ENV Grid ── */
  .env-grid { display: flex; flex-direction: column; gap: .75rem; }
  .env-row {
    background: rgba(249,115,22,.04) !important;
  }

  /* ── Metadata Grid ── */
  .meta-grid {
    background: rgba(10,10,18,.8);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 1rem;
  }
  .meta-row {
    display: grid;
    grid-template-columns: 2rem 180px 1fr;
    align-items: center;
    gap: .75rem;
    padding: .7rem 1.1rem;
    border-bottom: 1px solid var(--border);
    transition: background .15s;
  }
  .meta-row:last-child { border-bottom: none; }
  .meta-row:hover { background: rgba(255,255,255,.03); }
  .meta-icon { font-size: 1rem; text-align: center; }
  .meta-key {
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--text-dim);
    letter-spacing: .04em;
  }
  .meta-val {
    font-family: var(--mono);
    font-size: 0.8rem;
    color: var(--accent);
    word-break: break-all;
  }

  /* ── PII Table ── */
  .table-wrap {
    background: rgba(10,10,18,.8);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .pii-table {
    width: 100%;
    border-collapse: collapse;
  }
  .pii-table thead tr {
    background: rgba(255,255,255,.04);
    border-bottom: 1px solid var(--border);
  }
  .pii-table th {
    font-family: var(--mono);
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-dim);
    padding: .75rem 1rem;
    text-align: left;
  }
  .pii-table tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background .15s;
  }
  .pii-table tbody tr:last-child { border-bottom: none; }
  .pii-table tbody tr:hover { background: rgba(255,255,255,.03); }
  .pii-table td {
    padding: .7rem 1rem;
    vertical-align: middle;
  }
  .pii-check {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: #d0d0e0;
  }
  .pii-msg {
    font-size: 0.78rem;
    color: var(--text-dim);
    line-height: 1.5;
  }

  /* ── Empty Cards ── */
  .empty-card {
    display: flex;
    align-items: center;
    gap: .75rem;
    padding: 1.25rem 1.5rem;
    border-radius: var(--radius);
    font-size: 0.85rem;
    font-weight: 500;
    border: 1px solid;
  }
  .empty-card.green {
    background: rgba(34,197,94,.07);
    border-color: rgba(34,197,94,.3);
    color: #22c55e;
  }

  /* ── Footer ── */
  .site-footer {
    margin-top: 4rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
  }
  .footer-inner {
    display: flex;
    align-items: flex-start;
    gap: 2rem;
    flex-wrap: wrap;
    margin-bottom: 1.5rem;
  }
  .footer-brand {
    display: flex;
    align-items: center;
    gap: .6rem;
    font-family: var(--mono);
    font-size: 0.85rem;
    font-weight: 600;
    color: var(--accent);
    opacity: .8;
  }
  .footer-evidence { flex: 1; display: flex; flex-direction: column; gap: .4rem; }
  .evidence-row {
    display: flex;
    align-items: baseline;
    gap: .75rem;
    flex-wrap: wrap;
  }
  .evidence-label {
    font-size: 0.7rem;
    font-weight: 600;
    letter-spacing: .08em;
    text-transform: uppercase;
    color: var(--text-dim);
    width: 70px;
    flex-shrink: 0;
  }
  .evidence-val {
    font-family: var(--mono);
    font-size: 0.73rem;
    color: #8888a8;
    word-break: break-all;
  }
  .evidence-val.hash {
    color: rgba(0,212,255,.5);
    font-size: 0.65rem;
  }
  .footer-nav { display: flex; align-items: center; }
  .footer-link {
    font-family: var(--mono);
    font-size: 0.78rem;
    color: var(--accent);
    text-decoration: none;
    opacity: .7;
    transition: opacity .2s;
  }
  .footer-link:hover { opacity: 1; }
  .footer-disclaimer {
    font-size: 0.7rem;
    color: var(--text-dim);
    opacity: .6;
    text-align: center;
    line-height: 1.7;
    padding-bottom: 1rem;
  }

  /* ── Fade-in Animations ── */
  .fade-in {
    opacity: 0;
    transform: translateY(16px);
    animation: fadeUp .5s ease forwards;
  }
  .fade-in:nth-child(1) { animation-delay: .05s; }
  .fade-in:nth-child(2) { animation-delay: .12s; }
  .fade-in:nth-child(3) { animation-delay: .19s; }
  .fade-in:nth-child(4) { animation-delay: .26s; }
  .fade-in:nth-child(5) { animation-delay: .33s; }
  .fade-in:nth-child(6) { animation-delay: .40s; }
  @keyframes fadeUp {
    to { opacity: 1; transform: translateY(0); }
  }

  /* ── Responsive ── */
  @media (max-width: 640px) {
    .header-inner { flex-direction: column; gap: 1rem; }
    .stats-grid { grid-template-columns: 1fr 1fr; }
    .meta-row { grid-template-columns: 2rem 1fr; }
    .meta-key { display: none; }
    .footer-inner { flex-direction: column; gap: 1rem; }
  }
  @media (max-width: 400px) {
    .stats-grid { grid-template-columns: 1fr; }
  }

  /* ── Print ── */
  @media print {
    body { background: #fff; color: #111; }
    body::before, body::after { display: none; }
    .no-print { display: none !important; }
    .site-header, .report-section, .site-footer { break-inside: avoid; }
    .stat-card, .category-block, .tech-block, .meta-grid, .table-wrap { break-inside: avoid; }
    .finding-row { border-left-width: 2px; }
    a { color: inherit; }
    .detail-panel { display: block !important; }
    .fade-in { opacity: 1 !important; transform: none !important; animation: none !important; }
    .header-title { font-size: 1.2rem; }
  }
</style>`;
}

// ── JS snippets ────────────────────────────────────────────────────

function buildJS() {
  return `
<script>
  function toggleDetail(id) {
    var el = document.getElementById(id);
    if (!el) return;
    var btn = el.previousElementSibling && el.previousElementSibling.classList.contains('toggle-btn')
      ? el.previousElementSibling
      : el.closest('.finding-top') && el.closest('.finding-top').querySelector('.toggle-btn');
    if (el.style.display === 'none' || el.style.display === '') {
      el.style.display = 'block';
      if (btn) btn.textContent = 'fechar ▴';
    } else {
      el.style.display = 'none';
      if (btn) btn.textContent = 'detalhes ▾';
    }
  }
</script>`;
}

// ── Main generator ─────────────────────────────────────────────────

function generateCredentialsReport(auditData) {
  const data    = auditData || {};
  const results = Array.isArray(data.results) ? data.results : [];

  const title    = `Credenciais Expostas — ${esc(data.projectUrl || 'Auditoria')}`;
  const css      = buildCSS();
  const header   = buildHeader(data);
  const summary  = buildSummaryRow(results);
  const creds    = buildCredentialSection(results);
  const envSec   = buildEnvSection(results);
  const metadata = buildMetadataSection(data);
  const pii      = buildPIISection(results);
  const footer   = buildFooter(data.evidence || {});
  const js       = buildJS();

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="robots" content="noindex, nofollow">
  <title>${title}</title>
  ${css}
</head>
<body>
  <div class="page-wrap">
    ${header}
    ${summary}
    ${creds}
    ${envSec}
    ${metadata}
    ${pii}
    ${footer}
  </div>
  ${js}
</body>
</html>`;
}

module.exports = { generateCredentialsReport };
