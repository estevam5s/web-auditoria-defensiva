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
    <div class="stat-card" style="border-color:${s.color}33;color:${s.color};box-shadow:0 4px 24px ${s.color}12,inset 0 0 40px ${s.color}06;">
      <div class="stat-icon">${s.icon}</div>
      <div class="stat-number">${s.value}</div>
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
      <div class="section-header red-accent">
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
    <div class="section-header red-accent">
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
      <div class="section-header orange-accent">
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
    <div class="section-header orange-accent">
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
    <div class="section-header blue-accent">
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
      <div class="section-header blue-accent">
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
    <div class="section-header red-accent">
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
    --dark:     #030308;
    --card:     #0a0a14;
    --card2:    #0d0d1a;
    --border:   rgba(255,255,255,.07);
    --border2:  rgba(255,255,255,.04);
    --red:      #ef4444;
    --orange:   #f97316;
    --yellow:   #eab308;
    --green:    #22c55e;
    --blue:     #3b82f6;
    --purple:   #a855f7;
    --accent:   #00d4ff;
    --accent2:  #00ff9f;
    --mono:    'JetBrains Mono', monospace;
    --sans:    'Inter', sans-serif;
    --text:    #c8c8d4;
    --text-dim: #5a5a70;
    --radius:   12px;
    --radius-sm: 6px;
    --radius-lg: 16px;
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
      rgba(0,0,0,0.025) 2px,
      rgba(0,0,0,0.025) 4px
    );
    pointer-events: none;
    z-index: 0;
  }

  /* Grid dot pattern */
  body::after {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      radial-gradient(circle, rgba(0,212,255,0.06) 1px, transparent 1px);
    background-size: 32px 32px;
    pointer-events: none;
    z-index: 0;
    opacity: .5;
  }

  .page-wrap {
    position: relative;
    z-index: 1;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1.5rem 5rem;
  }

  /* ── Print Button ── */
  .print-btn {
    position: fixed;
    top: 3.8rem;
    right: 1.5rem;
    z-index: 200;
    display: inline-flex;
    align-items: center;
    gap: .5rem;
    padding: .55rem 1.1rem;
    background: rgba(0,212,255,0.08);
    border: 1px solid rgba(0,212,255,0.3);
    border-radius: 8px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.75rem;
    cursor: pointer;
    transition: background .2s, box-shadow .2s;
    backdrop-filter: blur(14px);
  }
  .print-btn:hover {
    background: rgba(0,212,255,0.16);
    box-shadow: 0 0 20px rgba(0,212,255,0.2);
  }

  /* ── Top Nav ── */
  .top-nav {
    position: sticky;
    top: 0;
    z-index: 100;
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: .7rem 1.5rem;
    background: rgba(3,3,8,0.85);
    backdrop-filter: blur(20px) saturate(160%);
    border-bottom: 1px solid rgba(0,212,255,0.1);
    margin: 0 -1.5rem;
    box-shadow: 0 2px 20px rgba(0,0,0,0.4);
  }
  .top-nav-back {
    display: inline-flex;
    align-items: center;
    gap: .35rem;
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--accent);
    text-decoration: none;
    opacity: .7;
    transition: opacity .2s;
    flex-shrink: 0;
  }
  .top-nav-back:hover { opacity: 1; }
  .top-nav-breadcrumb {
    display: flex;
    align-items: center;
    gap: .5rem;
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--text-dim);
    flex: 1;
  }
  .top-nav-breadcrumb .sep { opacity: .4; }
  .crumb-active { color: var(--text); }
  .top-nav-status {
    display: flex;
    align-items: center;
    gap: .5rem;
    font-family: var(--mono);
    font-size: 0.65rem;
    color: var(--red);
    letter-spacing: .1em;
    text-transform: uppercase;
    opacity: .8;
  }
  .status-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--red);
    box-shadow: 0 0 8px var(--red);
    animation: pulse-dot 2s ease-in-out infinite;
    flex-shrink: 0;
  }
  @keyframes pulse-dot {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%       { opacity: .5; transform: scale(.8); }
  }

  /* ── Header Banner ── */
  .site-header {
    position: relative;
    padding: 3.5rem 2rem 3rem;
    margin: 1.5rem -1.5rem 2.5rem;
    overflow: hidden;
    background: linear-gradient(135deg, rgba(239,68,68,0.06) 0%, rgba(3,3,8,0) 50%, rgba(168,85,247,0.04) 100%);
    border: 1px solid rgba(239,68,68,0.12);
    border-radius: var(--radius-lg);
  }
  .header-bg-grid {
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(239,68,68,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(239,68,68,0.04) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }
  .header-bg-glow {
    position: absolute;
    top: -60px;
    right: 5%;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 65%);
    pointer-events: none;
    z-index: 0;
  }
  .header-bottom-line {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(90deg, transparent, rgba(239,68,68,0.5), rgba(168,85,247,0.4), transparent);
  }
  .header-inner {
    position: relative;
    z-index: 1;
    display: flex;
    align-items: flex-start;
    gap: 2rem;
  }
  .header-icon-wrap {
    position: relative;
    flex-shrink: 0;
    width: 72px;
    height: 72px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .header-icon-ring {
    position: absolute;
    inset: 0;
    border-radius: 50%;
    border: 1px solid rgba(239,68,68,0.4);
    animation: ring-spin 8s linear infinite;
    background: radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 70%);
  }
  @keyframes ring-spin {
    from { transform: rotate(0deg); }
    to   { transform: rotate(360deg); }
  }
  .header-icon-svg { filter: drop-shadow(0 0 16px rgba(239,68,68,0.5)); }
  .header-text { flex: 1; }
  .header-eyebrow {
    display: flex;
    align-items: center;
    gap: .75rem;
    font-family: var(--mono);
    font-size: 0.65rem;
    letter-spacing: .18em;
    color: var(--text-dim);
    text-transform: uppercase;
    margin-bottom: .7rem;
  }
  .eyebrow-pill {
    background: rgba(239,68,68,0.15);
    border: 1px solid rgba(239,68,68,0.4);
    color: var(--red);
    padding: .1rem .5rem;
    border-radius: 20px;
    font-size: 0.6rem;
    letter-spacing: .12em;
  }
  .header-title {
    font-family: var(--mono);
    font-size: clamp(1.2rem, 3.5vw, 2rem);
    font-weight: 700;
    color: #f0f0f8;
    letter-spacing: .03em;
    line-height: 1.2;
    margin-bottom: .9rem;
    text-shadow: 0 0 40px rgba(239,68,68,0.2);
  }
  .title-accent {
    color: var(--red);
    text-shadow: 0 0 30px rgba(239,68,68,0.4);
  }
  .header-url {
    display: inline-flex;
    align-items: center;
    gap: .5rem;
    font-family: var(--mono);
    font-size: 0.82rem;
    color: var(--accent);
    background: rgba(0,212,255,0.06);
    border: 1px solid rgba(0,212,255,0.15);
    border-radius: var(--radius-sm);
    padding: .3rem .75rem;
    margin-bottom: .9rem;
    word-break: break-all;
  }
  .header-meta {
    display: flex;
    align-items: center;
    flex-wrap: wrap;
    gap: .75rem;
    font-size: 0.76rem;
    color: var(--text-dim);
  }
  .meta-chip {
    display: inline-flex;
    align-items: center;
    gap: .35rem;
    background: rgba(255,255,255,.04);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: .25rem .65rem;
  }
  .score-badge {
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: .25rem .8rem;
    border: 1px solid;
    border-radius: 20px;
  }

  /* ── Summary Stats ── */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 1rem;
    margin-bottom: 2.5rem;
  }
  .stat-card {
    position: relative;
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid;
    border-radius: var(--radius);
    padding: 1.5rem 1.4rem;
    text-align: center;
    overflow: hidden;
    transition: transform .2s, box-shadow .25s;
  }
  .stat-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: currentColor;
    opacity: .5;
    border-radius: var(--radius) var(--radius) 0 0;
  }
  .stat-card:hover {
    transform: translateY(-4px);
    box-shadow: 0 12px 40px rgba(0,0,0,.5);
  }
  .stat-icon { font-size: 1.6rem; margin-bottom: .5rem; }
  .stat-number {
    font-family: var(--mono);
    font-size: 2.8rem;
    font-weight: 700;
    line-height: 1;
    margin-bottom: .35rem;
    text-shadow: 0 0 20px currentColor;
  }
  .stat-label {
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: #d0d0e0;
    margin-bottom: .25rem;
  }
  .stat-desc { font-size: 0.68rem; color: var(--text-dim); }

  /* ── Report Sections ── */
  .report-section {
    margin-bottom: 3rem;
  }
  .section-header {
    display: flex;
    align-items: center;
    gap: .8rem;
    margin-bottom: 1.25rem;
    padding: .85rem 1.1rem .85rem 1.25rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  }
  .section-header.red-accent    { border-left-color: var(--red);    }
  .section-header.orange-accent { border-left-color: var(--orange); }
  .section-header.blue-accent   { border-left-color: var(--blue);   }
  .section-header h2 {
    font-family: var(--mono);
    font-size: 0.92rem;
    font-weight: 600;
    color: #e8e8f4;
    letter-spacing: .04em;
    flex: 1;
  }
  .section-icon {
    width: 30px;
    height: 30px;
    border-radius: 7px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.95rem;
    flex-shrink: 0;
  }
  .section-icon.red    { background: rgba(239,68,68,.14);  border: 1px solid rgba(239,68,68,.25);  }
  .section-icon.orange { background: rgba(249,115,22,.14); border: 1px solid rgba(249,115,22,.25); }
  .section-icon.accent { background: rgba(0,212,255,.1);   border: 1px solid rgba(0,212,255,.2);   }
  .section-icon.blue   { background: rgba(59,130,246,.14); border: 1px solid rgba(59,130,246,.25); }
  .section-count {
    font-family: var(--mono);
    font-size: 0.7rem;
    padding: .15rem .6rem;
    border-radius: 20px;
    font-weight: 700;
    border: 1px solid;
  }
  .section-count.red    { color: var(--red);    border-color: rgba(239,68,68,.35);   background: rgba(239,68,68,.12);   }
  .section-count.orange { color: var(--orange); border-color: rgba(249,115,22,.35);  background: rgba(249,115,22,.12);  }

  /* ── Category Blocks ── */
  .category-block, .tech-block {
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.35rem;
    margin-bottom: 1rem;
    transition: border-color .2s;
  }
  .category-block:hover, .tech-block:hover {
    border-color: rgba(255,255,255,.12);
  }
  .category-title {
    display: flex;
    align-items: center;
    gap: .6rem;
    font-family: var(--mono);
    font-size: 0.78rem;
    font-weight: 600;
    color: #d8d8e8;
    letter-spacing: .07em;
    text-transform: uppercase;
    margin-bottom: 1rem;
    padding-bottom: .7rem;
    border-bottom: 1px solid var(--border);
  }
  .cat-icon { font-size: 1rem; }
  .cat-count {
    margin-left: auto;
    font-family: var(--mono);
    font-size: 0.68rem;
    color: var(--text-dim);
    background: rgba(255,255,255,.06);
    border: 1px solid rgba(255,255,255,.08);
    padding: .1rem .5rem;
    border-radius: 10px;
  }

  /* ── Finding Rows ── */
  .finding-row {
    border-left: 3px solid;
    padding: .8rem 1rem;
    margin-bottom: .5rem;
    background: rgba(255,255,255,.018);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    transition: background .15s, transform .1s;
  }
  .finding-row:last-child { margin-bottom: 0; }
  .finding-row:hover {
    background: rgba(255,255,255,.04);
    transform: translateX(2px);
  }
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
    color: #e4e4f4;
    flex: 1;
  }
  .finding-msg {
    font-size: 0.79rem;
    color: var(--text-dim);
    line-height: 1.55;
  }

  /* ── Severity Badges ── */
  .sev-badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 0.62rem;
    font-weight: 700;
    letter-spacing: .1em;
    padding: .15rem .55rem;
    border-radius: 4px;
    border: 1px solid;
    flex-shrink: 0;
    text-shadow: 0 0 8px currentColor;
  }

  /* ── Toggle / Detail Panel ── */
  .toggle-btn {
    margin-left: auto;
    background: rgba(255,255,255,.05);
    border: 1px solid rgba(255,255,255,.1);
    border-radius: 4px;
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.63rem;
    padding: .15rem .5rem;
    cursor: pointer;
    transition: background .15s, box-shadow .15s;
    flex-shrink: 0;
  }
  .toggle-btn:hover {
    background: rgba(0,212,255,.1);
    box-shadow: 0 0 8px rgba(0,212,255,.2);
  }
  .detail-panel {
    margin-top: .75rem;
    background: rgba(0,0,0,.5);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    overflow: hidden;
    animation: slideDown .2s ease;
  }
  .detail-panel pre {
    font-family: var(--mono);
    font-size: 0.71rem;
    color: #8888a8;
    padding: .9rem 1rem;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.65;
    overflow-x: auto;
  }
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-6px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* ── ENV Grid ── */
  .env-grid { display: flex; flex-direction: column; gap: .6rem; }
  .env-row { background: rgba(249,115,22,.035) !important; }

  /* ── Metadata Grid ── */
  .meta-grid {
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    margin-bottom: 1rem;
  }
  .meta-row {
    display: grid;
    grid-template-columns: 2.2rem 190px 1fr;
    align-items: center;
    gap: .75rem;
    padding: .75rem 1.2rem;
    border-bottom: 1px solid var(--border2);
    transition: background .15s;
  }
  .meta-row:last-child { border-bottom: none; }
  .meta-row:hover { background: rgba(0,212,255,.025); }
  .meta-icon { font-size: 1rem; text-align: center; }
  .meta-key {
    font-family: var(--mono);
    font-size: 0.73rem;
    color: var(--text-dim);
    letter-spacing: .04em;
  }
  .meta-val {
    font-family: var(--mono);
    font-size: 0.79rem;
    color: var(--accent);
    word-break: break-all;
  }

  /* ── PII Table ── */
  .table-wrap {
    background: var(--card);
    backdrop-filter: blur(12px);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .pii-table { width: 100%; border-collapse: collapse; }
  .pii-table thead tr {
    background: rgba(255,255,255,.04);
    border-bottom: 1px solid var(--border);
  }
  .pii-table th {
    font-family: var(--mono);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--text-dim);
    padding: .8rem 1rem;
    text-align: left;
  }
  .pii-table tbody tr {
    border-bottom: 1px solid var(--border2);
    transition: background .15s;
  }
  .pii-table tbody tr:last-child { border-bottom: none; }
  .pii-table tbody tr:hover { background: rgba(59,130,246,.04); }
  .pii-table td { padding: .72rem 1rem; vertical-align: middle; }
  .pii-check {
    font-family: var(--mono);
    font-size: 0.77rem;
    color: #d4d4e8;
  }
  .pii-msg {
    font-size: 0.77rem;
    color: var(--text-dim);
    line-height: 1.5;
  }

  /* ── Empty Cards ── */
  .empty-card {
    display: flex;
    align-items: center;
    gap: .85rem;
    padding: 1.4rem 1.6rem;
    border-radius: var(--radius);
    font-size: 0.83rem;
    font-weight: 500;
    border: 1px solid;
  }
  .empty-card.green {
    background: rgba(34,197,94,.06);
    border-color: rgba(34,197,94,.25);
    color: #22c55e;
    box-shadow: 0 0 20px rgba(34,197,94,.05), inset 0 1px 0 rgba(34,197,94,.08);
  }

  /* ── Footer ── */
  .site-footer {
    margin-top: 4rem;
    padding: 2rem 2rem 1.5rem;
    background: rgba(8,8,16,.6);
    backdrop-filter: blur(20px);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    box-shadow: 0 -4px 40px rgba(0,0,0,.3), inset 0 1px 0 rgba(255,255,255,.03);
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
  .footer-evidence { flex: 1; display: flex; flex-direction: column; gap: .45rem; }
  .evidence-row {
    display: flex;
    align-items: baseline;
    gap: .75rem;
    flex-wrap: wrap;
  }
  .evidence-label {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: .1em;
    text-transform: uppercase;
    color: var(--text-dim);
    width: 72px;
    flex-shrink: 0;
  }
  .evidence-val {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: #7878a0;
    word-break: break-all;
  }
  .evidence-val.hash {
    color: rgba(0,212,255,.45);
    font-size: 0.64rem;
  }
  .footer-nav { display: flex; align-items: center; }
  .footer-link {
    font-family: var(--mono);
    font-size: 0.76rem;
    color: var(--accent);
    text-decoration: none;
    opacity: .65;
    transition: opacity .2s;
  }
  .footer-link:hover { opacity: 1; }
  .footer-disclaimer {
    font-size: 0.68rem;
    color: var(--text-dim);
    opacity: .55;
    text-align: center;
    line-height: 1.7;
    padding-top: 1rem;
    border-top: 1px solid var(--border2);
  }

  /* ── Fade-in Animations ── */
  .fade-in {
    opacity: 0;
    transform: translateY(18px);
    animation: fadeUp .55s ease forwards;
  }
  .fade-in:nth-child(1) { animation-delay: .05s; }
  .fade-in:nth-child(2) { animation-delay: .13s; }
  .fade-in:nth-child(3) { animation-delay: .21s; }
  .fade-in:nth-child(4) { animation-delay: .29s; }
  .fade-in:nth-child(5) { animation-delay: .37s; }
  .fade-in:nth-child(6) { animation-delay: .45s; }
  @keyframes fadeUp {
    to { opacity: 1; transform: translateY(0); }
  }

  /* ── Responsive ── */
  @media (max-width: 768px) {
    .site-header { margin: 1rem -1.5rem; padding: 2.5rem 1.5rem 2rem; }
    .header-inner { flex-direction: column; gap: 1.25rem; }
    .header-icon-wrap { width: 56px; height: 56px; }
  }
  @media (max-width: 640px) {
    .stats-grid { grid-template-columns: 1fr 1fr; }
    .meta-row { grid-template-columns: 2rem 1fr; }
    .meta-key { display: none; }
    .footer-inner { flex-direction: column; gap: 1rem; }
    .top-nav-status { display: none; }
  }
  @media (max-width: 400px) {
    .stats-grid { grid-template-columns: 1fr; }
  }

  /* ── Print ── */
  @media print {
    body { background: #fff; color: #111; }
    body::before, body::after { display: none; }
    .no-print { display: none !important; }
    .top-nav { display: none; }
    .site-header {
      background: #f8f8f8 !important;
      border: 1px solid #ccc !important;
      padding: 1.5rem !important;
    }
    .header-bg-grid, .header-bg-glow, .header-icon-ring { display: none; }
    .header-title, .title-accent { color: #111 !important; text-shadow: none !important; }
    .header-url { background: #f0f0f0 !important; border-color: #ccc !important; color: #0066cc !important; }
    .stat-card { background: #f8f8f8 !important; border-color: #ddd !important; break-inside: avoid; }
    .stat-number { text-shadow: none !important; }
    .report-section, .site-footer { break-inside: avoid; }
    .category-block, .tech-block, .meta-grid, .table-wrap { break-inside: avoid; background: #fafafa !important; border-color: #ddd !important; }
    .site-footer { background: #f8f8f8 !important; border-color: #ddd !important; }
    .section-header { background: #f0f0f0 !important; border-color: #ddd !important; }
    .finding-row { background: #fafafa !important; }
    a { color: #0066cc !important; }
    .detail-panel { display: block !important; background: #f4f4f4 !important; }
    .detail-panel pre { color: #333 !important; }
    .fade-in { opacity: 1 !important; transform: none !important; animation: none !important; }
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
