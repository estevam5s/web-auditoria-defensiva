/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Consulting Proposal HTML Generator
   Generates a white-theme professional consulting document from audit data.
   ═══════════════════════════════════════════════════════════════════ */

'use strict';

// ── HTML Escape ────────────────────────────────────────────────────
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Severity helpers ───────────────────────────────────────────────
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_LABELS = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MÉDIO', low: 'BAIXO', info: 'INFO' };
const SEV_COLORS = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280' };

function maxSeverity(items) {
  let best = 5;
  for (const item of items) best = Math.min(best, SEV_ORDER[item.severity] ?? 4);
  return Object.keys(SEV_ORDER)[best] || 'info';
}

// ── Group definitions ──────────────────────────────────────────────
const CONSULT_GROUPS = [
  { group: 'rls',              pattern: /RLS|Row Level/i,                                      label: 'Row Level Security (RLS)' },
  { group: 'service-key',      pattern: /Service Key/i,                                        label: 'Service Key / Chave de Serviço' },
  { group: 'auth',             pattern: /Auth(?!or)|Open Signup/i,                             label: 'Autenticação' },
  { group: 'jwt',              pattern: /JWT/i,                                                 label: 'Configuração JWT' },
  { group: 'bundle-keys',      pattern: /Bundle Key/i,                                         label: 'Chaves em Bundle JS' },
  { group: 'credential',       pattern: /Credential|PII/i,                                     label: 'Credenciais / PII' },
  { group: 'env',              pattern: /\.env|Key Exposure/i,                                 label: 'Arquivos .env Expostos' },
  { group: 'rest',             pattern: /REST|RPC/i,                                            label: 'REST API / RPC' },
  { group: 'cors',             pattern: /CORS/i,                                                label: 'Configuração CORS' },
  { group: 'storage',          pattern: /Storage/i,                                             label: 'Storage Buckets' },
  { group: 'graphql',          pattern: /GraphQL/i,                                             label: 'GraphQL' },
  { group: 'edge',             pattern: /Edge/i,                                                label: 'Edge Functions' },
  { group: 'vuln',             pattern: /Vulnerability/i,                                       label: 'Vulnerabilidades Gerais' },
  { group: 'routes',           pattern: /Route|Hidden/i,                                        label: 'Rotas Ocultas' },
  { group: 'source',           pattern: /Source Code/i,                                         label: 'Código-Fonte' },
  { group: 'sensitive',        pattern: /Sensitive Data/i,                                      label: 'Dados Sensíveis' },
  { group: 'hardening',        pattern: /Hardening|Rate Limit/i,                               label: 'Hardening / Rate Limiting' },
  { group: 'dns',              pattern: /DNS/i,                                                  label: 'DNS' },
  { group: 'realtime',         pattern: /Realtime/i,                                            label: 'Realtime' },
  { group: 'ddos',             pattern: /DDoS|ATTACK/i,                                         label: 'Proteção DDoS' },
  { group: 'brute-force',      pattern: /Brute Force|Lockout/i,                                label: 'Brute Force / Lockout' },
  { group: 'ssl',              pattern: /SSL|TLS/i,                                             label: 'SSL / TLS' },
  { group: 'security-headers', pattern: /Security Headers/i,                                   label: 'Headers de Segurança' },
  { group: 'hydra',            pattern: /Hydra/i,                                               label: 'Simulação Hydra' },
  { group: 'network',          pattern: /Network|Tailscale|VPN/i,                              label: 'Rede / Tailscale' },
  { group: 'dos-advanced',     pattern: /DoS Avançado|Slowloris|ReDoS|Connection Exhaustion/i, label: 'DoS Avançado' },
  { group: 'port-scan',        pattern: /Port Scan|Serviços.*Expostos|Portas.*Abertas/i,       label: 'Port Scan' },
  { group: 'git-exposure',     pattern: /Git Exposure|\.git|docker-compose/i,                  label: 'Exposição de Git' },
  { group: 'open-redirect',    pattern: /Open Redirect|Redirecionamento.*Aberto/i,             label: 'Open Redirect' },
  { group: 'saas-pii',         pattern: /SaaS Customer|Customer Data/i,                        label: 'Dados de Clientes (SaaS PII)' },
];

function getGroup(checkName) {
  for (const { group, pattern } of CONSULT_GROUPS) {
    if (pattern.test(checkName)) return group;
  }
  return 'other';
}

function getGroupLabel(group) {
  return (CONSULT_GROUPS.find(g => g.group === group) || {}).label || 'Outros';
}

// ── Embedded CSS ───────────────────────────────────────────────────
const CSS = `
/* ── Reset & Base ── */
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;background:#f0f2f5;color:#1f2937;font-size:14px;line-height:1.65}

/* ── Print / Export Button ── */
.print-btn{
  position:fixed;top:24px;right:24px;z-index:9999;
  background:linear-gradient(135deg,#1a2744 0%,#2d4a8a 100%);
  color:#fff;border:none;padding:10px 22px;border-radius:8px;
  cursor:pointer;font-size:13px;font-weight:700;letter-spacing:.3px;
  box-shadow:0 4px 14px rgba(26,39,68,.35);transition:all .2s ease;
  display:flex;align-items:center;gap:7px
}
.print-btn:hover{background:linear-gradient(135deg,#2d4a8a 0%,#3b5faa 100%);box-shadow:0 6px 18px rgba(26,39,68,.45);transform:translateY(-1px)}
.print-btn:active{transform:translateY(0);box-shadow:0 3px 10px rgba(26,39,68,.3)}

/* ── Cover Page ── */
.cover{
  background:#fff;
  border-top:6px solid #1a2744;
  padding:60px 56px 52px;
  max-width:none;
  position:relative;
  overflow:hidden
}
.cover::before{
  content:'';position:absolute;top:0;right:0;
  width:320px;height:320px;
  background:radial-gradient(circle at top right,rgba(45,74,138,.07) 0%,transparent 70%);
  pointer-events:none
}
.cover-top-bar{
  display:flex;justify-content:space-between;align-items:flex-start;
  margin-bottom:44px;padding-bottom:28px;border-bottom:1px solid #e5e7eb
}
.cover-consultant-name{font-size:17px;font-weight:700;color:#1a2744;margin-bottom:3px}
.cover-consultant-detail{font-size:13px;color:#6b7280;line-height:1.7}
.cover-date-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:1px;margin-bottom:3px}
.cover-date-value{font-size:13px;font-weight:600;color:#374151;text-align:right}
.cover-category{font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:8px}
.cover-title{font-size:30px;font-weight:800;color:#1a2744;line-height:1.25;word-break:break-all;margin-bottom:32px}
.cover-score-row{display:flex;align-items:center;gap:28px;flex-wrap:wrap}

/* ── Score Circle ── */
.score-circle{
  width:116px;height:116px;border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  color:#fff;flex-shrink:0;
  box-shadow:0 6px 20px rgba(0,0,0,.2)
}
.score-num{font-size:36px;font-weight:800;line-height:1;letter-spacing:-1px}
.score-lbl{font-size:11px;opacity:.9;margin-top:1px;font-weight:600;letter-spacing:.3px}
.cover-score-info-title{font-size:19px;font-weight:800;color:#1a2744;margin-bottom:6px}

/* ── Sections ── */
section{
  background:#fff;
  max-width:960px;margin:20px auto;
  padding:40px 48px;
  border-radius:10px;
  box-shadow:0 2px 12px rgba(0,0,0,.06);
  border:1px solid #e9ecef
}
section.cover{background:#fff;border-radius:0;box-shadow:none;border:none;max-width:none;margin:0}

/* ── Typography ── */
h1{font-size:26px;font-weight:800;color:#1a2744;margin-bottom:6px;line-height:1.3}
h2{
  font-size:18px;font-weight:700;color:#1a2744;
  margin-bottom:20px;padding-bottom:12px;
  border-bottom:2px solid #1a2744;
  display:flex;align-items:center;gap:10px
}
h2 .sec-icon{font-size:20px}
h3{font-size:14px;font-weight:700;color:#1a2744;margin-bottom:6px}
p{margin-bottom:12px;color:#374151;line-height:1.7}
strong{color:#1a2744}

/* ── Summary callout ── */
.summary-box{
  background:#f8fafd;border-left:4px solid #1a2744;
  border-radius:0 8px 8px 0;padding:18px 22px;margin-bottom:20px;
  font-size:14px;color:#374151;line-height:1.75
}
.summary-stats{
  display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:20px
}
.stat-card{
  background:#fff;border:1px solid #e5e7eb;border-radius:8px;
  padding:14px 16px;text-align:center
}
.stat-card .stat-val{font-size:24px;font-weight:800;color:#1a2744;line-height:1}
.stat-card .stat-label{font-size:11px;color:#6b7280;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}

/* ── Tables ── */
.table-wrap{overflow-x:auto;margin-bottom:20px;border-radius:8px;border:1px solid #e5e7eb}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{
  background:#1a2744;color:#fff;
  padding:11px 14px;text-align:left;
  font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.6px
}
thead th:first-child{border-radius:8px 0 0 0}
thead th:last-child{border-radius:0 8px 0 0}
td{padding:10px 14px;border-bottom:1px solid #f0f2f5;vertical-align:top;color:#374151}
tr:last-child td{border-bottom:none}
tr:hover td{background:#f8fafd}
tfoot td{background:#1a2744!important;color:#fff!important;font-weight:700;border-bottom:none;padding:12px 14px}
tfoot tr td:last-child{font-size:15px}

/* ── Badges ── */
.badge{
  display:inline-block;padding:3px 9px;border-radius:20px;
  font-size:10px;font-weight:800;color:#fff;letter-spacing:.5px;
  white-space:nowrap
}

/* ── Group header ── */
.group-hdr{
  display:flex;align-items:center;gap:10px;
  margin-top:28px;margin-bottom:10px;
  padding:10px 14px;
  background:#f8fafd;border-left:3px solid #1a2744;
  border-radius:0 6px 6px 0
}
.group-hdr h3{margin:0;font-size:14px;font-weight:700;color:#1a2744}

/* ── Services ── */
.service-note{font-size:12px;color:#6b7280;font-style:italic;margin-top:8px}
.service-total-label{font-size:13px}

/* ── Controls grid ── */
.controls-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));
  gap:6px 16px;margin-top:4px
}
.ctrl-item{
  display:flex;align-items:center;gap:8px;
  padding:6px 10px;font-size:13px;
  background:#f0fdf4;border-radius:6px;
  border:1px solid #bbf7d0
}
.ctrl-check{font-size:14px;font-weight:800;color:#16a34a;flex-shrink:0}

/* ── Empty states ── */
.empty-ok{
  background:#f0fdf4;border:1px solid #86efac;border-radius:8px;
  padding:16px 20px;color:#166534;font-weight:600;
  display:flex;align-items:center;gap:10px;font-size:14px
}
.empty-ok::before{content:'✓';font-size:18px;color:#16a34a;flex-shrink:0}
.empty-warn{
  background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;
  padding:16px 20px;color:#92400e;font-weight:600;
  display:flex;align-items:center;gap:10px;font-size:14px
}

/* ── Next Steps list ── */
.next-steps-list{list-style:none;padding:0;counter-reset:steps}
.next-steps-list li{
  counter-increment:steps;
  padding:14px 16px 14px 54px;
  position:relative;
  border:1px solid #e5e7eb;border-radius:8px;
  margin-bottom:10px;background:#fff
}
.next-steps-list li::before{
  content:counter(steps);
  position:absolute;left:14px;top:50%;transform:translateY(-50%);
  width:26px;height:26px;border-radius:50%;
  background:#1a2744;color:#fff;
  display:flex;align-items:center;justify-content:center;
  font-size:12px;font-weight:800
}
.next-step-title{display:flex;align-items:center;gap:8px;margin-bottom:3px;font-weight:700;color:#1a2744;font-size:14px}
.next-step-desc{font-size:13px;color:#6b7280}

/* ── Footer ── */
.footer-wrap{
  background:#1a2744;color:#cbd5e1;
  padding:36px 56px;font-size:13px;margin-top:0
}
.footer-grid{display:grid;grid-template-columns:1fr 1fr;gap:32px;margin-bottom:20px}
.footer-section-label{
  font-size:10px;text-transform:uppercase;letter-spacing:1.5px;
  color:#64748b;margin-bottom:10px;font-weight:700
}
.footer-name{font-size:15px;font-weight:800;color:#e2e8f0;margin-bottom:4px}
.footer-detail{color:#94a3b8;margin-bottom:3px;font-size:13px}
.footer-doc-item{margin-bottom:4px;color:#94a3b8}
.footer-doc-label{color:#64748b;font-size:11px}
.hash{font-family:'Courier New',Courier,monospace;font-size:11px;color:#475569}
.disclaimer{
  font-size:11px;color:#475569;font-style:italic;
  border-top:1px solid #2d4a6e;padding-top:16px;margin-top:4px;line-height:1.7
}

/* ── Divider ── */
.page-break-hint{height:20px;background:transparent}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#f1f5f9}
::-webkit-scrollbar-thumb{background:#94a3b8;border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:#64748b}

/* ── Print Media ── */
@media print{
  body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .print-btn{display:none!important}
  section{
    page-break-inside:avoid;max-width:none;
    box-shadow:none!important;border:none!important;
    margin:0;border-radius:0;padding:32px 40px
  }
  section.cover{page-break-before:avoid}
  section+section{page-break-before:always}
  h2{page-break-after:avoid}
  .group-hdr{page-break-after:avoid}
  tr{page-break-inside:avoid}
  thead{display:table-header-group}
  tfoot{display:table-footer-group}
  .table-wrap{border:1px solid #e5e7eb!important}
  .footer-wrap{page-break-before:always;margin:0}
  .summary-stats{grid-template-columns:repeat(4,1fr)}
  .controls-grid{grid-template-columns:repeat(2,1fr)}
  .ctrl-item{background:#f0fdf4!important;-webkit-print-color-adjust:exact}
  .empty-ok{background:#f0fdf4!important;-webkit-print-color-adjust:exact}
}
`;

// ── Section: Cover ─────────────────────────────────────────────────
function buildCover(projectUrl, auditDate, score, grade, productionReady, cfg) {
  const scoreColor = score >= 88 ? '#16a34a' : score >= 52 ? '#ea580c' : '#dc2626';
  const pv = productionReady || {};
  const pvColor = pv.color || '#6b7280';

  const contactLines = [
    cfg.company ? `<div style="font-weight:600;font-size:16px;margin-bottom:2px">${esc(cfg.company)}</div>` : '',
    cfg.email   ? `<div style="color:#4b5563">✉ ${esc(cfg.email)}</div>` : '',
    cfg.phone   ? `<div style="color:#4b5563">✆ ${esc(cfg.phone)}</div>` : '',
  ].filter(Boolean).join('');

  return `<section class="cover">
  <div class="cover-top-bar">
    <div>
      <div class="cover-consultant-name">${esc(cfg.name)}</div>
      <div class="cover-consultant-detail">${contactLines}</div>
    </div>
    <div style="text-align:right">
      <div class="cover-date-label">Emitido em</div>
      <div class="cover-date-value">${esc(auditDate)}</div>
    </div>
  </div>

  <div class="cover-category">Proposta de Consultoria em Segurança</div>
  <div class="cover-title">${esc(projectUrl)}</div>

  <div class="cover-score-row">
    <div class="score-circle" style="background:${scoreColor}">
      <span class="score-num">${score}</span>
      <span class="score-lbl">Grau ${esc(grade.grade || '?')}</span>
    </div>
    <div>
      <div class="cover-score-info-title">${esc(grade.label || '')}</div>
      <span class="badge" style="background:${esc(pvColor)};color:#fff;font-size:11px;padding:5px 16px;border-radius:20px">${esc(pv.label || '')}</span>
    </div>
  </div>
</section>`;
}

// ── Section: Executive Summary ─────────────────────────────────────
function buildSummary(projectUrl, auditDate, score, grade, failed, warnings, totalChecks, duration) {
  let fraseFinal;
  if (failed === 0 && warnings === 0) {
    fraseFinal = 'Nenhuma vulnerabilidade foi detectada nas verificações realizadas.';
  } else if (score >= 88) {
    fraseFinal = 'O sistema apresenta boas práticas de segurança com pontos de melhoria menores.';
  } else if (score >= 72) {
    fraseFinal = 'Recomenda-se correção dos itens identificados antes de um lançamento em produção.';
  } else if (score >= 52) {
    fraseFinal = 'Atenção necessária: existem vulnerabilidades que devem ser corrigidas com prioridade.';
  } else if (score >= 32) {
    fraseFinal = 'Risco elevado: falhas críticas detectadas requerem ação imediata.';
  } else {
    fraseFinal = 'Situação crítica: o sistema não deve ser mantido em produção até a resolução das falhas identificadas.';
  }

  return `<section>
  <h2><span class="sec-icon">📊</span> Sumário Executivo</h2>
  <div class="summary-box">
    A auditoria de segurança realizada em <strong>${esc(projectUrl)}</strong> em ${esc(auditDate)}
    identificou <strong>${failed}</strong> falha(s) e <strong>${warnings}</strong> alerta(s)
    em um total de <strong>${totalChecks}</strong> verificações, com duração de ${esc(duration)}.
    O score de segurança obtido foi <strong>${score}/100</strong>
    (Grau <strong>${esc(grade.grade || '?')}</strong> — ${esc(grade.label || '')}).
    ${esc(fraseFinal)}
  </div>
  <div class="summary-stats">
    <div class="stat-card">
      <div class="stat-val" style="color:#dc2626">${failed}</div>
      <div class="stat-label">Falhas</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#ea580c">${warnings}</div>
      <div class="stat-label">Alertas</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#1a2744">${totalChecks}</div>
      <div class="stat-label">Verificações</div>
    </div>
    <div class="stat-card">
      <div class="stat-val" style="color:#16a34a">${score}</div>
      <div class="stat-label">Score / 100</div>
    </div>
  </div>
</section>`;
}

// ── Section: Vulnerability Assessment ─────────────────────────────
function buildVulnerabilities(results) {
  const issues = results.filter(r => r.status === 'FAIL' || r.status === 'WARN');

  if (issues.length === 0) {
    return `<section>
  <h2><span class="sec-icon">🔍</span> Levantamento de Vulnerabilidades</h2>
  <div class="empty-ok">Nenhuma vulnerabilidade encontrada — sistema em conformidade.</div>
</section>`;
  }

  // Group by semantic category
  const grouped = {};
  for (const r of issues) {
    const g = getGroup(r.check || '');
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(r);
  }

  let html = `<section><h2><span class="sec-icon">🔍</span> Levantamento de Vulnerabilidades por Categoria</h2>`;

  for (const [group, items] of Object.entries(grouped)) {
    const maxSev  = maxSeverity(items);
    const sevColor = SEV_COLORS[maxSev] || '#6b7280';
    const sevLabel = SEV_LABELS[maxSev] || maxSev.toUpperCase();
    const label    = getGroupLabel(group);

    html += `<div class="group-hdr">
      <h3>${esc(label)}</h3>
      <span class="badge" style="background:${sevColor}">${sevLabel}</span>
      <span style="margin-left:auto;font-size:12px;color:#6b7280">${items.length} item(s)</span>
    </div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Verificação</th><th>Status</th><th>Severidade</th><th>Descrição</th></tr></thead>
      <tbody>`;

    for (const r of items) {
      const sc = SEV_COLORS[r.severity] || '#6b7280';
      const sl = SEV_LABELS[r.severity] || esc((r.severity || '').toUpperCase());
      const statusColor = r.status === 'FAIL' ? '#dc2626' : '#ea580c';
      html += `<tr>
        <td style="font-weight:600;color:#1a2744;min-width:160px">${esc(r.check || '')}</td>
        <td style="min-width:70px"><span class="badge" style="background:${statusColor}">${esc(r.status)}</span></td>
        <td style="min-width:90px"><span class="badge" style="background:${sc}">${sl}</span></td>
        <td style="color:#4b5563">${esc(r.message || '')}</td>
      </tr>`;
    }

    html += '</tbody></table></div>';
  }

  html += '</section>';
  return html;
}

// ── Section: Consulting Services ───────────────────────────────────
const SERVICE_CATALOG = [
  { key: 'rls',      label: 'Implementação e Revisão de RLS',       desc: 'Configuração de políticas Row Level Security para todas as tabelas expostas.', groups: ['rls'],                                          price: p => p.rls },
  { key: 'auth',     label: 'Hardening de Autenticação e JWT',       desc: 'Revisão de configurações de autenticação, JWT, signup e controle de sessão.',   groups: ['auth', 'jwt'],                                  price: p => p.auth },
  { key: 'env',      label: 'Correção de Credenciais Expostas',      desc: 'Remoção e rotação de credenciais expostas publicamente ou em bundles JS.',      groups: ['env', 'bundle-keys', 'credential', 'service-key'], price: p => p.env },
  { key: 'headers',  label: 'Configuração de Headers e CORS',        desc: 'Implementação de headers de segurança HTTP e política CORS restritiva.',        groups: ['cors', 'security-headers', 'hardening'],          price: p => p.headers },
  { key: 'ssl',      label: 'Auditoria e Configuração SSL/TLS',      desc: 'Revisão de certificados, ciphers e configuração de transporte seguro.',         groups: ['ssl'],                                           price: p => p.hourly * 6 },
  { key: 'ddos',     label: 'Proteção contra Ataques',               desc: 'Implementação de rate limiting, proteção DDoS, bloqueio de brute force.',       groups: ['ddos', 'brute-force', 'hydra', 'dos-advanced'],  price: p => p.hourly * 12 },
  { key: 'infra',    label: 'Hardening de Infraestrutura/Rede',      desc: 'Fechamento de portas desnecessárias e hardening de configuração de rede.',       groups: ['port-scan', 'network'],                          price: p => p.hourly * 8 },
  { key: 'git',      label: 'Remoção de Exposição de Código/Git',    desc: 'Remoção de arquivos sensíveis acessíveis publicamente e exposição de código.',   groups: ['git-exposure', 'source'],                        price: p => p.hourly * 3 },
  { key: 'pii',      label: 'Proteção de Dados de Clientes (PII)',   desc: 'Revisão de tabelas com dados pessoais e implementação de controles de acesso.',  groups: ['saas-pii', 'sensitive'],                         price: p => p.hourly * 8 },
  { key: 'pentest',  label: 'Pentest Completo e Relatório Final',    desc: 'Teste de penetração completo com relatório executivo e técnico detalhado.',      groups: [],                                                price: p => p.pentest },
];

function buildServices(results, prices) {
  const failedGroups = new Set(
    results
      .filter(r => r.status === 'FAIL' || r.status === 'WARN')
      .map(r => getGroup(r.check || ''))
  );
  const hasFailures = failedGroups.size > 0;

  const activeServices = SERVICE_CATALOG.filter(s =>
    s.key === 'pentest' || s.groups.some(g => failedGroups.has(g))
  );

  let total = 0;
  let rows = '';
  for (const s of activeServices) {
    const raw = s.price(prices);
    const value = (typeof raw === 'number' && isFinite(raw) && raw >= 0) ? raw : 0;
    total += value;
    const estimateLabel = s.key === 'pentest' ? '24h' :
      s.key === 'ssl'    ? '6h'  :
      s.key === 'ddos'   ? '12h' :
      s.key === 'infra'  ? '8h'  :
      s.key === 'git'    ? '3h'  :
      s.key === 'pii'    ? '8h'  :
      s.key === 'env'    ? '6h'  :
      s.key === 'headers'? '4h'  :
      s.key === 'auth'   ? '8h'  :
      s.key === 'rls'    ? '10h' : '—';
    rows += `<tr>
      <td><strong>${esc(s.label)}</strong></td>
      <td style="color:#6b7280">${esc(s.desc)}</td>
      <td style="text-align:center">${estimateLabel}</td>
      <td style="text-align:right;font-weight:600">R$ ${value.toLocaleString('pt-BR')}</td>
    </tr>`;
  }

  const onlyPentest = !hasFailures;
  const extraNote = onlyPentest
    ? '<p class="empty-ok" style="margin-top:12px">Nenhuma vulnerabilidade crítica detectada. Recomendamos pentest preventivo para validação contínua.</p>'
    : '';

  return `<section>
  <h2><span class="sec-icon">💼</span> Serviços de Consultoria Recomendados</h2>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Serviço</th><th>Descrição</th><th style="text-align:center;white-space:nowrap">Estimativa</th><th style="text-align:right;white-space:nowrap">Valor (R$)</th></tr></thead>
    <tbody>
      ${rows}
    </tbody>
    <tfoot>
      <tr><td colspan="3" class="service-total-label"><strong>Total Estimado</strong></td><td style="text-align:right;font-size:16px">R$ ${total.toLocaleString('pt-BR')}</td></tr>
    </tfoot>
  </table>
  </div>
  ${extraNote}
  <p class="service-note">* Valores estimados. Proposta formal com escopo detalhado disponível mediante solicitação. Os preços podem variar conforme complexidade do projeto.</p>
</section>`;
}

// ── Section: Approved Controls ─────────────────────────────────────
function buildControls(results) {
  const passed = results.filter(r => r.status === 'PASS');

  if (passed.length === 0) {
    return `<section>
  <h2><span class="sec-icon">✅</span> Controles Aprovados</h2>
  <p style="color:#6b7280">Nenhum controle aprovado registrado.</p>
</section>`;
  }

  const items = passed.map(r =>
    `<div class="ctrl-item"><span class="ctrl-check">✓</span>${esc(r.check || '')}</div>`
  ).join('');

  return `<section>
  <h2><span class="sec-icon">✅</span> Controles Aprovados (${passed.length})</h2>
  <div class="controls-grid">${items}</div>
</section>`;
}

// ── Section: Next Steps ────────────────────────────────────────────
function buildNextSteps(results) {
  const fails = results.filter(r => r.status === 'FAIL');

  if (fails.length === 0) {
    return `<section>
  <h2><span class="sec-icon">🚀</span> Próximos Passos</h2>
  <div class="empty-ok">Nenhuma ação imediata necessária — mantenha monitoramento contínuo.</div>
</section>`;
  }

  const sorted = [...fails].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
  );

  const items = sorted.slice(0, 10).map(r => {
    const sc = SEV_COLORS[r.severity] || '#6b7280';
    const sl = SEV_LABELS[r.severity] || '';
    return `<li>
      <div class="next-step-title">
        ${esc(r.check || '')}
        <span class="badge" style="background:${sc}">${sl}</span>
      </div>
      <div class="next-step-desc">${esc(r.message || '')}</div>
    </li>`;
  }).join('');

  return `<section>
  <h2><span class="sec-icon">🚀</span> Próximos Passos (${Math.min(fails.length, 10)} principais)</h2>
  <ol class="next-steps-list">${items}</ol>
</section>`;
}

// ── Section: Footer ────────────────────────────────────────────────
function buildFooter(evidence, cfg, generatedDate) {
  const ev = evidence || {};
  const auditId  = ev.auditId  || '—';
  const sha256   = ev.sha256   ? ev.sha256.substring(0, 16) + '...' : '—';
  const auditDate = ev.timestamp
    ? new Date(ev.timestamp).toLocaleDateString('pt-BR')
    : '—';

  const contactLines = [
    cfg.name    && `<div class="footer-name">${esc(cfg.name)}</div>`,
    cfg.company && `<div class="footer-detail">${esc(cfg.company)}</div>`,
    cfg.email   && `<div class="footer-detail">✉ ${esc(cfg.email)}</div>`,
    cfg.phone   && `<div class="footer-detail">✆ ${esc(cfg.phone)}</div>`,
  ].filter(Boolean).join('');

  return `<div class="footer-wrap">
  <div class="footer-grid">
    <div>
      <div class="footer-section-label">Consultor Responsável</div>
      ${contactLines}
    </div>
    <div style="text-align:right">
      <div class="footer-section-label">Rastreabilidade do Documento</div>
      <div class="footer-doc-item"><span class="footer-doc-label">ID da Auditoria: </span><span class="hash">${esc(auditId)}</span></div>
      <div class="footer-doc-item"><span class="footer-doc-label">SHA-256: </span><span class="hash">${esc(sha256)}</span></div>
      <div class="footer-doc-item"><span class="footer-doc-label">Data da auditoria: </span>${esc(auditDate)}</div>
      <div class="footer-doc-item"><span class="footer-doc-label">Gerado em: </span>${esc(generatedDate)}</div>
    </div>
  </div>
  <div class="disclaimer">Este documento é confidencial e destinado exclusivamente ao destinatário indicado. A reprodução ou distribuição não autorizada é proibida. As informações contidas neste relatório refletem o estado do sistema no momento da auditoria.</div>
</div>`;
}

// ── Main generator ─────────────────────────────────────────────────
function generateConsultingReport(auditData, consultingConfig) {
  const results     = auditData.results     || [];
  const score       = Number(auditData.score ?? 0) || 0;
  const grade       = auditData.grade       || {};
  const productionReady = auditData.productionReady || {};
  const evidence    = auditData.evidence    || {};
  const projectUrl  = auditData.projectUrl  || '';
  const duration    = auditData.duration    || '—';
  const totalChecks = auditData.totalChecks ?? results.length;
  const failed      = auditData.failed      ?? results.filter(r => r.status === 'FAIL').length;
  const warnings    = auditData.warnings    ?? results.filter(r => r.status === 'WARN').length;

  const cfg   = consultingConfig || {};
  const prices = cfg.prices || {};

  const auditDate    = evidence.timestamp
    ? new Date(evidence.timestamp).toLocaleDateString('pt-BR')
    : new Date().toLocaleDateString('pt-BR');
  const generatedDate = new Date().toLocaleDateString('pt-BR');

  const cover      = buildCover(projectUrl, auditDate, score, grade, productionReady, cfg);
  const summary    = buildSummary(projectUrl, auditDate, score, grade, failed, warnings, totalChecks, duration);
  const vulns      = buildVulnerabilities(results);
  const services   = buildServices(results, prices);
  const controls   = buildControls(results);
  const nextSteps  = buildNextSteps(results);
  const footer     = buildFooter(evidence, cfg, generatedDate);

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Proposta de Consultoria — ${esc(projectUrl)}</title>
  <style>${CSS}</style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">&#8659; Exportar PDF</button>
  ${cover}
  ${summary}
  ${vulns}
  ${services}
  ${controls}
  ${nextSteps}
  ${footer}
</body>
</html>`;
}

module.exports = { generateConsultingReport };
