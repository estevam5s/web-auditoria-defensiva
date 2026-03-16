/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Consulting Proposal HTML Generator (Dark Theme v2)
   Dark UI + Chart.js interactive charts (gauge, donut, bars, radar)
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
const SEV_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV_LABELS = { critical: 'CRÍTICO', high: 'ALTO', medium: 'MÉDIO', low: 'BAIXO', info: 'INFO' };
const SEV_COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#64748b' };
const SEV_GLOW   = { critical: 'rgba(239,68,68,0.35)', high: 'rgba(249,115,22,0.30)', medium: 'rgba(234,179,8,0.25)', low: 'rgba(59,130,246,0.25)', info: 'rgba(100,116,139,0.20)' };

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

// ── Embedded dark CSS ──────────────────────────────────────────────
const CSS = `
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap');

:root {
  --bg:        #030308;
  --surf:      #0a0a14;
  --surf2:     #0f0f1e;
  --surf3:     #141428;
  --border:    rgba(255,255,255,0.07);
  --border2:   rgba(255,255,255,0.12);
  --text:      #e2e8f0;
  --muted:     #64748b;
  --muted2:    #475569;
  --accent:    #f97316;
  --accent2:   #ef4444;
  --cyan:      #00d4ff;
  --green:     #22c55e;
  --yellow:    #eab308;
  --blue:      #3b82f6;
  --purple:    #a855f7;
  --mono:      'JetBrains Mono', monospace;
  --sans:      'Inter', sans-serif;
  --r:         12px;
  --r-sm:      8px;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; font-size: 14px; }

body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  line-height: 1.65;
  overflow-x: hidden;
}

body::before {
  content: '';
  position: fixed; inset: 0; z-index: 0;
  background-image: radial-gradient(circle at 1px 1px, rgba(249,115,22,0.06) 1px, transparent 0);
  background-size: 32px 32px;
  pointer-events: none;
}

::-webkit-scrollbar { width: 7px; height: 7px; }
::-webkit-scrollbar-track { background: var(--surf); }
::-webkit-scrollbar-thumb { background: rgba(249,115,22,0.4); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent); }

/* ── Animations ── */
@keyframes fadeUp   { from { opacity:0; transform:translateY(20px) } to { opacity:1; transform:translateY(0) } }
@keyframes scanline { 0%,100% { transform:translateY(-100%) } 50% { transform:translateY(100vh) } }
@keyframes glow     { 0%,100% { opacity:.6 } 50% { opacity:1 } }
@keyframes spin     { to { transform: rotate(360deg) } }

/* ── Print / Export Button ── */
.print-btn {
  position: fixed; top: 20px; right: 20px; z-index: 9999;
  background: linear-gradient(135deg, var(--accent), #ea580c);
  color: #fff; border: none; padding: 10px 22px;
  border-radius: 9px; cursor: pointer;
  font-size: 13px; font-weight: 700; font-family: var(--sans);
  letter-spacing: .4px;
  box-shadow: 0 4px 20px rgba(249,115,22,.45);
  transition: all .22s ease;
  display: flex; align-items: center; gap: 8px;
}
.print-btn:hover { transform: translateY(-2px); box-shadow: 0 6px 28px rgba(249,115,22,.6); }

/* ── Wrapper ── */
.page { position: relative; z-index: 1; }

/* ── Cover ── */
.cover {
  background: linear-gradient(160deg, #05050f 0%, #0a0a1e 40%, #0d0520 100%);
  padding: 64px 60px 56px;
  position: relative; overflow: hidden;
  border-bottom: 1px solid var(--border2);
}
.cover::before {
  content: '';
  position: absolute; inset: 0;
  background:
    radial-gradient(ellipse 60% 50% at 80% 20%, rgba(249,115,22,.12) 0%, transparent 60%),
    radial-gradient(ellipse 40% 60% at 10% 80%, rgba(168,85,247,.08) 0%, transparent 55%),
    radial-gradient(ellipse 50% 40% at 50% 50%, rgba(0,212,255,.04) 0%, transparent 70%);
  pointer-events: none;
}
.cover::after {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: linear-gradient(90deg, var(--accent) 0%, var(--cyan) 50%, var(--purple) 100%);
  box-shadow: 0 0 20px rgba(249,115,22,.5);
}
.cover-scanline {
  position: absolute; inset: 0; overflow: hidden; pointer-events: none; opacity: .04;
}
.cover-scanline::after {
  content: '';
  position: absolute; left: 0; right: 0; height: 2px;
  background: var(--cyan);
  animation: scanline 6s linear infinite;
}
.cover-inner { position: relative; z-index: 1; }
.cover-top-bar {
  display: flex; justify-content: space-between; align-items: flex-start;
  margin-bottom: 48px; padding-bottom: 24px;
  border-bottom: 1px solid var(--border);
}
.cover-brand { font-family: var(--mono); font-size: 11px; color: var(--accent); letter-spacing: 2.5px; text-transform: uppercase; margin-bottom: 4px; }
.cover-consultant-name { font-size: 18px; font-weight: 800; color: var(--text); margin-bottom: 3px; }
.cover-consultant-detail { font-size: 13px; color: var(--muted); line-height: 1.7; }
.cover-date-label { font-size: 10px; color: var(--muted2); text-transform: uppercase; letter-spacing: 1.4px; margin-bottom: 3px; font-family: var(--mono); }
.cover-date-value { font-size: 13px; font-weight: 600; color: var(--text); text-align: right; font-family: var(--mono); }
.cover-category {
  font-size: 11px; color: var(--cyan); text-transform: uppercase;
  letter-spacing: 3px; margin-bottom: 10px; font-weight: 600; font-family: var(--mono);
}
.cover-title {
  font-size: clamp(22px, 4vw, 34px); font-weight: 800;
  color: #f1f5ff; line-height: 1.2; word-break: break-all;
  margin-bottom: 36px;
  text-shadow: 0 0 40px rgba(0,212,255,.15);
}
.cover-score-row { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
.cover-gauge-wrap { position: relative; width: 130px; height: 130px; flex-shrink: 0; }
.cover-gauge-wrap canvas { position: absolute; inset: 0; }
.cover-gauge-center {
  position: absolute; inset: 0; display: flex; flex-direction: column;
  align-items: center; justify-content: center;
}
.cover-gauge-num { font-size: 34px; font-weight: 800; line-height: 1; font-family: var(--mono); }
.cover-gauge-lbl { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }
.cover-grade-badge {
  display: inline-flex; align-items: center; gap: 10px;
  padding: 8px 20px; border-radius: 9px;
  background: rgba(249,115,22,.1); border: 1px solid rgba(249,115,22,.3);
  font-size: 13px; font-weight: 700; color: var(--accent);
  font-family: var(--mono); letter-spacing: .5px; margin-bottom: 8px;
}
.cover-pv-badge {
  display: inline-flex; align-items: center; gap: 8px;
  padding: 6px 16px; border-radius: 20px;
  font-size: 12px; font-weight: 700; letter-spacing: .4px;
}

/* ── Sections ── */
section {
  background: var(--surf);
  max-width: 980px; margin: 22px auto;
  padding: 40px 48px;
  border-radius: var(--r);
  border: 1px solid var(--border);
  animation: fadeUp 0.4s ease both;
  position: relative; overflow: hidden;
}
section::before {
  content: '';
  position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, transparent, rgba(249,115,22,.3), transparent);
}
section.cover {
  background: transparent; border-radius: 0; border: none;
  max-width: none; margin: 0; padding: 0; animation: none; overflow: visible;
}
section.cover::before { display: none; }

/* ── Section headings ── */
h2 {
  font-size: 17px; font-weight: 800; color: var(--text);
  margin-bottom: 24px; padding: 12px 16px 12px 18px;
  border-left: 3px solid var(--accent);
  background: linear-gradient(90deg, rgba(249,115,22,.08) 0%, transparent 100%);
  border-radius: 0 var(--r-sm) var(--r-sm) 0;
  display: flex; align-items: center; gap: 10px;
  letter-spacing: .2px;
}
h2 .sec-icon { font-size: 18px; }
h3 { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
p { margin-bottom: 12px; color: #94a3b8; line-height: 1.75; }

/* ── Summary box ── */
.summary-box {
  background: linear-gradient(90deg, rgba(249,115,22,.07) 0%, rgba(249,115,22,.02) 100%);
  border-left: 3px solid var(--accent);
  border-radius: 0 var(--r-sm) var(--r-sm) 0;
  padding: 18px 22px; margin-bottom: 28px;
  font-size: 14px; color: #94a3b8; line-height: 1.85;
}
.summary-box strong { color: var(--text); }

/* ── Stats grid ── */
.summary-stats {
  display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-top: 0;
}
.stat-card {
  background: var(--surf2);
  border: 1px solid var(--border);
  border-radius: var(--r); padding: 18px 16px 14px;
  text-align: center;
  transition: transform .2s, border-color .2s;
  position: relative; overflow: hidden;
}
.stat-card:hover { transform: translateY(-3px); border-color: var(--border2); }
.stat-card::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: var(--accent-clr, var(--accent));
}
.stat-card .stat-val { font-size: 28px; font-weight: 800; line-height: 1; font-family: var(--mono); }
.stat-card .stat-label { font-size: 11px; color: var(--muted); margin-top: 5px; text-transform: uppercase; letter-spacing: .7px; }

/* ── Charts row ── */
.charts-row {
  display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 28px;
}
.chart-card {
  background: var(--surf2); border: 1px solid var(--border);
  border-radius: var(--r); padding: 22px 24px;
  position: relative;
}
.chart-card-title {
  font-size: 12px; font-weight: 700; color: var(--muted);
  text-transform: uppercase; letter-spacing: 1.2px;
  margin-bottom: 16px; font-family: var(--mono);
}
.chart-wrap { position: relative; height: 200px; }

/* ── Radar chart row ── */
.radar-row {
  display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px;
}
.chart-card.full { grid-column: 1 / -1; }
.chart-wrap-tall { position: relative; height: 280px; }

/* ── Tables ── */
.table-wrap {
  overflow-x: auto; margin-bottom: 22px;
  border-radius: var(--r); border: 1px solid var(--border);
}
table { width: 100%; border-collapse: collapse; font-size: 13px; }
thead th {
  background: var(--surf3);
  color: var(--muted); padding: 11px 16px; text-align: left;
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: .8px; font-family: var(--mono);
  border-bottom: 1px solid var(--border2);
}
thead th:first-child { border-radius: var(--r) 0 0 0; }
thead th:last-child  { border-radius: 0 var(--r) 0 0; }
td {
  padding: 12px 16px; border-bottom: 1px solid var(--border);
  vertical-align: top; color: #94a3b8;
}
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(255,255,255,.025); }
tfoot td {
  background: var(--surf3) !important;
  color: var(--text) !important; font-weight: 700;
  border-bottom: none; padding: 13px 16px;
  border-top: 1px solid var(--border2);
}
tfoot tr td:last-child { font-size: 15px; color: var(--accent) !important; font-family: var(--mono); }

/* ── Badges ── */
.badge {
  display: inline-block; padding: 2px 9px; border-radius: 20px;
  font-size: 10px; font-weight: 800; color: #fff; letter-spacing: .5px;
  white-space: nowrap;
}

/* ── Group header ── */
.group-hdr {
  display: flex; align-items: center; gap: 10px;
  margin-top: 28px; margin-bottom: 12px;
  padding: 10px 16px;
  background: var(--surf3);
  border-left: 3px solid var(--accent);
  border-radius: 0 var(--r-sm) var(--r-sm) 0;
}
.group-hdr h3 { margin: 0; font-size: 13px; font-weight: 700; color: var(--text); }

/* ── Services ── */
.service-note { font-size: 12px; color: var(--muted); font-style: italic; margin-top: 10px; }

/* ── Controls grid ── */
.controls-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 8px 14px; margin-top: 6px;
}
.ctrl-item {
  display: flex; align-items: center; gap: 9px;
  padding: 9px 12px; font-size: 13px;
  background: rgba(34,197,94,.06);
  border-radius: var(--r-sm);
  border: 1px solid rgba(34,197,94,.2);
  transition: transform .18s ease, border-color .18s ease;
  color: #94a3b8;
}
.ctrl-item:hover { transform: translateY(-2px); border-color: rgba(34,197,94,.4); }
.ctrl-check { font-size: 14px; color: var(--green); flex-shrink: 0; }

/* ── Empty states ── */
.empty-ok {
  background: rgba(34,197,94,.07); border: 1px solid rgba(34,197,94,.3);
  border-radius: var(--r); padding: 16px 20px;
  color: var(--green); font-weight: 600;
  display: flex; align-items: center; gap: 12px; font-size: 14px;
}
.empty-ok::before { content: '✓'; font-size: 18px; flex-shrink: 0; }
.empty-warn {
  background: rgba(234,179,8,.07); border: 1px solid rgba(234,179,8,.3);
  border-radius: var(--r); padding: 16px 20px;
  color: var(--yellow); font-weight: 600;
  display: flex; align-items: center; gap: 12px; font-size: 14px;
}

/* ── Next Steps ── */
.next-steps-list { list-style: none; padding: 0; counter-reset: steps; }
.next-steps-list li {
  counter-increment: steps;
  padding: 15px 18px 15px 58px;
  position: relative;
  border: 1px solid var(--border);
  border-radius: var(--r); margin-bottom: 10px;
  background: var(--surf2);
  transition: border-color .2s, transform .2s;
}
.next-steps-list li:hover { border-color: var(--border2); transform: translateX(2px); }
.next-steps-list li::before {
  content: counter(steps);
  position: absolute; left: 14px; top: 50%; transform: translateY(-50%);
  width: 26px; height: 26px; border-radius: 50%;
  background: linear-gradient(135deg, var(--accent) 0%, #ea580c 100%);
  color: #fff;
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 800; font-family: var(--mono);
  box-shadow: 0 2px 8px rgba(249,115,22,.4);
}
.next-step-title { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; font-weight: 700; color: var(--text); font-size: 13px; }
.next-step-desc { font-size: 12px; color: var(--muted); }

/* ── Dark web ── */
.dw-banner {
  border-radius: var(--r); padding: 20px 24px; margin-bottom: 22px;
  display: flex; align-items: center; gap: 20px; flex-wrap: wrap;
}
.dw-banner.dark-web  { background: rgba(239,68,68,.08);   border: 1px solid rgba(239,68,68,.35);   color: #fca5a5; }
.dw-banner.deep-web  { background: rgba(168,85,247,.08);  border: 1px solid rgba(168,85,247,.35);  color: #d8b4fe; }
.dw-banner.surface-web { background: rgba(234,179,8,.08); border: 1px solid rgba(234,179,8,.35);   color: #fde68a; }
.dw-banner.clean     { background: rgba(34,197,94,.07);   border: 1px solid rgba(34,197,94,.3);    color: #86efac; }
.dw-tier-icon { font-size: 34px; flex-shrink: 0; }
.dw-tier-label { font-size: 11px; font-weight: 800; letter-spacing: 2px; text-transform: uppercase; opacity: .7; margin-bottom: 2px; font-family: var(--mono); }
.dw-tier-title { font-size: 20px; font-weight: 800; line-height: 1.2; }
.dw-tier-desc { font-size: 12px; opacity: .7; margin-top: 3px; }
.dw-risk-badge {
  margin-left: auto; flex-shrink: 0;
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  width: 72px; height: 72px; border-radius: 50%;
  font-weight: 800; border: 2px solid currentColor;
  background: rgba(0,0,0,.3);
}
.dw-risk-num { font-size: 24px; line-height: 1; font-family: var(--mono); }
.dw-risk-lbl { font-size: 10px; opacity: .6; text-transform: uppercase; letter-spacing: .5px; }
.dw-metrics {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 10px; margin-bottom: 18px;
}
.dw-metric {
  background: var(--surf2); border: 1px solid var(--border);
  border-radius: var(--r-sm); padding: 13px 15px;
  position: relative; overflow: hidden;
  transition: transform .18s ease;
}
.dw-metric:hover { transform: translateY(-2px); }
.dw-metric::before {
  content: ''; position: absolute; top: 0; left: 0; width: 3px; height: 100%;
  background: var(--dw-accent, var(--blue));
}
.dw-metric-val  { font-size: 22px; font-weight: 800; color: var(--text); line-height: 1; font-family: var(--mono); }
.dw-metric-label { font-size: 11px; color: var(--muted); margin-top: 3px; text-transform: uppercase; letter-spacing: .5px; }
.dw-metric.warn { --dw-accent: #ef4444; } .dw-metric.warn .dw-metric-val { color: #ef4444; }
.dw-metric.ok   { --dw-accent: var(--green); } .dw-metric.ok .dw-metric-val { color: var(--green); }
.dw-subdomains  { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
.dw-subdomain   { background: rgba(59,130,246,.1); border: 1px solid rgba(59,130,246,.25); border-radius: 4px; padding: 3px 9px; font-size: 11px; font-family: var(--mono); color: #93c5fd; }
.dw-network-row { display: flex; flex-wrap: wrap; gap: 8px 24px; margin-top: 10px; padding: 13px 16px; background: var(--surf2); border-radius: var(--r-sm); border: 1px solid var(--border); }
.dw-net-label   { font-size: 10px; color: var(--muted2); text-transform: uppercase; letter-spacing: .5px; margin-bottom: 1px; font-family: var(--mono); }
.dw-net-item    { font-size: 12px; color: #94a3b8; }
.dw-darkweb-link {
  display: inline-flex; align-items: center; gap: 7px;
  background: rgba(249,115,22,.1); color: var(--accent);
  text-decoration: none; padding: 9px 20px;
  border: 1px solid rgba(249,115,22,.3); border-radius: var(--r-sm);
  font-size: 12px; font-weight: 700; margin-top: 14px;
  transition: all .22s ease; font-family: var(--mono); letter-spacing: .3px;
}
.dw-darkweb-link:hover { background: rgba(249,115,22,.18); border-color: var(--accent); transform: translateY(-1px); }

/* ── Footer ── */
.footer-wrap {
  background: linear-gradient(135deg, #05050f 0%, #0a0a1e 100%);
  color: #64748b; padding: 40px 60px;
  border-top: 1px solid var(--border2);
  position: relative;
}
.footer-wrap::before {
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--accent), var(--cyan), var(--purple));
}
.footer-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 32px; margin-bottom: 22px; }
.footer-section-label { font-size: 10px; text-transform: uppercase; letter-spacing: 1.8px; color: var(--muted2); margin-bottom: 10px; font-weight: 700; font-family: var(--mono); }
.footer-name   { font-size: 14px; font-weight: 800; color: var(--text); margin-bottom: 4px; }
.footer-detail { color: #64748b; margin-bottom: 3px; font-size: 13px; }
.footer-doc-item { margin-bottom: 5px; }
.footer-doc-label { color: var(--muted2); font-size: 11px; }
.hash { font-family: var(--mono); font-size: 11px; color: #475569; }
.disclaimer { font-size: 11px; color: #374151; font-style: italic; border-top: 1px solid rgba(255,255,255,.05); padding-top: 18px; margin-top: 6px; line-height: 1.75; }

/* ── Risk Bar ── */
.risk-bar-wrap { margin-top: 20px; }
.risk-bar-label { font-size: 11px; color: var(--muted); margin-bottom: 4px; text-transform: uppercase; letter-spacing: .7px; font-family: var(--mono); }
.risk-bar-track { height: 8px; background: rgba(255,255,255,.07); border-radius: 4px; overflow: hidden; margin-bottom: 12px; }
.risk-bar-fill  { height: 100%; border-radius: 4px; transition: width 1s ease; }

/* ── Accordion ── */
.accordion-btn {
  width: 100%; background: var(--surf3); border: none; border-bottom: 1px solid var(--border);
  color: var(--text); padding: 12px 16px; text-align: left; cursor: pointer;
  display: flex; align-items: center; gap: 10px; font-size: 13px; font-weight: 600;
  font-family: var(--sans); transition: background .18s;
}
.accordion-btn:hover { background: rgba(249,115,22,.06); }
.accordion-btn .acc-arrow { margin-left: auto; transition: transform .25s; font-size: 11px; color: var(--muted); }
.accordion-btn.open .acc-arrow { transform: rotate(90deg); }
.accordion-body { display: none; }
.accordion-body.open { display: block; }

/* ── Print ── */
@media print {
  body { background: #030308 !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  .print-btn { display: none !important; }
  section { page-break-inside: avoid; max-width: none; animation: none; margin: 0; border-radius: 0; }
  section + section { page-break-before: always; }
  .footer-wrap { page-break-before: always; }
  canvas { max-width: 100%; }
}
`;

// ── Section: Cover ─────────────────────────────────────────────────
function buildCover(projectUrl, auditDate, score, grade, productionReady, cfg) {
  const scoreColor = score >= 88 ? '#22c55e' : score >= 52 ? '#f97316' : '#ef4444';
  const pv = productionReady || {};
  const pvBg  = pv.color ? `rgba(${hexToRgb(pv.color)},0.12)` : 'rgba(100,116,139,0.12)';
  const pvBorder = pv.color ? `rgba(${hexToRgb(pv.color)},0.35)` : 'rgba(100,116,139,0.35)';
  const pvTextColor = pv.color || '#64748b';

  const contactLines = [
    cfg.company ? `<div style="color:#94a3b8;font-size:13px">${esc(cfg.company)}</div>` : '',
    cfg.email   ? `<div style="color:#64748b;font-size:12px">✉ ${esc(cfg.email)}</div>` : '',
    cfg.phone   ? `<div style="color:#64748b;font-size:12px">✆ ${esc(cfg.phone)}</div>` : '',
  ].filter(Boolean).join('');

  return `<div class="cover">
  <div class="cover-scanline"></div>
  <div class="cover-inner">
    <div class="cover-top-bar">
      <div>
        <div class="cover-brand">Supabase Guard · Consultoria em Segurança</div>
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
      <div class="cover-gauge-wrap">
        <canvas id="coverGauge" width="130" height="130"></canvas>
        <div class="cover-gauge-center">
          <div class="cover-gauge-num" style="color:${scoreColor}">${score}</div>
          <div class="cover-gauge-lbl">Score</div>
        </div>
      </div>
      <div>
        <div class="cover-grade-badge">
          <span style="font-size:22px;font-weight:900;color:${scoreColor}">${esc(grade.grade || '?')}</span>
          <span style="font-size:13px;color:var(--muted)">${esc(grade.label || '')}</span>
        </div>
        <br>
        ${pv.label ? `<span class="cover-pv-badge" style="background:${pvBg};border:1px solid ${pvBorder};color:${pvTextColor}">${esc(pv.label)}</span>` : ''}
      </div>
    </div>
  </div>
</div>`;
}

// ── Section: Executive Summary + Charts ───────────────────────────
function buildSummary(projectUrl, auditDate, score, grade, failed, warnings, totalChecks, duration, results) {
  const passed  = totalChecks - failed - warnings;
  const info    = (results || []).filter(r => r.status === 'INFO' || r.severity === 'info').length;
  const critical = (results || []).filter(r => r.severity === 'critical' && r.status !== 'PASS').length;
  const high     = (results || []).filter(r => r.severity === 'high' && r.status !== 'PASS').length;
  const medium   = (results || []).filter(r => r.severity === 'medium' && r.status !== 'PASS').length;
  const low      = (results || []).filter(r => r.severity === 'low' && r.status !== 'PASS').length;

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

  const scoreColor = score >= 88 ? '#22c55e' : score >= 52 ? '#f97316' : '#ef4444';

  return `<section>
  <h2><span class="sec-icon">📊</span> Sumário Executivo</h2>
  <div class="summary-box">
    A auditoria de segurança realizada em <strong>${esc(projectUrl)}</strong> em ${esc(auditDate)}
    identificou <strong>${failed}</strong> falha(s) e <strong>${warnings}</strong> alerta(s)
    em um total de <strong>${totalChecks}</strong> verificações, com duração de ${esc(duration)}.
    Score de segurança: <strong style="color:${scoreColor}">${score}/100</strong>
    (Grau <strong>${esc(grade.grade || '?')}</strong> — ${esc(grade.label || '')}).
    ${esc(fraseFinal)}
  </div>

  <div class="summary-stats">
    <div class="stat-card" style="--accent-clr:#ef4444">
      <div class="stat-val" style="color:#ef4444">${failed}</div>
      <div class="stat-label">Falhas</div>
    </div>
    <div class="stat-card" style="--accent-clr:#f97316">
      <div class="stat-val" style="color:#f97316">${warnings}</div>
      <div class="stat-label">Alertas</div>
    </div>
    <div class="stat-card" style="--accent-clr:#22c55e">
      <div class="stat-val" style="color:#22c55e">${Math.max(0,passed)}</div>
      <div class="stat-label">Aprovados</div>
    </div>
    <div class="stat-card" style="--accent-clr:${scoreColor}">
      <div class="stat-val" style="color:${scoreColor}">${score}</div>
      <div class="stat-label">Score / 100</div>
    </div>
  </div>

  <div class="charts-row" style="margin-top:28px">
    <div class="chart-card">
      <div class="chart-card-title">Distribuição por Severidade</div>
      <div class="chart-wrap">
        <canvas id="chartSeverity"></canvas>
      </div>
    </div>
    <div class="chart-card">
      <div class="chart-card-title">Status das Verificações</div>
      <div class="chart-wrap">
        <canvas id="chartStatus"></canvas>
      </div>
    </div>
  </div>

  <div class="radar-row" style="margin-top:20px">
    <div class="chart-card full">
      <div class="chart-card-title">Mapa de Risco por Domínio de Segurança</div>
      <div class="chart-wrap-tall">
        <canvas id="chartRisk"></canvas>
      </div>
    </div>
  </div>

  <script>
  window.__AUDIT_CHART_DATA = {
    critical: ${critical}, high: ${high}, medium: ${medium}, low: ${low},
    failed: ${failed}, warnings: ${warnings}, passed: ${Math.max(0, passed)}, info: ${info},
    score: ${score},
    groups: ${JSON.stringify(_buildGroupRiskData(results || []))}
  };
  </script>
</section>`;
}

// helper — compute per-group risk score for radar chart (server-side)
function _buildGroupRiskData(results) {
  const RADAR_DOMAINS = [
    { label: 'Autenticação',    pattern: /Auth|JWT|Signup|Password/i },
    { label: 'Controle de Acesso', pattern: /RLS|Row Level|REST|RPC|Service Key/i },
    { label: 'Headers/CORS',    pattern: /Header|CORS|CSP/i },
    { label: 'Credenciais',     pattern: /Key Exposure|\.env|Bundle|Credential/i },
    { label: 'Rede/DDoS',       pattern: /DDoS|DoS|Rate Limit|SSL|TLS|Network/i },
    { label: 'Dados/PII',       pattern: /Storage|Sensitive|PII|Customer Data/i },
    { label: 'Código/Git',      pattern: /Source Code|Git Exposure|Route/i },
    { label: 'Infra/SSL',       pattern: /SSL|TLS|DNS|Port Scan/i },
  ];
  return RADAR_DOMAINS.map(d => {
    const domainResults = results.filter(r => d.pattern.test(r.check || ''));
    if (!domainResults.length) return { label: d.label, score: 100 };
    const fails = domainResults.filter(r => r.status !== 'PASS').length;
    const rawScore = Math.round(100 - (fails / domainResults.length) * 100);
    return { label: d.label, score: rawScore };
  });
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

  const grouped = {};
  for (const r of issues) {
    const g = getGroup(r.check || '');
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(r);
  }

  let html = `<section><h2><span class="sec-icon">🔍</span> Levantamento de Vulnerabilidades por Categoria</h2>`;

  let idx = 0;
  for (const [group, items] of Object.entries(grouped)) {
    const maxSev   = maxSeverity(items);
    const sevColor = SEV_COLORS[maxSev] || '#64748b';
    const sevGlow  = SEV_GLOW[maxSev]  || '';
    const sevLabel = SEV_LABELS[maxSev] || maxSev.toUpperCase();
    const label    = getGroupLabel(group);
    const bid      = `acc-${idx++}`;

    html += `<div class="group-hdr">
      <h3>${esc(label)}</h3>
      <span class="badge" style="background:${sevColor};box-shadow:0 0 8px ${sevGlow}">${sevLabel}</span>
      <span style="margin-left:auto;font-size:11px;color:var(--muted);font-family:var(--mono)">${items.length} item(s)</span>
    </div>
    <button class="accordion-btn" onclick="toggleAcc('${bid}')" id="btn-${bid}">
      <span>Ver detalhes (${items.length})</span>
      <span class="acc-arrow">▶</span>
    </button>
    <div class="accordion-body" id="${bid}">
    <div class="table-wrap" style="margin-bottom:0;border-top:none;border-radius:0 0 ${bid} 0">
    <table>
      <thead><tr><th>Verificação</th><th>Status</th><th>Severidade</th><th>Descrição</th></tr></thead>
      <tbody>`;

    for (const r of items) {
      const sc = SEV_COLORS[r.severity] || '#64748b';
      const sl = SEV_LABELS[r.severity] || esc((r.severity || '').toUpperCase());
      const statusColor = r.status === 'FAIL' ? '#ef4444' : '#f97316';
      html += `<tr>
        <td style="font-weight:600;color:var(--text);min-width:160px;font-family:var(--mono);font-size:12px">${esc(r.check || '')}</td>
        <td style="min-width:70px"><span class="badge" style="background:${statusColor}">${esc(r.status)}</span></td>
        <td style="min-width:90px"><span class="badge" style="background:${sc}">${sl}</span></td>
        <td style="color:#64748b">${esc(r.message || '')}</td>
      </tr>`;
    }

    html += `</tbody></table></div></div>`;
  }

  html += `</section>`;
  return html;
}

// ── Section: Consulting Services ───────────────────────────────────
const SERVICE_CATALOG = [
  { key: 'rls',      label: 'Implementação e Revisão de RLS',    desc: 'Configuração de políticas Row Level Security para todas as tabelas expostas.',  groups: ['rls'],                                            price: p => p.rls,     est: '10h' },
  { key: 'auth',     label: 'Hardening de Autenticação e JWT',   desc: 'Revisão de autenticação, JWT, signup e controle de sessão.',                     groups: ['auth', 'jwt'],                                    price: p => p.auth,    est: '8h'  },
  { key: 'env',      label: 'Correção de Credenciais Expostas',  desc: 'Remoção e rotação de credenciais expostas publicamente ou em bundles JS.',       groups: ['env', 'bundle-keys', 'credential', 'service-key'], price: p => p.env,     est: '6h'  },
  { key: 'headers',  label: 'Configuração de Headers e CORS',    desc: 'Implementação de headers de segurança HTTP e política CORS restritiva.',         groups: ['cors', 'security-headers', 'hardening'],          price: p => p.headers, est: '4h'  },
  { key: 'ssl',      label: 'Auditoria e Configuração SSL/TLS',  desc: 'Revisão de certificados, ciphers e configuração de transporte seguro.',          groups: ['ssl'],                                            price: p => p.hourly * 6, est: '6h' },
  { key: 'ddos',     label: 'Proteção contra Ataques',           desc: 'Rate limiting, proteção DDoS, bloqueio de brute force.',                         groups: ['ddos', 'brute-force', 'hydra', 'dos-advanced'],   price: p => p.hourly * 12, est: '12h' },
  { key: 'infra',    label: 'Hardening de Infraestrutura/Rede',  desc: 'Fechamento de portas desnecessárias e hardening de rede.',                       groups: ['port-scan', 'network'],                           price: p => p.hourly * 8, est: '8h'  },
  { key: 'git',      label: 'Remoção de Exposição de Código',    desc: 'Remoção de arquivos sensíveis acessíveis publicamente.',                         groups: ['git-exposure', 'source'],                         price: p => p.hourly * 3, est: '3h'  },
  { key: 'pii',      label: 'Proteção de Dados de Clientes',     desc: 'Revisão de tabelas com dados pessoais e controles de acesso.',                   groups: ['saas-pii', 'sensitive'],                          price: p => p.hourly * 8, est: '8h'  },
  { key: 'pentest',  label: 'Pentest Completo e Relatório',      desc: 'Teste de penetração completo com relatório executivo e técnico detalhado.',      groups: [],                                                  price: p => p.pentest, est: '24h' },
];

function buildServices(results, prices) {
  const failedGroups = new Set(
    results.filter(r => r.status === 'FAIL' || r.status === 'WARN').map(r => getGroup(r.check || ''))
  );

  const activeServices = SERVICE_CATALOG.filter(s =>
    s.key === 'pentest' || s.groups.some(g => failedGroups.has(g))
  );

  let total = 0;
  let rows = '';
  const serviceChartData = [];

  for (const s of activeServices) {
    const raw = s.price(prices);
    const value = (typeof raw === 'number' && isFinite(raw) && raw >= 0) ? raw : 0;
    total += value;
    serviceChartData.push({ label: s.label, value });
    rows += `<tr>
      <td style="font-weight:600;color:var(--text)">${esc(s.label)}</td>
      <td style="color:#64748b">${esc(s.desc)}</td>
      <td style="text-align:center;font-family:var(--mono);color:var(--muted)">${esc(s.est)}</td>
      <td style="text-align:right;font-weight:700;font-family:var(--mono);color:var(--accent)">R$ ${value.toLocaleString('pt-BR')}</td>
    </tr>`;
  }

  return `<section>
  <h2><span class="sec-icon">💼</span> Serviços de Consultoria Recomendados</h2>

  <div class="chart-card" style="margin-bottom:24px">
    <div class="chart-card-title">Estimativa de Investimento por Serviço</div>
    <div style="position:relative;height:${Math.max(160, activeServices.length * 36)}px">
      <canvas id="chartServices"></canvas>
    </div>
  </div>

  <div class="table-wrap">
  <table>
    <thead><tr><th>Serviço</th><th>Descrição</th><th style="text-align:center;white-space:nowrap">Estimativa</th><th style="text-align:right;white-space:nowrap">Valor (R$)</th></tr></thead>
    <tbody>${rows}</tbody>
    <tfoot>
      <tr><td colspan="3" style="font-weight:700">Total Estimado</td><td style="text-align:right">R$ ${total.toLocaleString('pt-BR')}</td></tr>
    </tfoot>
  </table>
  </div>
  <p class="service-note">* Valores estimados. Proposta formal com escopo detalhado disponível mediante solicitação.</p>
  <script>window.__SERVICE_CHART_DATA = ${JSON.stringify(serviceChartData)};</script>
</section>`;
}

// ── Section: Approved Controls ─────────────────────────────────────
function buildControls(results) {
  const passed = results.filter(r => r.status === 'PASS');
  if (passed.length === 0) {
    return `<section>
  <h2><span class="sec-icon">✅</span> Controles Aprovados</h2>
  <p style="color:var(--muted)">Nenhum controle aprovado registrado.</p>
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
  const sorted = [...fails].sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5));
  const items = sorted.slice(0, 10).map(r => {
    const sc = SEV_COLORS[r.severity] || '#64748b';
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

// ── Section: Dark / Deep / Surface Web Intelligence ────────────────
function buildDarkWebSection(intel, auditId) {
  if (!intel) {
    return `<section>
  <h2><span class="sec-icon">🌐</span> Inteligência Dark/Deep/Surface Web</h2>
  <div class="empty-warn">
    ⚠ Análise OSINT/Dark Web não disponível para esta auditoria.
    ${auditId ? `<a class="dw-darkweb-link" href="/darkweb/${esc(auditId)}" style="margin-top:0;margin-left:auto">🕵️ Executar Agora</a>` : ''}
  </div>
</section>`;
  }

  const level = intel.threatLevel;
  const tierMap = {
    DARK_WEB:    { cls: 'dark-web',    icon: '🕸️', label: 'Dark Web',    title: 'Presença Detectada na Dark Web',    desc: 'Ameaças ativas, malware ou credenciais expostas identificadas.' },
    DEEP_WEB:    { cls: 'deep-web',    icon: '🔍', label: 'Deep Web',    title: 'Atividade Suspeita na Deep Web',    desc: 'Indicadores de comprometimento moderados detectados.' },
    SURFACE_WEB: { cls: 'surface-web', icon: '🌐', label: 'Surface Web', title: 'Riscos na Surface Web',             desc: 'Riscos menores em fontes abertas. Acompanhamento indicado.' },
  };
  const cleanTier = { cls: 'clean', icon: '✅', label: 'Limpo', title: 'Nenhuma Ameaça Detectada', desc: 'Sem presença em listas de ameaças, malware ou vazamentos conhecidos.' };
  const tier = tierMap[level] || cleanTier;

  const breachCount   = intel.hibp?.domainBreaches?.length || 0;
  const malwareCount  = intel.otx?.malwareCount            || 0;
  const pulseCount    = intel.otx?.pulseCount              || 0;
  const urlMalicious  = intel.urlscan?.malicious           || 0;
  const urlSuspicious = intel.urlscan?.suspicious          || 0;
  const subCount      = intel.subdomains?.count            || 0;
  const vtMalicious   = intel.virustotal?.malicious        || 0;
  const riskScore     = intel.riskScore ?? 0;

  const banner = `<div class="dw-banner ${esc(tier.cls)}">
    <span class="dw-tier-icon">${tier.icon}</span>
    <div>
      <div class="dw-tier-label">${esc(tier.label)}</div>
      <div class="dw-tier-title">${esc(tier.title)}</div>
      <div class="dw-tier-desc">${esc(tier.desc)}</div>
    </div>
    <div class="dw-risk-badge">
      <span class="dw-risk-num">${riskScore}</span>
      <span class="dw-risk-lbl">Risco</span>
    </div>
  </div>`;

  function metric(val, label, warn) {
    const cls = warn && val > 0 ? 'warn' : val === 0 ? 'ok' : '';
    return `<div class="dw-metric ${cls}">
      <div class="dw-metric-val">${val}</div>
      <div class="dw-metric-label">${label}</div>
    </div>`;
  }

  const metrics = `<div class="dw-metrics">
    ${metric(breachCount,   'Vazamentos HIBP',  true)}
    ${metric(malwareCount,  'Malware OTX',      true)}
    ${metric(pulseCount,    'Pulsos de Ameaça', true)}
    ${metric(urlMalicious,  'URLs Maliciosas',  true)}
    ${metric(urlSuspicious, 'URLs Suspeitas',   false)}
    ${metric(subCount,      'Subdomínios',      false)}
    ${vtMalicious !== null ? metric(vtMalicious, 'VirusTotal', true) : ''}
  </div>`;

  let breachDetail = '';
  if (breachCount > 0) {
    const rows = (intel.hibp.domainBreaches || []).map(b => `<tr>
      <td style="font-weight:600;color:var(--text)">${esc(b.title || b.name)}</td>
      <td style="font-family:var(--mono);font-size:11px">${esc(b.breachDate || '—')}</td>
      <td style="text-align:right;color:#ef4444;font-weight:600;font-family:var(--mono)">${b.pwnCount ? b.pwnCount.toLocaleString('pt-BR') : '—'}</td>
      <td style="color:#64748b;font-size:12px">${esc((b.dataClasses || []).slice(0, 4).join(', '))}</td>
    </tr>`).join('');
    breachDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Vazamentos por Domínio (HIBP)</h3>
      <span class="badge" style="background:#ef4444">${breachCount}</span>
    </div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Incidente</th><th>Data</th><th style="text-align:right">Contas Afetadas</th><th>Dados Expostos</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  }

  let malwareDetail = '';
  const families = intel.otx?.malwareFamilies || [];
  if (families.length > 0) {
    malwareDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Famílias de Malware Detectadas (OTX)</h3>
      <span class="badge" style="background:#f97316">${families.length}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin:10px 0">
      ${families.map(f => `<span class="badge" style="background:#f97316">${esc(f)}</span>`).join('')}
    </div>`;
  }

  let subDetail = '';
  const subs = intel.subdomains?.subdomains || [];
  if (subs.length > 0) {
    subDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Subdomínios Descobertos (crt.sh)</h3>
      <span class="badge" style="background:#3b82f6">${subCount}</span>
    </div>
    <div class="dw-subdomains">${subs.map(s => `<span class="dw-subdomain">${esc(s)}</span>`).join('')}</div>`;
  }

  let netDetail = '';
  const net = intel.network;
  if (net?.ip) {
    netDetail = `<div class="group-hdr" style="margin-top:20px"><h3>Informações de Rede</h3></div>
    <div class="dw-network-row">
      ${net.ip      ? `<div class="dw-net-item"><div class="dw-net-label">IP</div>${esc(net.ip)}</div>` : ''}
      ${net.hosting ? `<div class="dw-net-item"><div class="dw-net-label">Hosting</div>${esc(net.hosting)}</div>` : ''}
      ${net.org     ? `<div class="dw-net-item"><div class="dw-net-label">Organização</div>${esc(net.org)}</div>` : ''}
      ${net.city    ? `<div class="dw-net-item"><div class="dw-net-label">Cidade</div>${esc(net.city)}, ${esc(net.country || '')}</div>` : ''}
      ${net.timezone? `<div class="dw-net-item"><div class="dw-net-label">Timezone</div>${esc(net.timezone)}</div>` : ''}
      ${net.asn     ? `<div class="dw-net-item"><div class="dw-net-label">ASN</div>${esc(net.asn)}</div>` : ''}
    </div>`;
  }

  const darkwebLink = auditId
    ? `<a class="dw-darkweb-link" href="/darkweb/${esc(auditId)}" target="_blank">🕵️ Ver Relatório Completo Dark Web</a>`
    : '';

  return `<section>
  <h2><span class="sec-icon">🌐</span> Inteligência Dark/Deep/Surface Web</h2>
  ${banner}
  ${metrics}
  ${breachDetail}
  ${malwareDetail}
  ${subDetail}
  ${netDetail}
  ${darkwebLink}
</section>`;
}

// ── Section: Footer ────────────────────────────────────────────────
function buildFooter(evidence, cfg, generatedDate) {
  const ev       = evidence || {};
  const auditId  = ev.auditId  || '—';
  const sha256   = ev.sha256   ? ev.sha256.substring(0, 16) + '...' : '—';
  const auditDate = ev.timestamp ? new Date(ev.timestamp).toLocaleDateString('pt-BR') : '—';

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
  <div class="disclaimer">Este documento é confidencial e destinado exclusivamente ao destinatário indicado. A reprodução ou distribuição não autorizada é proibida. As informações refletem o estado do sistema no momento da auditoria.</div>
</div>`;
}

// ── JS block: Chart.js rendering ───────────────────────────────────
const CHART_SCRIPT = `
<script>
(function() {
  function waitForChartJS(cb) {
    if (typeof Chart !== 'undefined') { cb(); return; }
    setTimeout(() => waitForChartJS(cb), 80);
  }

  function toggleAcc(id) {
    const body = document.getElementById(id);
    const btn  = document.getElementById('btn-' + id);
    if (!body || !btn) return;
    const isOpen = body.classList.contains('open');
    body.classList.toggle('open', !isOpen);
    btn.classList.toggle('open', !isOpen);
  }
  window.toggleAcc = toggleAcc;

  waitForChartJS(function() {
    Chart.defaults.color = '#64748b';
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size   = 11;

    const D = window.__AUDIT_CHART_DATA || {};
    const S = window.__SERVICE_CHART_DATA || [];

    // ── 1. Severity Donut ──────────────────────────────────────────
    const ctxSev = document.getElementById('chartSeverity');
    if (ctxSev) {
      new Chart(ctxSev, {
        type: 'doughnut',
        data: {
          labels: ['Crítico', 'Alto', 'Médio', 'Baixo'],
          datasets: [{
            data: [D.critical||0, D.high||0, D.medium||0, D.low||0],
            backgroundColor: ['#ef4444','#f97316','#eab308','#3b82f6'],
            borderColor: '#0a0a14',
            borderWidth: 3,
            hoverOffset: 6,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          cutout: '65%',
          plugins: {
            legend: {
              position: 'right',
              labels: { padding: 14, boxWidth: 12, color: '#94a3b8' }
            },
            tooltip: {
              backgroundColor: '#0f0f1e',
              borderColor: 'rgba(255,255,255,0.1)',
              borderWidth: 1,
              titleColor: '#e2e8f0',
              bodyColor: '#94a3b8',
            }
          }
        }
      });
    }

    // ── 2. Status Bar (horizontal) ────────────────────────────────
    const ctxSt = document.getElementById('chartStatus');
    if (ctxSt) {
      new Chart(ctxSt, {
        type: 'bar',
        data: {
          labels: ['Falhas', 'Alertas', 'Aprovados'],
          datasets: [{
            label: 'Verificações',
            data: [D.failed||0, D.warnings||0, D.passed||0],
            backgroundColor: [
              'rgba(239,68,68,0.75)',
              'rgba(249,115,22,0.75)',
              'rgba(34,197,94,0.75)',
            ],
            borderColor: ['#ef4444','#f97316','#22c55e'],
            borderWidth: 1,
            borderRadius: 6,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#0f0f1e',
              borderColor: 'rgba(255,255,255,0.1)',
              borderWidth: 1,
              titleColor: '#e2e8f0', bodyColor: '#94a3b8',
            }
          },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#64748b' }, border: { color: 'rgba(255,255,255,0.07)' } },
            y: { grid: { display: false }, ticks: { color: '#94a3b8' }, border: { display: false } }
          }
        }
      });
    }

    // ── 3. Risk Radar ──────────────────────────────────────────────
    const ctxRisk = document.getElementById('chartRisk');
    if (ctxRisk && D.groups && D.groups.length) {
      new Chart(ctxRisk, {
        type: 'radar',
        data: {
          labels: D.groups.map(g => g.label),
          datasets: [{
            label: 'Score por Domínio',
            data: D.groups.map(g => g.score),
            backgroundColor: 'rgba(249,115,22,0.12)',
            borderColor: '#f97316',
            borderWidth: 2,
            pointBackgroundColor: '#f97316',
            pointBorderColor: '#0a0a14',
            pointBorderWidth: 2,
            pointRadius: 4,
            pointHoverRadius: 6,
          }, {
            label: 'Meta (100)',
            data: D.groups.map(() => 100),
            backgroundColor: 'rgba(0,212,255,0.04)',
            borderColor: 'rgba(0,212,255,0.2)',
            borderWidth: 1,
            borderDash: [4, 4],
            pointRadius: 0,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { labels: { color: '#64748b', padding: 14, boxWidth: 12 } },
            tooltip: {
              backgroundColor: '#0f0f1e',
              borderColor: 'rgba(255,255,255,0.1)',
              borderWidth: 1,
              titleColor: '#e2e8f0', bodyColor: '#94a3b8',
            }
          },
          scales: {
            r: {
              min: 0, max: 100,
              ticks: { stepSize: 25, color: '#475569', backdropColor: 'transparent', font: { size: 10 } },
              grid: { color: 'rgba(255,255,255,0.06)' },
              pointLabels: { color: '#94a3b8', font: { size: 11 } },
              angleLines: { color: 'rgba(255,255,255,0.06)' }
            }
          }
        }
      });
    }

    // ── 4. Cover Gauge (arc) ───────────────────────────────────────
    const ctxGauge = document.getElementById('coverGauge');
    if (ctxGauge) {
      const score = D.score || 0;
      const color = score >= 88 ? '#22c55e' : score >= 52 ? '#f97316' : '#ef4444';
      new Chart(ctxGauge, {
        type: 'doughnut',
        data: {
          datasets: [{
            data: [score, 100 - score],
            backgroundColor: [color, 'rgba(255,255,255,0.05)'],
            borderColor: 'transparent',
            borderWidth: 0,
          }]
        },
        options: {
          responsive: false,
          cutout: '80%',
          rotation: -90,
          circumference: 180,
          plugins: { legend: { display: false }, tooltip: { enabled: false } },
          animation: { duration: 1200, easing: 'easeOutQuart' }
        }
      });
    }

    // ── 5. Services horizontal bar ─────────────────────────────────
    const ctxSvc = document.getElementById('chartServices');
    if (ctxSvc && S.length) {
      const COLORS = ['#f97316','#ef4444','#eab308','#22c55e','#3b82f6','#a855f7','#00d4ff','#ec4899','#14b8a6','#f59e0b'];
      new Chart(ctxSvc, {
        type: 'bar',
        data: {
          labels: S.map(s => s.label.length > 28 ? s.label.slice(0, 26) + '…' : s.label),
          datasets: [{
            label: 'R$',
            data: S.map(s => s.value),
            backgroundColor: S.map((_, i) => COLORS[i % COLORS.length] + 'cc'),
            borderColor:     S.map((_, i) => COLORS[i % COLORS.length]),
            borderWidth: 1,
            borderRadius: 5,
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: '#0f0f1e', borderColor: 'rgba(255,255,255,0.1)', borderWidth: 1,
              titleColor: '#e2e8f0', bodyColor: '#94a3b8',
              callbacks: {
                label: ctx => ' R$ ' + ctx.parsed.x.toLocaleString('pt-BR')
              }
            }
          },
          scales: {
            x: {
              grid: { color: 'rgba(255,255,255,0.05)' },
              ticks: { color: '#64748b', callback: v => 'R$ ' + Number(v).toLocaleString('pt-BR') },
              border: { color: 'rgba(255,255,255,0.07)' }
            },
            y: {
              grid: { display: false },
              ticks: { color: '#94a3b8' },
              border: { display: false }
            }
          }
        }
      });
    }

  }); // end waitForChartJS
})();
</script>`;

// ── Hex → rgb helper (for CSS rgba) ────────────────────────────────
function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  if (!r) return '100,116,139';
  return `${parseInt(r[1],16)},${parseInt(r[2],16)},${parseInt(r[3],16)}`;
}

// ── Main generator ─────────────────────────────────────────────────
function generateConsultingReport(auditData, consultingConfig, darkWebIntel) {
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

  const cfg    = consultingConfig || {};
  const prices = cfg.prices || {};

  const auditDate    = evidence.timestamp
    ? new Date(evidence.timestamp).toLocaleDateString('pt-BR')
    : new Date().toLocaleDateString('pt-BR');
  const generatedDate = new Date().toLocaleDateString('pt-BR');

  const auditId = evidence.auditId || null;

  const cover     = buildCover(projectUrl, auditDate, score, grade, productionReady, cfg);
  const summary   = buildSummary(projectUrl, auditDate, score, grade, failed, warnings, totalChecks, duration, results);
  const darkWeb   = buildDarkWebSection(darkWebIntel, auditId);
  const vulns     = buildVulnerabilities(results);
  const services  = buildServices(results, prices);
  const controls  = buildControls(results);
  const nextSteps = buildNextSteps(results);
  const footer    = buildFooter(evidence, cfg, generatedDate);

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Proposta de Consultoria — ${esc(projectUrl)}</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"><\/script>
  <style>${CSS}</style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">&#8659; Exportar PDF</button>
  <div class="page">
    <section class="cover">${cover}</section>
    ${summary}
    ${darkWeb}
    ${vulns}
    ${services}
    ${controls}
    ${nextSteps}
    ${footer}
  </div>
  ${CHART_SCRIPT}
</body>
</html>`;
}

module.exports = { generateConsultingReport };
