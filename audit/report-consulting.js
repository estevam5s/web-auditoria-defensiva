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
/* ── CSS Variables ── */
:root{
  --clr-navy:        #1a2744;
  --clr-navy-deep:   #0f1729;
  --clr-navy-mid:    #2d4a8a;
  --clr-blue:        #2563eb;
  --clr-sky:         #0ea5e9;
  --clr-indigo:      #6366f1;
  --clr-bg:          #f8faff;
  --clr-bg-card:     #ffffff;
  --clr-border:      #e2e8f2;
  --clr-text:        #1f2937;
  --clr-text-muted:  #6b7280;
  --clr-success:     #16a34a;
  --clr-danger:      #dc2626;
  --clr-warning:     #ca8a04;
  --clr-orange:      #ea580c;
  --shadow-sm:       0 1px 4px rgba(15,23,41,.06);
  --shadow-md:       0 4px 16px rgba(15,23,41,.10);
  --shadow-lg:       0 8px 32px rgba(15,23,41,.14);
  --radius-md:       10px;
  --radius-sm:       6px
}

/* ── Reset & Base ── */
*{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{
  font-family:'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif;
  background:var(--clr-bg);color:var(--clr-text);font-size:14px;line-height:1.65
}

/* ── Custom Scrollbar ── */
::-webkit-scrollbar{width:7px;height:7px}
::-webkit-scrollbar-track{background:var(--clr-navy-deep);border-radius:4px}
::-webkit-scrollbar-thumb{
  background:linear-gradient(to bottom,var(--clr-navy-mid),var(--clr-blue));
  border-radius:4px;border:1px solid rgba(255,255,255,.08)
}
::-webkit-scrollbar-thumb:hover{background:linear-gradient(to bottom,var(--clr-blue),var(--clr-sky))}

/* ── Animations ── */
@keyframes fade-up{
  from{opacity:0;transform:translateY(18px)}
  to  {opacity:1;transform:translateY(0)}
}
@keyframes ring-spin{
  from{transform:rotate(0deg)}
  to  {transform:rotate(360deg)}
}

/* ── Print / Export Button ── */
.print-btn{
  position:fixed;top:24px;right:24px;z-index:9999;
  background:linear-gradient(135deg,var(--clr-navy) 0%,var(--clr-blue) 100%);
  color:#fff;border:none;padding:11px 24px;border-radius:9px;
  cursor:pointer;font-size:13px;font-weight:700;letter-spacing:.4px;
  box-shadow:0 4px 18px rgba(37,99,235,.40);transition:all .22s ease;
  display:flex;align-items:center;gap:8px
}
.print-btn::before{content:'⬇';font-size:14px;filter:drop-shadow(0 1px 2px rgba(0,0,0,.3))}
.print-btn:hover{
  background:linear-gradient(135deg,var(--clr-navy-mid) 0%,var(--clr-sky) 100%);
  box-shadow:0 6px 24px rgba(37,99,235,.55);transform:translateY(-2px)
}
.print-btn:active{transform:translateY(0);box-shadow:0 3px 10px rgba(26,39,68,.3)}

/* ── Cover Page ── */
.cover{
  background:linear-gradient(160deg,#0b1525 0%,#1a2744 45%,#0f2040 100%);
  border-top:none;
  padding:64px 60px 56px;
  max-width:none;
  position:relative;
  overflow:hidden
}
.cover::before{
  content:'';position:absolute;top:0;left:0;right:0;bottom:0;
  background-image:
    radial-gradient(ellipse 60% 40% at 80% 20%,rgba(37,99,235,.18) 0%,transparent 60%),
    radial-gradient(ellipse 40% 60% at 10% 80%,rgba(99,102,241,.12) 0%,transparent 55%),
    repeating-linear-gradient(
      45deg,
      transparent,
      transparent 28px,
      rgba(255,255,255,.015) 28px,
      rgba(255,255,255,.015) 29px
    );
  pointer-events:none
}
.cover::after{
  content:'';position:absolute;top:0;left:0;right:0;height:4px;
  background:linear-gradient(90deg,var(--clr-blue) 0%,var(--clr-sky) 50%,var(--clr-indigo) 100%);
  box-shadow:0 0 24px rgba(14,165,233,.55)
}
.cover-top-bar{
  display:flex;justify-content:space-between;align-items:flex-start;
  margin-bottom:48px;padding-bottom:28px;
  border-bottom:1px solid rgba(255,255,255,.12);
  position:relative;z-index:1
}
.cover-consultant-name{font-size:18px;font-weight:700;color:#e2e8f0;margin-bottom:4px}
.cover-consultant-detail{font-size:13px;color:#94a3b8;line-height:1.75}
.cover-date-label{font-size:10px;color:#64748b;text-transform:uppercase;letter-spacing:1.2px;margin-bottom:3px}
.cover-date-value{font-size:13px;font-weight:600;color:#cbd5e1;text-align:right}
.cover-category{
  font-size:10px;color:var(--clr-sky);text-transform:uppercase;
  letter-spacing:2.5px;margin-bottom:10px;
  position:relative;z-index:1;font-weight:600
}
.cover-title{
  font-size:36px;font-weight:800;
  color:#f1f5ff;
  line-height:1.2;word-break:break-all;margin-bottom:36px;
  position:relative;z-index:1;
  text-shadow:0 2px 12px rgba(0,0,0,.4)
}
.cover-score-row{display:flex;align-items:center;gap:30px;flex-wrap:wrap;position:relative;z-index:1}

/* ── Score Circle ── */
.score-circle{
  width:120px;height:120px;border-radius:50%;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  color:#fff;flex-shrink:0;
  box-shadow:0 8px 32px rgba(0,0,0,.25);
  position:relative
}
.score-circle::after{
  content:'';
  position:absolute;inset:-5px;border-radius:50%;
  border:3px solid transparent;
  border-top-color:rgba(255,255,255,.35);
  border-right-color:rgba(255,255,255,.15);
  animation:ring-spin 3.5s linear infinite;
  pointer-events:none
}
.score-num{font-size:38px;font-weight:800;line-height:1;letter-spacing:-1px}
.score-lbl{font-size:11px;opacity:.9;margin-top:2px;font-weight:600;letter-spacing:.4px}
.cover-score-info-title{font-size:20px;font-weight:800;color:#e2e8f0;margin-bottom:8px}

/* ── Sections ── */
section{
  background:var(--clr-bg-card);
  max-width:960px;margin:22px auto;
  padding:40px 48px;
  border-radius:var(--radius-md);
  box-shadow:var(--shadow-md);
  border:1px solid var(--clr-border);
  animation:fade-up 0.5s ease both
}
section.cover{
  background:transparent;border-radius:0;box-shadow:none;
  border:none;max-width:none;margin:0;
  animation:none
}

/* ── Typography ── */
h1{font-size:26px;font-weight:800;color:var(--clr-navy);margin-bottom:6px;line-height:1.3}
h2{
  font-size:18px;font-weight:700;color:var(--clr-navy);
  margin-bottom:22px;padding:14px 16px 14px 18px;
  border-left:4px solid transparent;
  border-image:linear-gradient(to bottom,var(--clr-navy),var(--clr-blue)) 1;
  background:linear-gradient(90deg,#f4f7ff 0%,transparent 100%);
  border-radius:0 var(--radius-sm) var(--radius-sm) 0;
  display:flex;align-items:center;gap:10px
}
h2 .sec-icon{font-size:20px}
h3{font-size:14px;font-weight:700;color:var(--clr-navy);margin-bottom:6px}
p{margin-bottom:12px;color:#374151;line-height:1.7}
strong{color:var(--clr-navy)}

/* ── Summary callout ── */
.summary-box{
  background:linear-gradient(90deg,#f0f5ff 0%,#fafbff 100%);
  border-left:4px solid var(--clr-blue);
  border-radius:0 8px 8px 0;padding:20px 24px;margin-bottom:22px;
  font-size:14px;color:#374151;line-height:1.8;
  box-shadow:0 2px 8px rgba(37,99,235,.07)
}
.summary-stats{
  display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:22px
}
.stat-card{
  background:linear-gradient(135deg,#fafbff 0%,#f4f7ff 100%);
  border:1px solid var(--clr-border);border-radius:10px;
  padding:16px 16px 14px;text-align:center;
  box-shadow:var(--shadow-sm);
  transition:transform .2s ease,box-shadow .2s ease;
  border-top:3px solid var(--clr-blue)
}
.stat-card:hover{transform:translateY(-3px);box-shadow:var(--shadow-md)}
.stat-card .stat-val{font-size:26px;font-weight:800;color:var(--clr-navy);line-height:1}
.stat-card .stat-label{font-size:11px;color:var(--clr-text-muted);margin-top:5px;text-transform:uppercase;letter-spacing:.6px}

/* ── Tables ── */
.table-wrap{overflow-x:auto;margin-bottom:22px;border-radius:10px;border:1px solid var(--clr-border);box-shadow:var(--shadow-sm)}
table{width:100%;border-collapse:collapse;font-size:13px}
thead{position:sticky;top:0;z-index:2}
thead th{
  background:linear-gradient(135deg,var(--clr-navy) 0%,#243260 100%);
  color:#fff;
  padding:12px 16px;text-align:left;
  font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.7px
}
thead th:first-child{border-radius:10px 0 0 0}
thead th:last-child{border-radius:0 10px 0 0}
td{padding:12px 16px;border-bottom:1px solid var(--clr-border);vertical-align:top;color:#374151}
tr:nth-child(even) td{background:#f8faff}
tr:last-child td{border-bottom:none}
tr:hover td{background:#eef3ff;transition:background .15s ease}
tfoot td{
  background:linear-gradient(135deg,var(--clr-navy) 0%,#243260 100%)!important;
  color:#fff!important;font-weight:700;border-bottom:none;padding:13px 16px
}
tfoot tr td:last-child{font-size:15px}

/* ── Badges ── */
.badge{
  display:inline-block;padding:3px 10px;border-radius:20px;
  font-size:10px;font-weight:800;color:#fff;letter-spacing:.5px;
  white-space:nowrap;box-shadow:0 1px 4px rgba(0,0,0,.18)
}

/* ── Group header ── */
.group-hdr{
  display:flex;align-items:center;gap:10px;
  margin-top:28px;margin-bottom:12px;
  padding:11px 16px;
  background:linear-gradient(90deg,#f0f4ff 0%,#fafbff 100%);
  border-left:4px solid transparent;
  border-image:linear-gradient(to bottom,var(--clr-blue),var(--clr-indigo)) 1;
  border-radius:0 var(--radius-sm) var(--radius-sm) 0;
  box-shadow:var(--shadow-sm)
}
.group-hdr h3{margin:0;font-size:14px;font-weight:700;color:var(--clr-navy)}

/* ── Services ── */
.service-note{font-size:12px;color:var(--clr-text-muted);font-style:italic;margin-top:8px}
.service-total-label{font-size:13px}

/* ── Controls grid ── */
.controls-grid{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));
  gap:8px 14px;margin-top:6px
}
.ctrl-item{
  display:flex;align-items:center;gap:9px;
  padding:9px 12px;font-size:13px;
  background:linear-gradient(90deg,#f0fdf4 0%,#f8fff9 100%);
  border-radius:7px;
  border:1px solid #bbf7d0;
  box-shadow:var(--shadow-sm);
  transition:transform .18s ease,box-shadow .18s ease
}
.ctrl-item:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(22,163,74,.15)}
.ctrl-check{font-size:15px;font-weight:800;color:var(--clr-success);flex-shrink:0}

/* ── Empty states ── */
.empty-ok{
  background:#f0fdf4;border:1px solid #86efac;border-radius:9px;
  padding:17px 22px;color:#166534;font-weight:600;
  display:flex;align-items:center;gap:12px;font-size:14px;
  box-shadow:var(--shadow-sm)
}
.empty-ok::before{content:'✓';font-size:20px;color:var(--clr-success);flex-shrink:0}
.empty-warn{
  background:#fffbeb;border:1px solid #fcd34d;border-radius:9px;
  padding:17px 22px;color:#92400e;font-weight:600;
  display:flex;align-items:center;gap:12px;font-size:14px;
  box-shadow:var(--shadow-sm)
}

/* ── Next Steps list ── */
.next-steps-list{list-style:none;padding:0;counter-reset:steps}
.next-steps-list li{
  counter-increment:steps;
  padding:16px 18px 16px 60px;
  position:relative;
  border:1px solid var(--clr-border);border-radius:10px;
  margin-bottom:11px;background:#fff;
  box-shadow:var(--shadow-sm);
  transition:box-shadow .2s ease,transform .2s ease
}
.next-steps-list li:hover{box-shadow:var(--shadow-md);transform:translateX(2px)}
.next-steps-list li::before{
  content:counter(steps);
  position:absolute;left:16px;top:50%;transform:translateY(-50%);
  width:28px;height:28px;border-radius:50%;
  background:linear-gradient(135deg,var(--clr-navy) 0%,var(--clr-blue) 100%);
  color:#fff;
  display:flex;align-items:center;justify-content:center;
  font-size:12px;font-weight:800;
  box-shadow:0 2px 8px rgba(37,99,235,.30)
}
.next-step-title{display:flex;align-items:center;gap:8px;margin-bottom:3px;font-weight:700;color:var(--clr-navy);font-size:14px}
.next-step-desc{font-size:13px;color:var(--clr-text-muted)}

/* ── Footer ── */
.footer-wrap{
  background:linear-gradient(135deg,#0f1729 0%,#1a2744 50%,#0d1520 100%);
  color:#cbd5e1;
  padding:40px 60px;font-size:13px;margin-top:0;
  border-top:3px solid transparent;
  border-image:linear-gradient(90deg,var(--clr-blue),var(--clr-sky),var(--clr-indigo)) 1
}
.footer-grid{display:grid;grid-template-columns:1fr 1fr;gap:32px;margin-bottom:22px}
.footer-section-label{
  font-size:10px;text-transform:uppercase;letter-spacing:1.8px;
  color:#475569;margin-bottom:10px;font-weight:700
}
.footer-name{font-size:15px;font-weight:800;color:#e2e8f0;margin-bottom:4px}
.footer-detail{color:#94a3b8;margin-bottom:3px;font-size:13px}
.footer-doc-item{margin-bottom:5px;color:#94a3b8}
.footer-doc-label{color:#475569;font-size:11px}
.hash{font-family:'Courier New',Courier,monospace;font-size:11px;color:#64748b}
.disclaimer{
  font-size:11px;color:#475569;font-style:italic;
  border-top:1px solid rgba(255,255,255,.07);padding-top:18px;margin-top:6px;line-height:1.75
}

/* ── Divider ── */
.page-break-hint{height:20px;background:transparent}

/* ── Dark Web Intelligence Section ── */
.dw-banner{
  border-radius:12px;padding:22px 26px;margin-bottom:22px;
  display:flex;align-items:center;gap:20px;flex-wrap:wrap;
  backdrop-filter:blur(6px)
}
.dw-banner.dark-web{
  background:linear-gradient(135deg,#1a0505 0%,#2d0a0a 100%);
  border:1px solid rgba(239,68,68,.45);
  color:#fca5a5;
  box-shadow:0 4px 24px rgba(239,68,68,.25)
}
.dw-banner.deep-web{
  background:linear-gradient(135deg,#150d1c 0%,#200f30 100%);
  border:1px solid rgba(168,85,247,.45);
  color:#d8b4fe;
  box-shadow:0 4px 24px rgba(168,85,247,.20)
}
.dw-banner.surface-web{
  background:linear-gradient(135deg,#1c1500 0%,#2e2000 100%);
  border:1px solid rgba(245,158,11,.45);
  color:#fde68a;
  box-shadow:0 4px 24px rgba(245,158,11,.18)
}
.dw-banner.clean{
  background:linear-gradient(135deg,#052e16 0%,#0c3d20 100%);
  border:1px solid rgba(34,197,94,.45);
  color:#86efac;
  box-shadow:0 4px 24px rgba(34,197,94,.18)
}
.dw-tier-icon{font-size:38px;flex-shrink:0;filter:drop-shadow(0 2px 6px rgba(0,0,0,.4))}
.dw-tier-label{font-size:13px;font-weight:800;letter-spacing:2px;text-transform:uppercase;opacity:.8;margin-bottom:2px}
.dw-tier-title{font-size:22px;font-weight:800;line-height:1.2}
.dw-tier-desc{font-size:13px;opacity:.75;margin-top:3px}
.dw-risk-badge{
  margin-left:auto;flex-shrink:0;
  display:flex;flex-direction:column;align-items:center;justify-content:center;
  width:76px;height:76px;border-radius:50%;
  font-weight:800;border:2px solid currentColor;
  background:rgba(0,0,0,.25);
  box-shadow:0 0 16px rgba(0,0,0,.35)
}
.dw-risk-num{font-size:26px;line-height:1}
.dw-risk-lbl{font-size:10px;opacity:.7;text-transform:uppercase;letter-spacing:.5px}

.dw-metrics{
  display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));
  gap:10px;margin-bottom:18px
}
.dw-metric{
  background:#fff;border:1px solid var(--clr-border);border-radius:9px;
  padding:13px 15px;position:relative;overflow:hidden;
  box-shadow:var(--shadow-sm);transition:transform .18s ease,box-shadow .18s ease
}
.dw-metric:hover{transform:translateY(-2px);box-shadow:var(--shadow-md)}
.dw-metric::before{
  content:'';position:absolute;top:0;left:0;width:4px;height:100%;
  background:var(--dw-accent,var(--clr-navy));border-radius:0
}
.dw-metric-val{font-size:23px;font-weight:800;color:var(--clr-navy);line-height:1}
.dw-metric-label{font-size:11px;color:var(--clr-text-muted);margin-top:3px;text-transform:uppercase;letter-spacing:.5px}
.dw-metric.warn .dw-metric-val{color:var(--clr-danger)}
.dw-metric.warn{--dw-accent:#dc2626}
.dw-metric.ok .dw-metric-val{color:var(--clr-success)}
.dw-metric.ok{--dw-accent:#16a34a}

.dw-subdomains{
  display:flex;flex-wrap:wrap;gap:6px;margin-top:8px
}
.dw-subdomain{
  background:#f0f4ff;border:1px solid #c7d2fe;border-radius:4px;
  padding:3px 9px;font-size:11px;font-family:'Courier New',monospace;color:#3730a3
}
.dw-network-row{
  display:flex;flex-wrap:wrap;gap:8px 24px;margin-top:10px;
  padding:13px 16px;background:#f8faff;border-radius:9px;border:1px solid var(--clr-border);
  box-shadow:var(--shadow-sm)
}
.dw-net-item{font-size:12px;color:#4b5563}
.dw-net-label{font-size:10px;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;margin-bottom:1px}
.dw-darkweb-link{
  display:inline-flex;align-items:center;gap:7px;
  background:linear-gradient(135deg,var(--clr-navy) 0%,var(--clr-navy-mid) 100%);
  color:#fff;text-decoration:none;
  padding:9px 20px;border-radius:7px;font-size:12px;font-weight:700;
  margin-top:14px;transition:all .22s ease;
  box-shadow:0 3px 12px rgba(26,39,68,.30);letter-spacing:.3px
}
.dw-darkweb-link:hover{ background: #2d4a8a; box-shadow: 0 4px 16px rgba(45,74,138,.4); transform: translateY(-1px); }

/* ── Print Media ── */
@media print{
  body{background:#fff;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .print-btn{display:none!important}
  section{
    page-break-inside:avoid;max-width:none;
    box-shadow:none!important;border:none!important;
    margin:0;border-radius:0;padding:32px 40px;
    animation:none
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
  .dw-banner{-webkit-print-color-adjust:exact}
  .dw-metric{page-break-inside:avoid}
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

// ── Section: Dark / Deep / Surface Web Intelligence ────────────────
function buildDarkWebSection(intel, auditId) {
  // If no intel, show a minimal "not analyzed" card
  if (!intel) {
    return `<section>
  <h2><span class="sec-icon">🌐</span> Inteligência Dark/Deep/Surface Web</h2>
  <div class="empty-warn" style="background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:16px 20px;color:#92400e;font-weight:600;display:flex;align-items:center;gap:10px;font-size:14px">
    ⚠ Análise de inteligência OSINT/Dark Web não disponível para esta auditoria.
    ${auditId ? `<a class="dw-darkweb-link" href="/darkweb/${esc(auditId)}" style="margin-top:0;margin-left:auto">🕵️ Executar Agora</a>` : ''}
  </div>
</section>`;
  }

  const level = intel.threatLevel;

  const tierMap = {
    DARK_WEB:    { cls: 'dark-web',    icon: '🕸️',  label: 'Dark Web',    title: 'Presença Detectada na Dark Web',    desc: 'Ameaças ativas, malware ou credenciais expostas identificadas em fontes da dark web.' },
    DEEP_WEB:    { cls: 'deep-web',    icon: '🔍',  label: 'Deep Web',    title: 'Atividade Suspeita na Deep Web',    desc: 'Indicadores de comprometimento moderados. Monitoramento contínuo recomendado.' },
    SURFACE_WEB: { cls: 'surface-web', icon: '🌐',  label: 'Surface Web', title: 'Riscos na Surface Web',             desc: 'Riscos menores identificados em fontes abertas. Acompanhamento indicado.' },
  };
  const cleanTier = { cls: 'clean', icon: '✅', label: 'Limpo', title: 'Nenhuma Ameaça Detectada', desc: 'Nenhuma presença em listas de ameaças, malware ou vazamentos conhecidos.' };
  const tier = tierMap[level] || cleanTier;

  const breachCount   = intel.hibp?.domainBreaches?.length || 0;
  const malwareCount  = intel.otx?.malwareCount            || 0;
  const pulseCount    = intel.otx?.pulseCount              || 0;
  const urlMalicious  = intel.urlscan?.malicious           || 0;
  const urlSuspicious = intel.urlscan?.suspicious          || 0;
  const subCount      = intel.subdomains?.count            || 0;
  const vtMalicious   = intel.virustotal?.malicious        || 0;
  const riskScore     = intel.riskScore ?? 0;

  // Banner
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

  // Metrics
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

  // Domain breaches detail
  let breachDetail = '';
  if (breachCount > 0) {
    const rows = (intel.hibp.domainBreaches || []).map(b => `<tr>
      <td style="font-weight:600;color:#1a2744">${esc(b.title || b.name)}</td>
      <td>${esc(b.breachDate || '—')}</td>
      <td style="text-align:right;color:#dc2626;font-weight:600">${b.pwnCount ? b.pwnCount.toLocaleString('pt-BR') : '—'}</td>
      <td style="color:#4b5563;font-size:12px">${esc((b.dataClasses || []).slice(0, 4).join(', '))}</td>
    </tr>`).join('');
    breachDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Vazamentos por Domínio (HIBP)</h3>
      <span class="badge" style="background:#dc2626">${breachCount}</span>
    </div>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Incidente</th><th>Data</th><th style="text-align:right">Contas Afetadas</th><th>Dados Expostos</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
  }

  // Malware families
  let malwareDetail = '';
  const families = intel.otx?.malwareFamilies || [];
  if (families.length > 0) {
    malwareDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Famílias de Malware Detectadas (OTX)</h3>
      <span class="badge" style="background:#ea580c">${families.length}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin:10px 0">
      ${families.map(f => `<span class="badge" style="background:#ea580c;font-size:11px;padding:4px 10px">${esc(f)}</span>`).join('')}
    </div>`;
  }

  // Subdomains
  let subDetail = '';
  const subs = intel.subdomains?.subdomains || [];
  if (subs.length > 0) {
    subDetail = `<div class="group-hdr" style="margin-top:20px">
      <h3>Subdomínios Descobertos (crt.sh)</h3>
      <span class="badge" style="background:#2563eb">${subCount}</span>
    </div>
    <div class="dw-subdomains">${subs.map(s => `<span class="dw-subdomain">${esc(s)}</span>`).join('')}</div>`;
  }

  // Network info
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

  const cfg   = consultingConfig || {};
  const prices = cfg.prices || {};

  const auditDate    = evidence.timestamp
    ? new Date(evidence.timestamp).toLocaleDateString('pt-BR')
    : new Date().toLocaleDateString('pt-BR');
  const generatedDate = new Date().toLocaleDateString('pt-BR');

  const auditId = evidence.auditId || null;

  const cover      = buildCover(projectUrl, auditDate, score, grade, productionReady, cfg);
  const summary    = buildSummary(projectUrl, auditDate, score, grade, failed, warnings, totalChecks, duration);
  const darkWeb    = buildDarkWebSection(darkWebIntel, auditId);
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
  ${darkWeb}
  ${vulns}
  ${services}
  ${controls}
  ${nextSteps}
  ${footer}
</body>
</html>`;
}

module.exports = { generateConsultingReport };
