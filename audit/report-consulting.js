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
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:#fff;color:#1f2937;font-size:14px;line-height:1.6}
.print-btn{position:fixed;top:20px;right:20px;z-index:1000;background:#1a2744;color:#fff;border:none;padding:10px 20px;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600}
.print-btn:hover{background:#2d3e6e}
section{padding:40px;max-width:900px;margin:0 auto 0 auto}
section+section{border-top:1px solid #e5e7eb;padding-top:40px;margin-top:0}
h1{font-size:28px;color:#1a2744;margin-bottom:8px}
h2{font-size:20px;color:#1a2744;margin-bottom:16px;border-bottom:2px solid #1a2744;padding-bottom:8px}
h3{font-size:15px;color:#1a2744;margin-bottom:8px}
p{margin-bottom:12px;color:#374151}
table{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:13px}
th{background:#1a2744;color:#fff;padding:10px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #e5e7eb}
tr:nth-child(even) td{background:#f9fafb}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;color:#fff}
.cover{background:#fff;border-top:6px solid #1a2744;padding:60px 40px;max-width:none}
.score-circle{width:110px;height:110px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;color:#fff;flex-shrink:0}
.score-num{font-size:34px;font-weight:700;line-height:1}
.score-lbl{font-size:11px;opacity:.85}
.controls-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px}
.ctrl-item{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:13px}
.total-row td{background:#1a2744!important;color:#fff!important;font-weight:700;border-bottom:none}
.empty-ok{background:#f0fdf4;border:1px solid #16a34a;border-radius:6px;padding:14px 18px;color:#15803d;font-weight:600;margin-bottom:16px}
.empty-warn{background:#fef3c7;border:1px solid #ca8a04;border-radius:6px;padding:14px 18px;color:#92400e;margin-bottom:16px}
.group-hdr{display:flex;align-items:center;gap:10px;margin-top:24px;margin-bottom:8px}
.footer-wrap{background:#f5f7fa;border-top:3px solid #1a2744;padding:30px 40px;font-size:13px}
.footer-grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.disclaimer{font-size:11px;color:#6b7280;margin-top:20px;font-style:italic;border-top:1px solid #e5e7eb;padding-top:12px}
.hash{font-family:monospace;font-size:11px;color:#6b7280}
@media print{
  .print-btn{display:none!important}
  section{page-break-before:always;max-width:none}
  section.cover{page-break-before:avoid}
  *{box-shadow:none!important}
  body{background:#fff;color:#000}
  tr{page-break-inside:avoid}
  .footer-wrap{page-break-before:always}
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
  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:40px">
    <div>
      <h1 style="font-size:24px;margin-bottom:6px">${esc(cfg.name)}</h1>
      ${contactLines}
    </div>
    <div style="text-align:right;color:#6b7280;font-size:12px;padding-top:4px">
      <div style="text-transform:uppercase;letter-spacing:.5px">Emitido em</div>
      <div style="font-weight:600;color:#1f2937">${esc(auditDate)}</div>
    </div>
  </div>

  <div style="border-top:1px solid #e5e7eb;padding-top:40px">
    <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Proposta de Consultoria em Segurança</div>
    <h1 style="font-size:32px;color:#1a2744;word-break:break-all">${esc(projectUrl)}</h1>
  </div>

  <div style="display:flex;align-items:center;gap:24px;margin-top:36px">
    <div class="score-circle" style="background:${scoreColor}">
      <span class="score-num">${score}</span>
      <span class="score-lbl">Grau ${esc(grade.grade || '?')}</span>
    </div>
    <div>
      <div style="font-size:18px;font-weight:700;color:#1a2744;margin-bottom:6px">${esc(grade.label || '')}</div>
      <span class="badge" style="background:${esc(pvColor)};color:#000;font-size:12px;padding:4px 14px;border-radius:16px">${esc(pv.label || '')}</span>
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
  <h2>Sumário Executivo</h2>
  <p>
    A auditoria de segurança realizada em <strong>${esc(projectUrl)}</strong> em ${esc(auditDate)}
    identificou <strong>${failed}</strong> falha(s) e <strong>${warnings}</strong> alerta(s)
    em um total de <strong>${totalChecks}</strong> verificações, com duração de ${esc(duration)}.
    O score de segurança obtido foi <strong>${score}/100</strong>
    (Grau <strong>${esc(grade.grade || '?')}</strong> — ${esc(grade.label || '')}).
    ${esc(fraseFinal)}
  </p>
</section>`;
}

// ── Section: Vulnerability Assessment ─────────────────────────────
function buildVulnerabilities(results) {
  const issues = results.filter(r => r.status === 'FAIL' || r.status === 'WARN');

  if (issues.length === 0) {
    return `<section>
  <h2>Levantamento de Vulnerabilidades</h2>
  <div class="empty-ok">✓ Nenhuma vulnerabilidade encontrada — sistema em conformidade.</div>
</section>`;
  }

  // Group by semantic category
  const grouped = {};
  for (const r of issues) {
    const g = getGroup(r.check || '');
    if (!grouped[g]) grouped[g] = [];
    grouped[g].push(r);
  }

  let html = '<section><h2>Levantamento de Vulnerabilidades por Categoria</h2>';

  for (const [group, items] of Object.entries(grouped)) {
    const maxSev  = maxSeverity(items);
    const sevColor = SEV_COLORS[maxSev] || '#6b7280';
    const sevLabel = SEV_LABELS[maxSev] || maxSev.toUpperCase();
    const label    = getGroupLabel(group);

    html += `<div class="group-hdr">
      <h3 style="margin:0">${esc(label)}</h3>
      <span class="badge" style="background:${sevColor}">${sevLabel}</span>
    </div>
    <table>
      <thead><tr><th>Check</th><th>Status</th><th>Severidade</th><th>Descrição</th></tr></thead>
      <tbody>`;

    for (const r of items) {
      const sc = SEV_COLORS[r.severity] || '#6b7280';
      const sl = SEV_LABELS[r.severity] || (r.severity || '').toUpperCase();
      const statusColor = r.status === 'FAIL' ? '#dc2626' : '#ea580c';
      html += `<tr>
        <td>${esc(r.check || '')}</td>
        <td><span class="badge" style="background:${statusColor}">${esc(r.status)}</span></td>
        <td><span class="badge" style="background:${sc}">${sl}</span></td>
        <td>${esc(r.message || '')}</td>
      </tr>`;
    }

    html += '</tbody></table>';
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
    const value = s.price(prices);
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
  <h2>Serviços de Consultoria Recomendados</h2>
  <table>
    <thead><tr><th>Serviço</th><th>Descrição</th><th style="text-align:center">Estimativa</th><th style="text-align:right">Valor (R$)</th></tr></thead>
    <tbody>
      ${rows}
    </tbody>
    <tfoot>
      <tr class="total-row"><td colspan="3"><strong>Total Estimado</strong></td><td style="text-align:right">R$ ${total.toLocaleString('pt-BR')}</td></tr>
    </tfoot>
  </table>
  ${extraNote}
  <p style="font-size:12px;color:#6b7280;font-style:italic">Valores estimados. Proposta formal mediante definição detalhada do escopo.</p>
</section>`;
}

// ── Section: Approved Controls ─────────────────────────────────────
function buildControls(results) {
  const passed = results.filter(r => r.status === 'PASS');

  if (passed.length === 0) {
    return `<section>
  <h2>Controles Aprovados</h2>
  <p style="color:#6b7280">Nenhum controle aprovado registrado.</p>
</section>`;
  }

  const items = passed.map(r =>
    `<div class="ctrl-item"><span style="color:#16a34a;font-weight:700">✓</span> ${esc(r.check || '')}</div>`
  ).join('');

  return `<section>
  <h2>Controles Aprovados (${passed.length})</h2>
  <div class="controls-grid">${items}</div>
</section>`;
}

// ── Section: Next Steps ────────────────────────────────────────────
function buildNextSteps(results) {
  const fails = results.filter(r => r.status === 'FAIL');

  if (fails.length === 0) {
    return `<section>
  <h2>Próximos Passos</h2>
  <div class="empty-ok">✓ Nenhuma ação imediata necessária — mantenha monitoramento contínuo.</div>
</section>`;
  }

  const sorted = [...fails].sort((a, b) =>
    (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5)
  );

  const items = sorted.slice(0, 10).map((r, i) => {
    const sc = SEV_COLORS[r.severity] || '#6b7280';
    const sl = SEV_LABELS[r.severity] || '';
    return `<li style="margin-bottom:12px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:2px">
        <strong>${esc(r.check || '')}</strong>
        <span class="badge" style="background:${sc}">${sl}</span>
      </div>
      <div style="color:#4b5563;font-size:13px">${esc(r.message || '')}</div>
    </li>`;
  }).join('');

  return `<section>
  <h2>Próximos Passos (${Math.min(fails.length, 10)} principais)</h2>
  <ol style="padding-left:20px">${items}</ol>
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
    cfg.name    && `<div><strong>${esc(cfg.name)}</strong></div>`,
    cfg.company && `<div>${esc(cfg.company)}</div>`,
    cfg.email   && `<div>✉ ${esc(cfg.email)}</div>`,
    cfg.phone   && `<div>✆ ${esc(cfg.phone)}</div>`,
  ].filter(Boolean).join('');

  return `<div class="footer-wrap">
  <div class="footer-grid">
    <div>
      <h3 style="margin-bottom:8px;font-size:13px;text-transform:uppercase;color:#6b7280;letter-spacing:.5px">Consultor</h3>
      ${contactLines}
    </div>
    <div style="text-align:right">
      <h3 style="margin-bottom:8px;font-size:13px;text-transform:uppercase;color:#6b7280;letter-spacing:.5px">Documento</h3>
      <div>Auditoria: <span class="hash">${esc(auditId)}</span></div>
      <div>SHA-256: <span class="hash">${esc(sha256)}</span></div>
      <div>Data da auditoria: ${esc(auditDate)}</div>
      <div>Gerado em: ${esc(generatedDate)}</div>
    </div>
  </div>
  <div class="disclaimer">Este documento é confidencial e destinado exclusivamente ao destinatário indicado.</div>
</div>`;
}

// ── Main generator ─────────────────────────────────────────────────
function generateConsultingReport(auditData, consultingConfig) {
  const results     = auditData.results     || [];
  const score       = auditData.score       ?? 0;
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
