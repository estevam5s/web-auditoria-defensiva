/*  ═══════════════════════════════════════════════════════════════════
    HTML REPORT GENERATOR — Interactive Report with Charts & Tables
    Generates a self-contained HTML file with Chart.js visualizations
    ═══════════════════════════════════════════════════════════════════ */

function generateHTMLReport(auditData, networkInfo = {}) {
  const results = auditData.results || [];
  const score = auditData.score ?? 0;
  const grade = auditData.grade || {};
  const productionReady = auditData.productionReady || null;
  const { ip = null, hostname = null, hosting = null } = networkInfo;

  // Categorize results
  const critical = results.filter(r => r.severity === 'critical' && (r.status === 'FAIL' || r.status === 'WARN'));
  const high = results.filter(r => r.severity === 'high' && (r.status === 'FAIL' || r.status === 'WARN'));
  const medium = results.filter(r => r.severity === 'medium' && (r.status === 'FAIL' || r.status === 'WARN'));
  const low = results.filter(r => r.severity === 'low' && (r.status === 'FAIL' || r.status === 'WARN'));
  const passed = results.filter(r => r.status === 'PASS');
  const failed = results.filter(r => r.status === 'FAIL');
  const warnings = results.filter(r => r.status === 'WARN');

  // Extract routes
  const routes = extractRoutes(results);
  // Extract sensitive files
  const sensitiveFiles = extractSensitiveFiles(results);
  // Extract stack
  const stackResult = results.find(r => r.check === 'Stack Detection');
  const categories = stackResult?.details?.categories || {};
  const techs = stackResult?.details?.technologies || [];

  // Group results by check category
  const checkGroups = groupResults(results);

  // Extract exposed .env files with raw content
  const exposedEnvFiles = [];
  for (const r of results) {
    if (r.details?.files && Array.isArray(r.details.files)) {
      for (const f of r.details.files) {
        if (f.rawContent) exposedEnvFiles.push({ url: f.url || f.name, rawContent: f.rawContent });
      }
    }
  }

  return `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Supabase Guard — Relatório de Auditoria</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.js"><\/script>
  <style>
    :root {
      --bg: #0a0a0f;
      --bg2: #0d0d14;
      --bg3: #111118;
      --bg4: #181828;
      --border: #1a1a2e;
      --accent: #00ff41;
      --accent-dim: #00cc33;
      --red: #ff0040;
      --orange: #ff8c00;
      --yellow: #e6e600;
      --blue: #00bfff;
      --purple: #a855f7;
      --white: #e0e0e8;
      --gray: #8888aa;
      --gray-dark: #555570;
      --font: 'Segoe UI', system-ui, -apple-system, sans-serif;
      --mono: 'Cascadia Code', 'Fira Code', 'JetBrains Mono', monospace;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: var(--font); background: var(--bg); color: var(--white); min-height: 100vh; }
    
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    
    /* Header */
    .report-header {
      text-align: center;
      padding: 3rem 0;
      border-bottom: 1px solid var(--border);
      margin-bottom: 2rem;
    }
    .report-header h1 { font-size: 2.5rem; letter-spacing: 4px; }
    .report-header h1 span { color: var(--accent); }
    .report-header .subtitle { color: var(--gray); font-size: 0.9rem; margin: 0.5rem 0; letter-spacing: 2px; }
    .report-header .meta { display: flex; justify-content: center; gap: 2rem; margin-top: 1.5rem; flex-wrap: wrap; }
    .report-header .meta-item { background: var(--bg3); padding: 0.5rem 1rem; border-radius: 6px; border: 1px solid var(--border); font-size: 0.8rem; }
    .report-header .meta-item strong { color: var(--accent); }
    
    /* Navigation */
    .nav-bar {
      display: flex; flex-wrap: wrap; gap: 0.5rem; justify-content: center;
      padding: 1rem; background: var(--bg2); border-radius: 8px; margin-bottom: 2rem;
      border: 1px solid var(--border); position: sticky; top: 0; z-index: 100;
    }
    .nav-bar a {
      color: var(--gray); text-decoration: none; padding: 0.4rem 0.8rem;
      border-radius: 4px; font-size: 0.8rem; transition: 0.2s;
    }
    .nav-bar a:hover { color: var(--accent); background: rgba(0,255,65,0.1); }
    
    /* Score Section */
    .score-section {
      display: grid; grid-template-columns: 250px 1fr; gap: 2rem;
      margin-bottom: 3rem; align-items: center;
    }
    @media (max-width: 768px) { .score-section { grid-template-columns: 1fr; } }
    .score-circle-container { text-align: center; }
    .score-big { font-size: 5rem; font-weight: 800; line-height: 1; }
    .score-grade { font-size: 2rem; font-weight: 700; }
    .score-label { color: var(--gray); font-size: 0.9rem; }
    .score-bar { height: 8px; background: var(--bg4); border-radius: 4px; overflow: hidden; margin: 1rem 0; }
    .score-bar-fill { height: 100%; border-radius: 4px; transition: width 1s ease; }
    
    /* Stats Cards */
    .stats-grid {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 1rem; margin-bottom: 2rem;
    }
    .stat-card {
      background: var(--bg3); border: 1px solid var(--border); border-radius: 8px;
      padding: 1.2rem; text-align: center; border-top: 3px solid;
    }
    .stat-card .value { font-size: 2rem; font-weight: 800; }
    .stat-card .label { font-size: 0.75rem; color: var(--gray); margin-top: 0.3rem; }
    
    /* Section */
    section { 
      margin-bottom: 3rem; 
      padding: 1.5rem;
      background: var(--bg3);
      border-radius: 12px;
      border: 1px solid var(--border);
    }
    section > h2 {
      font-size: 1.3rem; color: var(--accent); margin-bottom: 1rem;
      padding-bottom: 0.5rem; border-bottom: 2px solid var(--accent);
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    section > h3 { font-size: 1rem; color: var(--white); margin: 1.5rem 0 0.5rem; }
    
    /* Charts */
    .charts-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 1.5rem; margin-bottom: 2rem; }
    .chart-card {
      background: var(--bg3); border: 1px solid var(--border); border-radius: 8px;
      padding: 1.5rem;
    }
    .chart-card h3 { color: var(--white); font-size: 0.95rem; margin-bottom: 1rem; }
    .chart-card canvas { max-height: 300px; }
    
    /* Tables */
    .data-table { 
      width: 100%; 
      border-collapse: collapse; 
      font-size: 0.8rem;
      margin-top: 1rem;
    }
    .data-table thead th {
      background: var(--accent); color: #000; padding: 0.8rem 1rem;
      text-align: left; font-weight: 600; position: sticky; top: 50px;
      border-bottom: 2px solid var(--border);
    }
    .data-table tbody tr { border-bottom: 1px solid var(--border); transition: 0.2s; }
    .data-table tbody tr:hover { background: rgba(0,255,65,0.08); }
    .data-table td { padding: 0.75rem 1rem; vertical-align: top; }
    .data-table .badge {
      display: inline-block; padding: 0.15rem 0.5rem; border-radius: 3px;
      font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    }
    .badge-critical { background: rgba(255,0,64,0.2); color: var(--red); }
    .badge-high { background: rgba(255,102,34,0.2); color: #ff6622; }
    .badge-medium { background: rgba(255,140,0,0.2); color: var(--orange); }
    .badge-low { background: rgba(230,230,0,0.2); color: var(--yellow); }
    .badge-info { background: rgba(0,191,255,0.2); color: var(--blue); }
    .badge-pass { background: rgba(0,255,65,0.15); color: var(--accent); }
    .badge-fail { background: rgba(255,0,64,0.2); color: var(--red); }
    .badge-warn { background: rgba(255,140,0,0.2); color: var(--orange); }
    .badge-error { background: rgba(168,85,247,0.2); color: var(--purple); }
    
    /* Stack */
    .stack-grid { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1rem; }
    .stack-tag {
      background: var(--bg4); border: 1px solid var(--border); border-radius: 20px;
      padding: 0.3rem 0.8rem; font-size: 0.8rem; color: var(--white);
    }
    .stack-category { color: var(--accent); font-weight: 600; font-size: 0.85rem; margin: 1rem 0 0.5rem; }
    
    /* Insights */
    .insight-card {
      background: var(--bg3); border-left: 4px solid; border-radius: 0 8px 8px 0;
      padding: 1rem 1.5rem; margin-bottom: 0.8rem;
    }
    .insight-card h4 { font-size: 0.95rem; margin-bottom: 0.3rem; }
    .insight-card p { font-size: 0.85rem; color: var(--gray); line-height: 1.5; }
    
    /* What we checked */
    .checks-list { list-style: none; }
    .checks-list li { padding: 0.3rem 0; font-size: 0.85rem; }
    .checks-list li::before { content: '✓'; color: var(--accent); margin-right: 0.5rem; font-weight: 700; }
    .checks-category { margin-top: 1rem; }
    .checks-category h4 { color: var(--accent); font-size: 0.9rem; margin-bottom: 0.5rem; }
    
    /* Evidence */
    .evidence-grid { display: grid; gap: 0.5rem; }
    .evidence-row {
      display: grid; grid-template-columns: 150px 1fr; gap: 1rem;
      background: var(--bg3); padding: 0.6rem 1rem; border-radius: 4px;
    }
    .evidence-row .key { color: var(--gray); font-size: 0.8rem; }
    .evidence-row .val { color: var(--accent); font-family: var(--mono); font-size: 0.8rem; word-break: break-all; }
    
    /* Details toggle */
    .result-details { display: none; margin-top: 0.5rem; background: var(--bg2); padding: 0.5rem; border-radius: 4px; font-size: 0.75rem; max-height: 200px; overflow: auto; }
    .result-details.open { display: block; }
    .result-row { cursor: pointer; }
    .result-row:hover td { background: rgba(0,255,65,0.03); }
    
    /* Print */
    @media print {
      body { background: #fff; color: #000; }
      .nav-bar { display: none; }
      .chart-card, .stat-card, .insight-card, .evidence-row { border: 1px solid #ddd; }
    }
    
    /* Network Cards */
    .net-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 1rem; }
    .net-card { background: var(--bg3); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
    .net-label { font-size: 0.7rem; color: var(--gray); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 0.3rem; }
    .net-value { font-size: 0.95rem; font-weight: 600; word-break: break-all; }

    /* Footer */
    .report-footer { text-align: center; padding: 2rem 0; border-top: 1px solid var(--border); color: var(--gray); font-size: 0.8rem; }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div class="report-header">
      <h1>SUPABASE <span>GUARD</span></h1>
      <p class="subtitle">RELATÓRIO DE AUDITORIA DE SEGURANÇA</p>
      <div class="meta">
        <div class="meta-item">Alvo: <strong>${esc(auditData.projectUrl)}</strong></div>
        ${ip ? `<div class="meta-item">IP: <strong>${esc(ip)}</strong></div>` : ''}
        ${hosting ? `<div class="meta-item">Hospedagem: <strong>${esc(hosting)}</strong></div>` : ''}
        <div class="meta-item">Data: <strong>${formatDate(auditData.evidence?.timestamp)}</strong></div>
        <div class="meta-item">Score: <strong>${score}/100 (${grade.grade || '-'})</strong></div>
        <div class="meta-item">Duração: <strong>${auditData.duration || 'N/A'}</strong></div>
        <div class="meta-item">Checks: <strong>${auditData.totalChecks || 0}</strong></div>
      </div>
    </div>
    
    <!-- Navigation -->
    <nav class="nav-bar">
      <a href="#score">Score</a>
      <a href="#charts">Gráficos</a>
      <a href="#network">Rede & Infra</a>
      <a href="#stack">Stack</a>
      <a href="#checked">O Que Verificamos</a>
      <a href="#vulnerabilities">Vulnerabilidades</a>
      <a href="#routes">Rotas Descobertas</a>
      <a href="#git-exposure">Git Exposure</a>
      <a href="#files">Arquivos Sensíveis</a>
      <a href="#insights">Insights</a>
      <a href="#evidence">Evidência</a>
    </nav>
    
    <!-- Score -->
    <section id="score">
      <h2>🛡️ Security Score</h2>
      <div class="score-section">
        <div class="score-circle-container">
          <div class="score-big" style="color:${grade.color || '#00ff41'}">${score}</div>
          <div class="score-grade" style="color:${grade.color || '#00ff41'}">${grade.grade || '-'}</div>
          <div class="score-label">${grade.label || ''}</div>
        </div>
        <div>
          <div class="score-bar">
            <div class="score-bar-fill" style="width:${score}%;background:${grade.color || '#00ff41'}"></div>
          </div>
          <div class="stats-grid">
            <div class="stat-card" style="border-top-color:#00ff41">
              <div class="value" style="color:#00ff41">${auditData.passed || 0}</div>
              <div class="label">Aprovados</div>
            </div>
            <div class="stat-card" style="border-top-color:#ff0040">
              <div class="value" style="color:#ff0040">${auditData.failed || 0}</div>
              <div class="label">Falhas</div>
            </div>
            <div class="stat-card" style="border-top-color:#ff8c00">
              <div class="value" style="color:#ff8c00">${auditData.warnings || 0}</div>
              <div class="label">Alertas</div>
            </div>
            <div class="stat-card" style="border-top-color:#ff0040">
              <div class="value" style="color:#ff0040">${critical.length}</div>
              <div class="label">Críticos</div>
            </div>
            <div class="stat-card" style="border-top-color:#ff6622">
              <div class="value" style="color:#ff6622">${high.length}</div>
              <div class="label">Altos</div>
            </div>
            <div class="stat-card" style="border-top-color:#ff8c00">
              <div class="value" style="color:#ff8c00">${medium.length}</div>
              <div class="label">Médios</div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <!-- Production Readiness Verdict -->
    ${productionReady ? `
    <section id="production-verdict" style="margin-bottom:2rem;">
      <div style="
        background: ${productionReady.color}18;
        border: 2px solid ${productionReady.color};
        border-radius: 12px;
        padding: 1.5rem 2rem;
        display: flex;
        align-items: flex-start;
        gap: 1.5rem;
        flex-wrap: wrap;
      ">
        <div style="flex:0 0 auto;">
          <div style="font-size:2.5rem;font-weight:900;color:${productionReady.color};letter-spacing:2px;">
            ${productionReady.verdict === 'APTO' ? '✅' : productionReady.verdict === 'APTO_COM_RESSALVAS' ? '⚠️' : '❌'}
          </div>
        </div>
        <div style="flex:1;min-width:200px;">
          <div style="font-size:1.3rem;font-weight:700;color:${productionReady.color};margin-bottom:0.5rem;">
            🏭 ${productionReady.label}
          </div>
          ${productionReady.reasons.length > 0 ? `
          <div style="font-size:0.85rem;color:#aaa;margin-bottom:0.5rem;">
            ${productionReady.reasons.map(r => `<span style="margin-right:1rem;">✓ ${esc(r)}</span>`).join('')}
          </div>` : ''}
          ${productionReady.blockers.length > 0 ? `
          <ul style="margin:0;padding-left:1.2rem;font-size:0.9rem;color:#ffcccc;">
            ${productionReady.blockers.map(b => `<li>${esc(b)}</li>`).join('')}
          </ul>` : ''}
        </div>
      </div>
    </section>` : ''}

    <!-- Charts -->
    <section id="charts">
      <h2>📊 Gráficos de Análise</h2>
      <div class="charts-grid">
        <div class="chart-card">
          <h3>Distribuição por Severidade</h3>
          <canvas id="chartSeverity"></canvas>
        </div>
        <div class="chart-card">
          <h3>Status dos Checks</h3>
          <canvas id="chartStatus"></canvas>
        </div>
        <div class="chart-card">
          <h3>Vulnerabilidades por Categoria</h3>
          <canvas id="chartCategory"></canvas>
        </div>
        <div class="chart-card">
          <h3>Score Breakdown</h3>
          <canvas id="chartBreakdown"></canvas>
        </div>
        <div class="chart-card">
          <h3>Severidade (Radar)</h3>
          <canvas id="chartRadar"></canvas>
        </div>
        <div class="chart-card">
          <h3>Penalidade por Severidade</h3>
          <canvas id="chartPenalty"></canvas>
        </div>
      </div>
    </section>
    
    <!-- Network & Infrastructure -->
    <section id="network">
      <h2>🌐 Rede & Infraestrutura</h2>
      <div class="net-grid">
        <div class="net-card">
          <div class="net-label">Hostname</div>
          <div class="net-value">${esc(hostname || (auditData.projectUrl ? (()=>{try{return new URL(auditData.projectUrl).hostname}catch{return auditData.projectUrl}})() : 'N/A'))}</div>
        </div>
        <div class="net-card">
          <div class="net-label">Endereço IP</div>
          <div class="net-value" style="color:var(--blue)">${esc(ip || 'Não resolvido')}</div>
        </div>
        <div class="net-card">
          <div class="net-label">Provedor de Hospedagem</div>
          <div class="net-value" style="color:var(--purple)">${esc(hosting || detectedHosting(results) || 'Não identificado')}</div>
        </div>
        <div class="net-card">
          <div class="net-label">Protocolo</div>
          <div class="net-value" style="color:${auditData.projectUrl?.startsWith('https') ? 'var(--accent)' : 'var(--red)'}">${auditData.projectUrl?.startsWith('https') ? 'HTTPS ✓' : 'HTTP ⚠'}</div>
        </div>
        <div class="net-card">
          <div class="net-label">Auditado em</div>
          <div class="net-value">${formatDate(auditData.evidence?.timestamp)}</div>
        </div>
        <div class="net-card">
          <div class="net-label">Audit ID</div>
          <div class="net-value" style="font-family:var(--mono);font-size:0.7rem">${esc((auditData.evidence?.auditId || 'N/A').substring(0, 24))}...</div>
        </div>
      </div>
    </section>

    <!-- Stack -->
    <section id="stack">
      <h2>🔧 Stack Detectado</h2>
      ${Object.keys(categories).length > 0 ? Object.entries(categories).map(([cat, items]) =>
        `<div class="stack-category">${esc(cat)}</div>
         <div class="stack-grid">${items.map(i => `<span class="stack-tag">${esc(i)}</span>`).join('')}</div>`
      ).join('') : '<p style="color:var(--gray)">Nenhuma tecnologia detectada ou módulo não executado.</p>'}
      ${techs.length > 0 ? `<p style="color:var(--gray);font-size:0.8rem;margin-top:1rem">Total: ${techs.length} tecnologia(s)</p>` : ''}
    </section>
    
    <!-- What We Checked -->
    <section id="checked">
      <h2>🔍 O Que Verificamos</h2>
      <div class="checks-category">
        <h4>Verificações Base (14 controles)</h4>
        <ul class="checks-list">
          <li>DNS & Conectividade — HTTPS, headers, acessibilidade</li>
          <li>REST API — Exposição PostgREST, tabelas via anon key</li>
          <li>RPC Functions — Funções expostas sem autenticação</li>
          <li>GraphQL — Introspection e acesso a dados</li>
          <li>Storage Buckets — Buckets públicos, listagem, upload</li>
          <li>Edge Functions — Descoberta e autenticação</li>
          <li>Realtime Channels — WebSocket público</li>
          <li>Auth Endpoints — Signup, admin endpoints</li>
          <li>.env Exposure — Arquivos sensíveis em paths comuns</li>
          <li>RLS Check — Row Level Security ativo</li>
          <li>CORS Headers — Configuração permissiva</li>
          <li>Service Key Leak — service_role em público</li>
          <li>Open Signup — Registro irrestrito</li>
          <li>JWT Configuration — Estrutura e configuração</li>
        </ul>
      </div>
      <div class="checks-category">
        <h4>Deep Analysis v1 (5 módulos)</h4>
        <ul class="checks-list">
          <li>Source Code — 25+ padrões de secrets</li>
          <li>Hidden Routes — 200+ rotas em 9 categorias</li>
          <li>Vulnerability Scanner — XSS, CSRF, clickjacking</li>
          <li>Sensitive Data — PII, financeiros, credenciais</li>
          <li>Error Detector — 5xx, SSL, mixed content</li>
        </ul>
      </div>
      <div class="checks-category">
        <h4>Deep Analysis v2 (7 módulos)</h4>
        <ul class="checks-list">
          <li>Deep RLS — 60+ tabelas, write ops, IDOR</li>
          <li>REST/RPC Leak — 80+ tabelas, 50+ RPCs, content analysis</li>
          <li>Edge Roles — JWT fakes, webhooks, 100+ functions</li>
          <li>Bundle Keys — 60+ patterns (payment, AI, cloud)</li>
          <li>Deep Storage — 50+ buckets, upload test, hidden discovery</li>
          <li>Credential/PII — CPF, CNPJ, cards, emails, bank data</li>
          <li>Stack Detection — 60+ tech fingerprints</li>
        </ul>
      </div>
    </section>
    
    <!-- Vulnerabilities Table -->
    <section id="vulnerabilities">
      <h2>⚠️ Vulnerabilidades Detalhadas</h2>
      <p style="color:var(--gray);font-size:0.85rem;margin-bottom:1rem">Todas as vulnerabilidades encontradas durante a auditoria, ordenadas por severidade.</p>
      <div style="overflow-x:auto;max-height:500px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Severidade</th>
              <th>Check</th>
              <th>Descrição</th>
            </tr>
          </thead>
          <tbody>
            ${results.filter(r => r.status !== 'PASS').sort((a,b) => {
              const so = {critical:0,high:1,medium:2,low:3,info:4};
              return (so[a.severity]??5) - (so[b.severity]??5);
            }).map(r => `
              <tr class="result-row" onclick="this.querySelector('.result-details')?.classList.toggle('open')">
                <td><span class="badge badge-${(r.status||'info').toLowerCase()}">${esc(r.status)}</span></td>
                <td><span class="badge badge-${r.severity}">${esc(r.severity)}</span></td>
                <td style="font-weight:600">${esc(r.check)}</td>
                <td>
                  ${esc(r.message?.substring(0, 150))}
                  ${r.details ? `<div class="result-details"><pre>${esc(JSON.stringify(r.details, null, 2))}</pre></div>` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </section>
    
    <!-- All Routes Discovered -->
    <section id="routes">
      <h2>🗺️ Rotas Descobertas</h2>
      <p style="color:var(--gray);font-size:0.85rem;margin-bottom:1rem">Todas as rotas descobertas durante o scan, incluindo rotas administrativas, API e páginas ocultas.</p>
      ${(() => {
        // Get full route data from route-discovery results
        const routeResult = results.find(r => r.check?.includes('Routes — Hidden') || r.check?.includes('Route'));
        const allRoutes = routeResult?.details?.allRoutes || routeResult?.details?.routes || routes;
        const byCategory = routeResult?.details?.byCategory || {};
        const criticals = (allRoutes).filter(r => r.risk === 'critical' || r.risk === 'high');
        const sitemapResult = results.find(r => r.check?.includes('Sitemap'));
        const sitemapUrls = sitemapResult?.details?.urls || [];
        const sourceResult = results.find(r => r.check?.includes('Source'));
        const sourceRoutes = sourceResult?.details?.routes || [];

        if (allRoutes.length === 0 && routes.length === 0) {
          return '<p style="color:var(--gray)">Módulo de descoberta de rotas não executado ou nenhuma rota encontrada. Execute com a opção "Hidden Routes" ativada.</p>';
        }

        return `
          ${criticals.length > 0 ? `
            <div style="background:rgba(255,0,64,0.1);border:1px solid rgba(255,0,64,0.3);border-radius:8px;padding:1rem;margin-bottom:1.5rem">
              <strong style="color:var(--red)">⚠ ${criticals.length} rota(s) crítica(s)/alta(s) descoberta(s)!</strong>
              <p style="color:var(--gray);font-size:0.85rem;margin-top:0.5rem">Estas rotas representam risco de segurança e devem ser protegidas ou removidas imediatamente.</p>
            </div>
          ` : ''}

          ${Object.keys(byCategory).length > 0 ? `
            <h3 style="color:var(--accent);margin-bottom:1rem">Por Categoria</h3>
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:2rem">
              ${Object.entries(byCategory).map(([cat, catRoutes]) => `
                <div style="background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:1rem">
                  <div style="font-weight:600;color:var(--accent);margin-bottom:0.5rem;text-transform:capitalize">${esc(cat)} (${catRoutes.length})</div>
                  ${catRoutes.slice(0, 10).map(r => {
                    const risk = r.risk || 'low';
                    const riskColor = risk === 'critical' ? 'var(--red)' : risk === 'high' ? '#ff6622' : risk === 'medium' ? 'var(--orange)' : 'var(--gray)';
                    const statusColor = r.status >= 200 && r.status < 300 ? 'var(--accent)' : r.status === 401 || r.status === 403 ? 'var(--orange)' : 'var(--gray)';
                    return `<div style="display:flex;justify-content:space-between;padding:0.25rem 0;border-bottom:1px solid rgba(255,255,255,0.05);font-size:0.8rem">
                      <span style="font-family:var(--mono);color:${riskColor}">${esc(r.path || r)}</span>
                      <span style="color:${statusColor}">${r.status || ''}</span>
                    </div>`;
                  }).join('')}
                  ${catRoutes.length > 10 ? `<div style="color:var(--gray);font-size:0.75rem;margin-top:0.5rem">+${catRoutes.length - 10} mais...</div>` : ''}
                </div>
              `).join('')}
            </div>
          ` : ''}

          <h3 style="color:var(--accent);margin-bottom:1rem">Todas as Rotas (${allRoutes.length || routes.length})</h3>
          <div style="overflow-x:auto;">
            <table class="data-table">
              <thead><tr><th>Rota</th><th>HTTP</th><th>Categoria</th><th>Risco</th></tr></thead>
              <tbody>
                ${(allRoutes.length > 0 ? allRoutes : routes).slice(0, 100).map(r => {
                  const rPath = typeof r === 'string' ? r : (r.path || r.url || JSON.stringify(r));
                  const rStatus = r.status || '—';
                  const rCat = r.category || r.type || '—';
                  const rRisk = r.risk || '—';
                  const riskColor = rRisk === 'critical' ? 'badge-critical' : rRisk === 'high' ? 'badge-high' : rRisk === 'medium' ? 'badge-medium' : 'badge-info';
                  const httpColor = rStatus >= 200 && rStatus < 300 ? '#00ff41' : rStatus === 401 || rStatus === 403 ? '#ff8c00' : '#8888aa';
                  return `<tr>
                    <td style="font-family:var(--mono);font-size:0.75rem">${esc(rPath)}</td>
                    <td style="color:${httpColor};font-weight:600">${rStatus}</td>
                    <td>${esc(String(rCat))}</td>
                    <td><span class="badge ${riskColor}">${esc(String(rRisk))}</span></td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
          <p style="color:var(--gray);font-size:0.8rem;margin-top:0.5rem">
            Mostrando ${Math.min(allRoutes.length || routes.length, 100)} de ${allRoutes.length || routes.length} rota(s) descoberta(s)
            ${sitemapUrls.length > 0 ? ` · ${sitemapUrls.length} URL(s) no sitemap.xml` : ''}
            ${sourceRoutes.length > 0 ? ` · ${sourceRoutes.length} rota(s) extraída(s) do código fonte` : ''}
          </p>
        `;
      })()}
    </section>

    <!-- Git Exposure -->
    <section id="git-exposure">
      <h2>🔍 Exposição Git & Histórico</h2>
      ${(() => {
        const gitRoutes = results.find(r => r.check?.includes('Hidden'))?.details?.allRoutes?.filter(r =>
          r.path?.includes('.git') || r.path?.includes('.svn') || r.path?.includes('.hg')
        ) || [];
        const gitFindings = results.filter(r => r.check?.toLowerCase().includes('git') || r.message?.toLowerCase().includes('git'));

        if (gitRoutes.length === 0 && gitFindings.length === 0) {
          return `<div style="background:rgba(0,255,65,0.05);border:1px solid rgba(0,255,65,0.2);border-radius:8px;padding:1rem">
            <strong style="color:var(--accent)">✓ Nenhum arquivo git exposto detectado</strong>
            <p style="color:var(--gray);font-size:0.85rem;margin-top:0.5rem">Arquivos como <code>.git/HEAD</code>, <code>.git/config</code> e <code>.gitignore</code> não estão acessíveis publicamente.</p>
          </div>`;
        }

        return `
          <div style="background:rgba(255,0,64,0.1);border:1px solid rgba(255,0,64,0.3);border-radius:8px;padding:1rem;margin-bottom:1.5rem">
            <strong style="color:var(--red)">⚠ Arquivos git encontrados acessíveis publicamente!</strong>
            <p style="color:var(--gray);font-size:0.85rem;margin-top:0.5rem">Isso pode expor código fonte, credenciais, histórico de commits e configurações sensíveis.</p>
          </div>
          ${gitRoutes.length > 0 ? `
            <div style="overflow-x:auto;margin-bottom:1rem">
              <table class="data-table">
                <thead><tr><th>Arquivo</th><th>HTTP</th><th>Risco</th></tr></thead>
                <tbody>
                  ${gitRoutes.map(r => `<tr>
                    <td style="font-family:var(--mono);color:var(--red)">${esc(r.path)}</td>
                    <td style="color:#00ff41">${r.status}</td>
                    <td><span class="badge badge-critical">CRÍTICO</span></td>
                  </tr>`).join('')}
                </tbody>
              </table>
            </div>
          ` : ''}
          <div style="background:var(--bg3);border-radius:8px;padding:1rem;margin-top:1rem">
            <strong style="color:var(--orange)">Como Mitigar:</strong>
            <pre style="margin-top:0.5rem;font-size:0.8rem;color:var(--gray);white-space:pre-wrap"># Nginx — bloquear acesso a .git
location ~ /\\.git {
    deny all;
    return 404;
}
# Apache — .htaccess
RedirectMatch 404 /\\.git</pre>
          </div>
        `;
      })()}
    </section>
    
    <!-- Sensitive Files -->
    <section id="files">
      <h2>📄 Arquivos Sensíveis</h2>
      <p style="color:var(--gray);font-size:0.85rem;margin-bottom:1rem">Arquivos potencialmente sensíveis expostos publicamente que podem conter informações confidenciais.</p>
      ${sensitiveFiles.length > 0 ? `
        <div style="overflow-x:auto;max-height:400px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;">
          <table class="data-table">
            <thead><tr><th>Arquivo/Tipo</th><th>Risco</th><th>Fonte</th></tr></thead>
            <tbody>
              ${sensitiveFiles.map(f => `
                <tr>
                  <td style="font-family:var(--mono);font-size:0.75rem;color:var(--red)">${esc(f.name)}</td>
                  <td><span class="badge badge-${f.risk}">${esc((f.risk||'').toUpperCase())}</span></td>
                  <td style="font-size:0.75rem">${esc(f.source)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
        <p style="color:var(--gray);font-size:0.8rem;margin-top:0.5rem">Total: ${sensitiveFiles.length} item(s)</p>
      ` : '<p style="color:var(--gray)">Nenhum arquivo sensível exposto detectado. ✓</p>'}
    </section>
    
    <!-- Exposed .env files with raw content -->
    ${exposedEnvFiles.length > 0 ? `
    <section id="env-exposed" style="margin-bottom:2rem;">
      <h2>🔑 Arquivos .env Expostos Publicamente</h2>
      <div style="background:#ff00200d;border:2px solid #ff0040;border-radius:8px;padding:1rem;margin-bottom:0.5rem;">
        <p style="color:#ff6680;font-weight:600;margin-bottom:0.5rem;">⚠️ CRÍTICO: Os seguintes arquivos .env estão acessíveis publicamente — conteúdo real exposto:</p>
        ${exposedEnvFiles.map(f => `
          <div style="margin-bottom:1rem;">
            <div style="font-family:monospace;font-size:0.8rem;color:#ff9999;margin-bottom:0.5rem;">📄 ${esc(f.url)}</div>
            <pre style="background:#1a0a0a;border:1px solid #ff0040;border-radius:6px;padding:1rem;font-family:monospace;font-size:0.75rem;color:#ff6666;overflow-x:auto;white-space:pre-wrap;word-break:break-all;">${esc(f.rawContent)}</pre>
          </div>
        `).join('')}
        <p style="color:#ff9999;font-size:0.8rem;margin-top:0.5rem;">AÇÃO URGENTE: Bloqueie o acesso a este arquivo no servidor e rotacione todas as credenciais imediatamente.</p>
      </div>
    </section>` : ''}

    <!-- Insights -->
    <section id="insights">
      <h2>💡 Insights & Recomendações</h2>
      ${generateInsightsHTML(auditData)}
    </section>
    
    <!-- Evidence -->
    <section id="evidence">
      <h2>🔐 Evidência de Integridade</h2>
      <div class="evidence-grid">
        <div class="evidence-row"><div class="key">Audit ID</div><div class="val">${esc(auditData.evidence?.auditId || 'N/A')}</div></div>
        <div class="evidence-row"><div class="key">SHA-256</div><div class="val">${esc(auditData.evidence?.sha256 || 'N/A')}</div></div>
        <div class="evidence-row"><div class="key">Timestamp</div><div class="val">${esc(auditData.evidence?.timestamp || 'N/A')}</div></div>
        <div class="evidence-row"><div class="key">Projeto</div><div class="val">${esc(auditData.projectUrl || 'N/A')}</div></div>
        <div class="evidence-row"><div class="key">Score</div><div class="val">${score}/100 (${grade.grade || '-'})</div></div>
        <div class="evidence-row"><div class="key">Duração</div><div class="val">${esc(auditData.duration || 'N/A')}</div></div>
        <div class="evidence-row"><div class="key">Engine</div><div class="val">Supabase Guard v3.3.0</div></div>
      </div>
    </section>
    
    <!-- Footer -->
    <div class="report-footer">
      <p>Documento confidencial — Gerado por <strong>Supabase Guard v3.3.0</strong></p>
      <p style="margin-top:0.3rem">SHA-256: ${esc(auditData.evidence?.sha256 || 'N/A')}</p>
    </div>
  </div>
  
  <!-- Chart.js Scripts -->
  <script>
    Chart.defaults.color = '#8888aa';
    Chart.defaults.borderColor = '#1a1a2e';
    
    // 1. Severity Doughnut
    new Chart(document.getElementById('chartSeverity'), {
      type: 'doughnut',
      data: {
        labels: ['Crítico', 'Alto', 'Médio', 'Baixo', 'Info'],
        datasets: [{
          data: [${critical.length}, ${high.length}, ${medium.length}, ${low.length}, ${results.filter(r => r.severity === 'info').length}],
          backgroundColor: ['#ff0040', '#ff6622', '#ff8c00', '#e6e600', '#00bfff'],
          borderWidth: 0
        }]
      },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });
    
    // 2. Status Pie
    new Chart(document.getElementById('chartStatus'), {
      type: 'pie',
      data: {
        labels: ['Aprovado', 'Falha', 'Alerta', 'Erro', 'Info'],
        datasets: [{
          data: [${passed.length}, ${failed.length}, ${warnings.length}, ${results.filter(r=>r.status==='ERROR').length}, ${results.filter(r=>r.status==='INFO').length}],
          backgroundColor: ['#00ff41', '#ff0040', '#ff8c00', '#a855f7', '#00bfff'],
          borderWidth: 0
        }]
      },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });
    
    // 3. Category Bar
    const categoryData = ${JSON.stringify(Object.entries(checkGroups).map(([k,v]) => ({ label: k, fail: v.filter(r=>r.status==='FAIL').length, pass: v.filter(r=>r.status==='PASS').length, warn: v.filter(r=>r.status==='WARN').length })))};
    new Chart(document.getElementById('chartCategory'), {
      type: 'bar',
      data: {
        labels: categoryData.map(d => d.label),
        datasets: [
          { label: 'Falhas', data: categoryData.map(d => d.fail), backgroundColor: '#ff0040' },
          { label: 'Alertas', data: categoryData.map(d => d.warn), backgroundColor: '#ff8c00' },
          { label: 'OK', data: categoryData.map(d => d.pass), backgroundColor: '#00ff41' },
        ]
      },
      options: {
        responsive: true, indexAxis: 'y',
        plugins: { legend: { position: 'bottom' } },
        scales: { x: { stacked: true }, y: { stacked: true } }
      }
    });
    
    // 4. Score Breakdown Gauge
    new Chart(document.getElementById('chartBreakdown'), {
      type: 'doughnut',
      data: {
        labels: ['Score', 'Penalidade'],
        datasets: [{
          data: [${score}, ${100 - score}],
          backgroundColor: ['${grade.color || '#00ff41'}', '#1a1a2e'],
          borderWidth: 0,
          circumference: 270,
          rotation: 225,
        }]
      },
      options: {
        responsive: true, cutout: '75%',
        plugins: {
          legend: { display: false },
          tooltip: { enabled: true }
        }
      }
    });
    
    // 5. Radar
    new Chart(document.getElementById('chartRadar'), {
      type: 'radar',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
          label: 'Falhas',
          data: [${critical.length}, ${high.length}, ${medium.length}, ${low.length}, ${results.filter(r=>r.severity==='info'&&r.status==='FAIL').length}],
          backgroundColor: 'rgba(255,0,64,0.2)',
          borderColor: '#ff0040',
          borderWidth: 2,
          pointBackgroundColor: '#ff0040'
        }, {
          label: 'Total',
          data: [${results.filter(r=>r.severity==='critical').length}, ${results.filter(r=>r.severity==='high').length}, ${results.filter(r=>r.severity==='medium').length}, ${results.filter(r=>r.severity==='low').length}, ${results.filter(r=>r.severity==='info').length}],
          backgroundColor: 'rgba(0,255,65,0.1)',
          borderColor: '#00ff41',
          borderWidth: 2,
          pointBackgroundColor: '#00ff41'
        }]
      },
      options: { responsive: true, scales: { r: { beginAtZero: true, grid: { color: '#1a1a2e' } } } }
    });
    
    // 6. Penalty Bar
    const penalties = { critical: 25, high: 15, medium: 8, low: 3, info: 0 };
    const sevCounts = {
      critical: ${critical.length},
      high: ${high.length},
      medium: ${medium.length},
      low: ${low.length}
    };
    new Chart(document.getElementById('chartPenalty'), {
      type: 'bar',
      data: {
        labels: ['Crítico (-25)', 'Alto (-15)', 'Médio (-8)', 'Baixo (-3)'],
        datasets: [{
          label: 'Penalidade Total',
          data: [
            sevCounts.critical * 25,
            sevCounts.high * 15,
            sevCounts.medium * 8,
            sevCounts.low * 3
          ],
          backgroundColor: ['#ff0040', '#ff6622', '#ff8c00', '#e6e600']
        }]
      },
      options: { responsive: true, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  <\/script>
</body>
</html>`;
}

// ── Helpers ──────────────────────────────────────────────────────

function esc(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatDate(iso) {
  if (!iso) return new Date().toLocaleString('pt-BR');
  try {
    return new Date(iso).toLocaleString('pt-BR', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  } catch { return iso; }
}

function extractRoutes(results) {
  const routes = [];
  for (const r of results) {
    // Primary: route-discovery stores discovered routes as details.allRoutes
    if (r.details?.allRoutes && Array.isArray(r.details.allRoutes)) {
      for (const route of r.details.allRoutes) {
        routes.push({
          path: route.path || route.url || route,
          status: route.status || route.statusCode || '—',
          type: route.category || route.type || '—',
          risk: route.risk || '—',
        });
      }
    }
    if (r.details?.criticalRoutes && Array.isArray(r.details.criticalRoutes)) {
      for (const route of r.details.criticalRoutes) {
        routes.push({ path: route.path, status: route.status || '—', type: route.category || '—', risk: 'critical' });
      }
    }
    if (r.details?.routes && Array.isArray(r.details.routes)) {
      for (const route of r.details.routes) {
        routes.push({
          path: route.path || route.url || route,
          status: route.status || route.statusCode || '—',
          type: route.category || route.type || '—',
          risk: route.risk || '—',
        });
      }
    }
    if (r.details?.discovered && Array.isArray(r.details.discovered)) {
      for (const d of r.details.discovered) {
        routes.push({ path: d.path || d.url || d, status: d.status || '—', type: d.category || '—', risk: '—' });
      }
    }
    if (r.details?.hiddenRoutes && Array.isArray(r.details.hiddenRoutes)) {
      for (const h of r.details.hiddenRoutes) {
        routes.push({ path: typeof h === 'string' ? h : h.path || h.url, status: h.status || '—', type: h.category || '—', risk: '—' });
      }
    }
  }
  // Deduplicate
  const seen = new Set();
  return routes.filter(r => {
    const key = typeof r.path === 'string' ? r.path : JSON.stringify(r.path);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function detectedHosting(results) {
  const stackResult = results.find(r => r.check === 'Stack Detection');
  const hostingList = stackResult?.details?.categories?.Hosting || [];
  return hostingList[0] || null;
}

function extractSensitiveFiles(results) {
  const files = [];
  for (const r of results.filter(r => r.status === 'FAIL' && r.check?.match(/sensit|file|storage|env|credential|pii|bundle|key/i))) {
    if (r.details?.files && Array.isArray(r.details.files)) {
      files.push(...r.details.files.map(f => ({
        name: typeof f === 'string' ? f : f.name || f.path || JSON.stringify(f),
        risk: r.severity, source: r.check
      })));
    }
    if (r.details?.findings && Array.isArray(r.details.findings)) {
      for (const f of r.details.findings) {
        files.push({ name: f.type || f.name || 'Unknown', risk: f.severity || r.severity, source: f.source || r.check });
      }
    }
    if (r.details?.sensitiveFiles && Array.isArray(r.details.sensitiveFiles)) {
      files.push(...r.details.sensitiveFiles.map(f => ({ name: typeof f === 'string' ? f : f.name || JSON.stringify(f), risk: r.severity, source: r.check })));
    }
    if (files.length === 0 || !r.details?.files) {
      files.push({ name: r.check, risk: r.severity, source: r.message?.substring(0, 60) || '' });
    }
  }
  return files;
}

function groupResults(results) {
  const groups = {};
  for (const r of results) {
    let cat = 'Outros';
    const check = (r.check || '').toLowerCase();
    if (check.match(/dns|connect/)) cat = 'DNS';
    else if (check.match(/rest(?!ore)/)) cat = 'REST API';
    else if (check.match(/rpc/)) cat = 'RPC';
    else if (check.match(/graphql/)) cat = 'GraphQL';
    else if (check.match(/storage/)) cat = 'Storage';
    else if (check.match(/edge|function/)) cat = 'Edge Functions';
    else if (check.match(/realtime/)) cat = 'Realtime';
    else if (check.match(/auth/)) cat = 'Auth';
    else if (check.match(/env|\.env/)) cat = '.env';
    else if (check.match(/rls/)) cat = 'RLS';
    else if (check.match(/cors/)) cat = 'CORS';
    else if (check.match(/service.*key/)) cat = 'Service Key';
    else if (check.match(/jwt/)) cat = 'JWT';
    else if (check.match(/route/)) cat = 'Routes';
    else if (check.match(/vuln/)) cat = 'Vulnerabilities';
    else if (check.match(/source|code/)) cat = 'Source Code';
    else if (check.match(/error/)) cat = 'Errors';
    else if (check.match(/sensit|data|pii|credential/i)) cat = 'Data/PII';
    else if (check.match(/bundle|key|token/)) cat = 'Keys/Tokens';
    else if (check.match(/stack/)) cat = 'Stack';

    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(r);
  }
  return groups;
}

function generateInsightsHTML(data) {
  const results = data.results || [];
  const score = data.score ?? 0;
  const insights = [];

  if (score < 30) {
    insights.push({ title: '🚨 ALERTA MÁXIMO — Score Abaixo de 30', desc: 'Vulnerabilidades graves requerem ação imediata. Considere desabilitar acesso público.', color: '#ff0040' });
  } else if (score < 60) {
    insights.push({ title: '⚠️ Risco Elevado', desc: 'Múltiplas vulnerabilidades. Priorize correções críticas e altas.', color: '#ff8c00' });
  } else if (score >= 90) {
    insights.push({ title: '✅ Excelente Postura de Segurança', desc: 'O projeto demonstra boas práticas. Continue monitorando.', color: '#00ff41' });
  }

  const rlsFails = results.filter(r => r.check?.match(/rls/i) && r.status === 'FAIL');
  if (rlsFails.length) insights.push({ title: '🔒 RLS Mal Configurado', desc: `${rlsFails.length} tabela(s) sem RLS. Configure em Authentication > Policies.`, color: '#ff0040' });

  const credFails = results.filter(r => r.check?.match(/credential|key|token|bundle|service/i) && r.status === 'FAIL');
  if (credFails.length) insights.push({ title: '🔑 Credenciais Expostas', desc: `${credFails.length} credencial(is). Rotacione chaves e mova para env vars.`, color: '#ff0040' });

  const piiFails = results.filter(r => r.check?.match(/pii|document|email|cpf|dado/i) && r.status === 'FAIL');
  if (piiFails.length) insights.push({ title: '📋 Dados Pessoais (LGPD)', desc: `${piiFails.length} tipo(s) de PII expostos. Possível violação de LGPD/GDPR.`, color: '#ff8c00' });

  insights.push({ title: '📋 Próximos Passos', desc: '1. Corrija CRITICAL imediatamente | 2. Aplique RLS | 3. Rotacione chaves | 4. CORS restritivo | 5. Re-scan após correções', color: '#00bfff' });

  return insights.map(i =>
    `<div class="insight-card" style="border-left-color:${i.color}">
      <h4 style="color:${i.color}">${esc(i.title)}</h4>
      <p>${esc(i.desc)}</p>
    </div>`
  ).join('');
}

module.exports = { generateHTMLReport };
