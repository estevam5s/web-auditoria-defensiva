/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Frontend Application Logic
   Handles audit execution, SSE streaming, and report generation
   ═══════════════════════════════════════════════════════════════════ */

let auditResults = null;
let logLines = [];
let isScanning = false;

// ── DOM Elements ─────────────────────────────────────────────────
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ── Start Audit ──────────────────────────────────────────────────
async function startAudit() {
  if (isScanning) return;

  const url = $('#projectUrl').value.trim();
  if (!url) {
    appendLog('error', 'ERROR', 'Insira a URL do projeto Supabase.');
    return;
  }

  isScanning = true;
  auditResults = null;
  logLines = [];

  // UI state
  const btn = $('#btnAudit');
  btn.disabled = true;
  btn.classList.add('scanning');
  btn.innerHTML = `<svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><path d="M21 12a9 9 0 11-6.219-8.56"/></svg> Escaneando...`;

  setStatus('scanning', 'Scanning');
  $('#consoleUrl').textContent = `scan://${url.replace(/https?:\/\//, '')}`;
  clearConsole();

  // Hide previous results
  $('#scoreSection').style.display = 'none';
  $('#resultsSection').style.display = 'none';
  $('#evidenceSection').style.display = 'none';

  // Show progress
  $('#progressContainer').style.display = 'block';
  updateProgress(0, 0);

  appendLog('info', 'INIT', `Iniciando auditoria em: ${url}`);
  appendLog('info', 'MODE', 'Role: GUEST (anon key)');

  // Gather options
  const anonKey = $('#anonKey')?.value?.trim() || '';
  const options = {
    checkREST: $('#chkREST')?.checked ?? true,
    checkRPC: $('#chkRPC')?.checked ?? true,
    checkGraphQL: $('#chkGraphQL')?.checked ?? true,
    checkStorage: $('#chkStorage')?.checked ?? true,
    checkEdgeFunctions: $('#chkEdge')?.checked ?? true,
    checkRealtime: $('#chkRealtime')?.checked ?? true,
    checkAuth: $('#chkAuth')?.checked ?? true,
    checkEnvExposure: $('#chkEnv')?.checked ?? true,
    checkRLS: $('#chkRLS')?.checked ?? true,
    checkCORS: $('#chkCORS')?.checked ?? true,
    // Deep Analysis
    checkDeepSource: $('#chkDeepSource')?.checked ?? true,
    checkDeepRoutes: $('#chkDeepRoutes')?.checked ?? true,
    checkDeepVuln: $('#chkDeepVuln')?.checked ?? true,
    checkDeepSensitive: $('#chkDeepSensitive')?.checked ?? true,
    checkDeepErrors: $('#chkDeepErrors')?.checked ?? true,
    // Deep Analysis v2
    checkDeepRLS: $('#chkDeepRLS')?.checked ?? true,
    checkDeepRESTRPC: $('#chkDeepRESTRPC')?.checked ?? true,
    checkDeepEdge: $('#chkDeepEdge')?.checked ?? true,
    checkDeepBundleKeys: $('#chkDeepBundleKeys')?.checked ?? true,
    checkDeepStorage: $('#chkDeepStorage')?.checked ?? true,
    checkDeepCredPII: $('#chkDeepCredPII')?.checked ?? true,
    userMode: document.querySelector('input[name="roleMode"]:checked')?.value === 'both'
  };

  try {
    const response = await fetch('/api/audit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, anonKey, options })
    });

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event = JSON.parse(line.slice(6));
            handleEvent(event);
          } catch {}
        }
      }
    }

    // Process remaining buffer
    if (buffer.startsWith('data: ')) {
      try {
        const event = JSON.parse(buffer.slice(6));
        handleEvent(event);
      } catch {}
    }

  } catch (err) {
    appendLog('error', 'ERROR', `Falha na conexão: ${err.message}`);
    setStatus('error', 'Error');
  }

  // Reset button
  isScanning = false;
  btn.disabled = false;
  btn.classList.remove('scanning');
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg> Iniciar Auditoria`;
}

// ── Handle SSE Events ────────────────────────────────────────────
function handleEvent(event) {
  switch (event.type) {
    case 'start':
      appendLog('info', 'START', event.message);
      break;

    case 'info':
      appendLog('info', 'INFO', event.message);
      break;

    case 'progress':
      appendLog('progress', 'SCAN', event.message);
      if (event.step && event.total) {
        updateProgress(event.step, event.total);
      }
      break;

    case 'result':
      handleResult(event.data);
      break;

    case 'complete':
      handleComplete(event.results);
      break;

    case 'error':
      appendLog('error', 'ERROR', event.message);
      setStatus('error', 'Error');
      break;

    case 'log':
      const logLevel = event.level === 'warn' ? 'warn' : 'info';
      appendLog(logLevel, event.level === 'warn' ? 'WARN' : 'LOG', event.message);
      break;
  }
}

// ── Handle Individual Result ─────────────────────────────────────
function handleResult(result) {
  const typeMap = {
    'PASS': 'pass',
    'FAIL': 'fail',
    'WARN': 'warn',
    'ERROR': 'error',
    'INFO': 'info'
  };

  const prefix = result.status || 'INFO';
  const cssClass = typeMap[prefix] || 'info';

  appendLog(cssClass, prefix, `[${result.check}] ${result.message}`);
}

// ── Handle Audit Complete ────────────────────────────────────────
function handleComplete(results) {
  auditResults = results;

  appendLog('info', '─────', '─────────────────────────────────────');
  appendLog('info', 'DONE', `Auditoria concluída em ${results.duration}`);
  appendLog('info', 'SCORE', `${results.score}/100 (${results.grade.grade} — ${results.grade.label})`);
  appendLog('info', 'HASH', `SHA-256: ${results.evidence.sha256}`);
  appendLog('info', 'ID', `Audit ID: ${results.evidence.auditId}`);

  setStatus('complete', 'Complete');
  updateProgress(results.totalChecks, results.totalChecks);

  // Show results UI
  showScoreCard(results);
  showResultsList(results.results);
  showEvidence(results);
}

// ── Score Card ───────────────────────────────────────────────────
function showScoreCard(results) {
  const section = $('#scoreSection');
  section.style.display = 'block';

  // Animate score circle
  const arc = $('#scoreArc');
  const circumference = 2 * Math.PI * 54; // r=54
  const offset = circumference - (results.score / 100) * circumference;
  
  arc.style.stroke = results.grade.color;
  setTimeout(() => {
    arc.style.transition = 'stroke-dashoffset 1.5s ease';
    arc.style.strokeDashoffset = offset;
  }, 100);

  // Animate number
  animateNumber($('#scoreNumber'), 0, results.score, 1500);

  const gradeEl = $('#scoreGrade');
  gradeEl.textContent = results.grade.grade;
  gradeEl.style.color = results.grade.color;

  $('#scoreTitle').textContent = `Security Score — ${results.grade.label}`;
  $('#scoreTitle').style.color = results.grade.color;

  $('#statPass').textContent = results.passed;
  $('#statFail').textContent = results.failed;
  $('#statWarn').textContent = results.warnings;
  $('#statInfo').textContent = results.info + results.errors;

  $('#scoreMeta').textContent = 
    `Projeto: ${results.projectUrl} | Duração: ${results.duration} | ${results.totalChecks} verificações | ${new Date().toLocaleString('pt-BR')}`;

  // Scroll to score
  section.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// ── Results List ─────────────────────────────────────────────────
function showResultsList(results) {
  const section = $('#resultsSection');
  section.style.display = 'block';

  const list = $('#resultsList');
  list.innerHTML = '';

  // Sort: critical first, then by status
  const sorted = [...results].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const statusOrder = { FAIL: 0, WARN: 1, ERROR: 2, INFO: 3, PASS: 4 };
    
    const aSev = severityOrder[a.severity] ?? 5;
    const bSev = severityOrder[b.severity] ?? 5;
    if (aSev !== bSev) return aSev - bSev;
    
    const aStat = statusOrder[a.status] ?? 5;
    const bStat = statusOrder[b.status] ?? 5;
    return aStat - bStat;
  });

  for (const result of sorted) {
    const item = document.createElement('div');
    item.className = `result-item severity-${result.severity}`;
    item.dataset.status = result.status;

    item.innerHTML = `
      <div class="result-header">
        <span class="result-check">${escapeHtml(result.check)}</span>
        <div class="result-badges">
          <span class="result-status ${result.status}">${result.status}</span>
          <span class="result-severity">${result.severity}</span>
        </div>
      </div>
      <div class="result-message">${escapeHtml(result.message)}</div>
      ${result.details ? `
        <div class="result-details">
          <pre>${escapeHtml(JSON.stringify(result.details, null, 2))}</pre>
        </div>
      ` : ''}
    `;

    item.addEventListener('click', () => {
      const details = item.querySelector('.result-details');
      if (details) details.classList.toggle('open');
    });

    list.appendChild(item);
  }
}

// ── Evidence Section ─────────────────────────────────────────────
function showEvidence(results) {
  const section = $('#evidenceSection');
  section.style.display = 'block';

  const details = $('#evidenceDetails');
  details.innerHTML = `
    <div class="evidence-line"><span class="evidence-key">Audit ID:</span> ${results.evidence.auditId}</div>
    <div class="evidence-line"><span class="evidence-key">SHA-256:</span> ${results.evidence.sha256}</div>
    <div class="evidence-line"><span class="evidence-key">Timestamp:</span> ${results.evidence.timestamp}</div>
    <div class="evidence-line"><span class="evidence-key">Projeto:</span> ${results.projectUrl}</div>
    <div class="evidence-line"><span class="evidence-key">Score:</span> ${results.score}/100 (${results.grade.grade})</div>
    <div class="evidence-line"><span class="evidence-key">Duração:</span> ${results.duration}</div>
    <div class="evidence-line"><span class="evidence-key">Verificações:</span> ${results.totalChecks}</div>
  `;
}

// ── Filter Results ───────────────────────────────────────────────
function filterResults(status) {
  $$('.filter-btn').forEach(btn => btn.classList.remove('active'));
  event.target.classList.add('active');

  $$('.result-item').forEach(item => {
    if (status === 'all' || item.dataset.status === status) {
      item.style.display = '';
    } else {
      item.style.display = 'none';
    }
  });
}

// ── Console Helpers ──────────────────────────────────────────────
function appendLog(type, prefix, message) {
  const output = $('#consoleOutput');
  
  // Remove cursor
  const cursor = output.querySelector('.console-cursor');
  if (cursor) cursor.remove();

  const line = document.createElement('div');
  line.className = `console-line ${type}`;
  line.innerHTML = `<span class="line-prefix">[${escapeHtml(prefix)}]</span><span>${escapeHtml(message)}</span>`;
  output.appendChild(line);

  // Add cursor back
  const newCursor = document.createElement('div');
  newCursor.className = 'console-cursor';
  newCursor.textContent = '█';
  output.appendChild(newCursor);

  // Auto scroll
  output.scrollTop = output.scrollHeight;

  // Store for copy
  logLines.push(`[${prefix}] ${message}`);
}

function clearConsole() {
  const output = $('#consoleOutput');
  output.innerHTML = '<div class="console-cursor">█</div>';
  logLines = [];
}

function setStatus(state, text) {
  const dot = $('#statusIndicator .status-dot');
  dot.className = `status-dot ${state}`;
  $('#statusText').textContent = text;
}

function updateProgress(current, total) {
  if (total === 0) return;
  const pct = Math.round((current / total) * 100);
  $('#progressBar').style.width = `${pct}%`;
  $('#progressText').textContent = `${pct}%`;
}

function animateNumber(el, from, to, duration) {
  const start = performance.now();
  const update = (now) => {
    const elapsed = now - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  };
  requestAnimationFrame(update);
}

// ── Copy Logs ────────────────────────────────────────────────────
function copyLogs() {
  const text = logLines.join('\n');
  navigator.clipboard.writeText(text).then(() => {
    const btn = $('.console-controls .btn-icon');
    btn.style.color = 'var(--accent)';
    setTimeout(() => btn.style.color = '', 1500);
  });
}

// ── Download Report ──────────────────────────────────────────────
function downloadReport() {
  if (!auditResults) return;

  const blob = new Blob([JSON.stringify(auditResults, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `supabase-audit-${auditResults.evidence.auditId}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadReportPDF() {
  if (!auditResults) return;

  let text = '';
  text += '═══════════════════════════════════════════════════════════════\n';
  text += '  SUPABASE GUARD — Relatório de Auditoria de Segurança\n';
  text += '═══════════════════════════════════════════════════════════════\n\n';
  text += `Projeto:       ${auditResults.projectUrl}\n`;
  text += `Data:          ${auditResults.evidence.timestamp}\n`;
  text += `Audit ID:      ${auditResults.evidence.auditId}\n`;
  text += `SHA-256:       ${auditResults.evidence.sha256}\n`;
  text += `Score:         ${auditResults.score}/100 (${auditResults.grade.grade} — ${auditResults.grade.label})\n`;
  text += `Duração:       ${auditResults.duration}\n`;
  text += `Verificações:  ${auditResults.totalChecks}\n`;
  text += `Aprovados:     ${auditResults.passed}\n`;
  text += `Falhas:        ${auditResults.failed}\n`;
  text += `Alertas:       ${auditResults.warnings}\n\n`;

  text += '───────────────────────────────────────────────────────────────\n';
  text += '  RESULTADOS DETALHADOS\n';
  text += '───────────────────────────────────────────────────────────────\n\n';

  for (const r of auditResults.results) {
    text += `[${r.status}] [${r.severity.toUpperCase()}] ${r.check}\n`;
    text += `  ${r.message}\n`;
    if (r.details) {
      text += `  Detalhes: ${JSON.stringify(r.details, null, 2).split('\n').join('\n  ')}\n`;
    }
    text += '\n';
  }

  text += '═══════════════════════════════════════════════════════════════\n';
  text += '  Gerado por Supabase Guard v1.0\n';
  text += '═══════════════════════════════════════════════════════════════\n';

  const blob = new Blob([text], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `supabase-audit-${auditResults.evidence.auditId}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Modals ───────────────────────────────────────────────────────
function showTerms() {
  $('#modalBody').innerHTML = `
    <h2>Termos de Uso e Limitação de Responsabilidade</h2>
    <p>Ao utilizar o Supabase Guard, você concorda com os seguintes termos:</p>
    <ul>
      <li><strong>Uso Ético:</strong> Esta ferramenta destina-se exclusivamente a auditorias defensivas de segurança em projetos que você possui ou tem autorização explícita para testar.</li>
      <li><strong>Sem Garantias:</strong> Os resultados são fornecidos "como estão", sem garantia de completude. A ausência de vulnerabilidades detectadas não garante segurança total.</li>
      <li><strong>Responsabilidade:</strong> O uso indevido desta ferramenta para acessar sistemas sem autorização é ilegal. O usuário é inteiramente responsável pelo uso da ferramenta.</li>
      <li><strong>Dados:</strong> As URLs e chaves fornecidas são processadas em tempo real e não são armazenadas permanentemente no servidor.</li>
      <li><strong>Rate Limiting:</strong> A ferramenta faz múltiplas requisições ao projeto alvo. Use com moderação para não sobrecarregar servidores.</li>
      <li><strong>Evidência:</strong> O hash SHA-256 do relatório serve como prova de integridade, não como prova legal.</li>
    </ul>
    <p><strong>Ao clicar em "Iniciar Auditoria", você declara ter autorização para testar o projeto informado.</strong></p>
  `;
  $('#modalOverlay').style.display = 'flex';
}

function showHowItWorks() {
  $('#modalBody').innerHTML = `
    <h2>Como a Auditoria Funciona</h2>
    <p>O Supabase Guard executa uma série de verificações de segurança não-intrusivas no seu projeto Supabase:</p>
    
    <h3 style="color: var(--text-secondary); margin-top: 1rem;">Verificações Base</h3>
    <ul>
      <li><strong>DNS & Connectivity:</strong> Verifica acessibilidade, HTTPS e headers do servidor.</li>
      <li><strong>REST API:</strong> Testa se PostgREST está exposto e se tabelas são acessíveis via <code>anon</code> key.</li>
      <li><strong>RPC Functions:</strong> Enumera funções RPC comuns que podem estar expostas.</li>
      <li><strong>GraphQL:</strong> Testa se pg_graphql permite introspection e acesso a dados.</li>
      <li><strong>Storage:</strong> Verifica buckets públicos, arquivos sensíveis e listagem sem auth.</li>
      <li><strong>Edge Functions:</strong> Descobre Edge Functions e testa se requerem autenticação.</li>
      <li><strong>Realtime:</strong> Verifica se WebSocket Realtime está acessível publicamente.</li>
      <li><strong>Auth:</strong> Analisa configurações de autenticação, signup, OTP e endpoints admin.</li>
      <li><strong>.env Exposure:</strong> Busca arquivos sensíveis (.env, config, etc.) em caminhos comuns.</li>
      <li><strong>RLS:</strong> Testa se Row Level Security está ativo nas tabelas detectadas.</li>
      <li><strong>CORS:</strong> Verifica se a configuração CORS é permissiva demais.</li>
      <li><strong>Service Key:</strong> Detecta vazamento de <code>service_role</code> key em recursos públicos.</li>
      <li><strong>JWT:</strong> Analisa a estrutura e configuração do token JWT.</li>
    </ul>

    <h3 style="color: var(--accent); margin-top: 1rem;">🔬 Deep Analysis Modules</h3>
    <ul>
      <li><strong>🔍 Source Code Analysis:</strong> Escaneia código-fonte (HTML, JS, CSS) buscando 25+ padrões de secrets (AWS, Stripe, JWT, passwords, API keys), 18+ padrões inseguros (eval, innerHTML, SQL injection), source maps e stack traces.</li>
      <li><strong>🗺️ Hidden Route Discovery:</strong> Testa 200+ rotas comuns em 9 categorias (admin, API, debug, auth, git, config, backup, Next.js, WordPress). Detecta rotas ocultas, quebradas e extrai rotas de código JS.</li>
      <li><strong>🛡️ Vulnerability Scanner:</strong> Testa XSS refletido, open redirect, CSRF, clickjacking, headers de segurança, métodos HTTP perigosos, information disclosure, cookies inseguros, rate limiting e fingerprinting de tecnologias.</li>
      <li><strong>🔐 Sensitive Data Detector:</strong> Detecta PII (CPF, CNPJ, SSN, emails, telefones), dados financeiros (cartões de crédito, Stripe keys), credenciais, URLs internas, campos sensíveis em respostas API e arquivos sensíveis em storage.</li>
      <li><strong>🐛 Error Detector:</strong> Detecta erros 5xx, recursos quebrados (scripts, links, imagens), erros em código JavaScript (eval, innerHTML, debugger, secrets hardcoded), problemas SSL/TLS, mixed content e vazamento de informações em erros da API.</li>
    </ul>

    <p style="margin-top: 1rem;"><strong>Todas as verificações são feitas como GUEST (usando anon key ou sem autenticação), simulando o que um atacante externo poderia descobrir.</strong></p>
    <p>Os resultados são assinados com SHA-256 para garantir integridade. Logs em tempo real mostram o progresso de cada módulo.</p>
  `;
  $('#modalOverlay').style.display = 'flex';
}

function closeModal() {
  $('#modalOverlay').style.display = 'none';
}

// ── Utilities ────────────────────────────────────────────────────
function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ── Keyboard shortcuts ──────────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.id === 'projectUrl') {
    startAudit();
  }
  if (e.key === 'Escape') {
    closeModal();
  }
});

// ── Add CSS for spin animation ──────────────────────────────────
const style = document.createElement('style');
style.textContent = `
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .spin { animation: spin 1s linear infinite; }
`;
document.head.appendChild(style);
