/*  ═══════════════════════════════════════════════════════════════════
    GIT EXPOSURE CHECK — Detects publicly accessible .git/ and .env files
    Tests common sensitive paths that should never be publicly accessible
    ═══════════════════════════════════════════════════════════════════ */

const https = require('https');
const http  = require('http');
const { URL } = require('url');

function httpGet(fullUrl, timeout = 8000) {
  return new Promise(resolve => {
    const parsed = new URL(fullUrl);
    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.get(fullUrl, { rejectUnauthorized: false }, res => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', chunk => { if (body.length < 4096) body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body, headers: res.headers }));
      res.on('error', () => resolve({ status: 0, body: '', headers: {} }));
    });
    req.setTimeout(timeout, () => { req.destroy(); resolve({ status: 0, body: '', headers: {} }); });
    req.on('error', () => resolve({ status: 0, body: '', headers: {} }));
  });
}

const GIT_PROBES = [
  {
    path: '/.git/config',
    name: '.git/config',
    severity: 'critical',
    indicators: ['[core]', '[remote', '[branch'],
    description: 'Arquivo de configuração Git com informações de repositório remoto',
  },
  {
    path: '/.git/HEAD',
    name: '.git/HEAD',
    severity: 'critical',
    indicators: ['ref: refs/', 'sha1'],
    description: 'Ponteiro HEAD do repositório Git',
  },
  {
    path: '/.git/COMMIT_EDITMSG',
    name: '.git/COMMIT_EDITMSG',
    severity: 'high',
    indicators: ['feat:', 'fix:', 'chore:', 'update', 'add', 'remove', 'initial'],
    description: 'Mensagem do último commit (revela nomes de arquivos e informações internas)',
  },
  {
    path: '/.git/logs/HEAD',
    name: '.git/logs/HEAD',
    severity: 'high',
    indicators: ['commit', '0000000'],
    description: 'Log de commits do repositório',
  },
  {
    path: '/docker-compose.yml',
    name: 'docker-compose.yml',
    severity: 'critical',
    indicators: ['version:', 'services:', 'image:', 'environment:'],
    description: 'Configuração Docker Compose com possíveis credenciais e segredos',
  },
  {
    path: '/docker-compose.yaml',
    name: 'docker-compose.yaml',
    severity: 'critical',
    indicators: ['version:', 'services:', 'image:'],
    description: 'Configuração Docker Compose',
  },
  {
    path: '/.env.example',
    name: '.env.example',
    severity: 'medium',
    indicators: ['=', 'KEY=', 'SECRET=', 'PASSWORD=', 'TOKEN=', 'API'],
    description: 'Arquivo .env de exemplo (pode revelar estrutura de variáveis)',
  },
  {
    path: '/.env.backup',
    name: '.env.backup',
    severity: 'critical',
    indicators: ['=', 'KEY=', 'SECRET=', 'PASSWORD=', 'TOKEN='],
    description: 'Backup de arquivo .env com possíveis credenciais reais',
  },
  {
    path: '/.env.local',
    name: '.env.local',
    severity: 'critical',
    indicators: ['=', 'SECRET', 'PASSWORD', 'KEY', 'TOKEN'],
    description: 'Arquivo .env local com credenciais',
  },
  {
    path: '/.env.production',
    name: '.env.production',
    severity: 'critical',
    indicators: ['=', 'SECRET', 'PASSWORD', 'KEY', 'TOKEN'],
    description: 'Arquivo .env de produção com credenciais',
  },
  {
    path: '/Makefile',
    name: 'Makefile',
    severity: 'low',
    indicators: ['make', 'build:', 'deploy:', 'install:'],
    description: 'Makefile pode revelar comandos internos de build/deploy',
  },
  {
    path: '/.github/workflows',
    name: '.github/workflows',
    severity: 'medium',
    indicators: ['<!DOCTYPE', '<html', 'on:', 'jobs:'],
    description: 'Workflows de CI/CD podem revelar segredos e processos internos',
  },
];

async function checkGitExposure(config, emit) {
  const results = [];

  let baseUrl;
  try {
    const parsed = new URL(config.projectUrl);
    baseUrl = `${parsed.protocol}//${parsed.host}`;
  } catch {
    results.push({
      check: '🔍 Git Exposure — Configuração',
      status: 'ERROR',
      severity: 'info',
      message: `URL inválida: ${config.projectUrl}`,
      details: null,
    });
    return results;
  }

  emit && emit({ type: 'progress', message: `[Git Exposure] Testando ${GIT_PROBES.length} caminhos sensíveis em ${baseUrl}...` });

  const exposed = [];
  const probeResults = await Promise.all(
    GIT_PROBES.map(async probe => {
      const url = baseUrl + probe.path;
      const res = await httpGet(url);
      if (res.status === 200) {
        const bodyLower = res.body.toLowerCase();
        const hit = probe.indicators.some(ind => res.body.includes(ind) || bodyLower.includes(ind.toLowerCase()));
        if (hit) {
          return { ...probe, url, snippet: res.body.substring(0, 200).replace(/\n/g, ' ') };
        }
      }
      return null;
    })
  );

  for (const result of probeResults) {
    if (result) exposed.push(result);
  }

  if (exposed.length === 0) {
    results.push({
      check: '🔍 Git Exposure — Arquivos Sensíveis',
      status: 'PASS',
      severity: 'info',
      message: `Nenhum arquivo Git ou de configuração sensível exposto publicamente em ${baseUrl}.`,
      details: { probesTested: GIT_PROBES.length },
    });
    return results;
  }

  // Group by severity
  const criticalItems = exposed.filter(e => e.severity === 'critical');
  const highItems     = exposed.filter(e => e.severity === 'high');
  const otherItems    = exposed.filter(e => e.severity !== 'critical' && e.severity !== 'high');

  if (criticalItems.length > 0) {
    results.push({
      check: '🔍 Git Exposure — Arquivos CRÍTICOS Expostos',
      status: 'FAIL',
      severity: 'critical',
      message: `${criticalItems.length} arquivo(s) crítico(s) acessível(is) publicamente! Repositório Git ou credenciais expostos.`,
      details: {
        exposed: criticalItems.map(e => ({ path: e.name, url: e.url, description: e.description, snippet: e.snippet })),
        recommendation: 'Bloqueie acesso aos arquivos imediatamente via configuração do servidor web. Considere o repositório comprometido e rotacione todas as credenciais.',
      },
    });
  }

  if (highItems.length > 0) {
    results.push({
      check: '🔍 Git Exposure — Arquivos de Alto Risco',
      status: 'FAIL',
      severity: 'high',
      message: `${highItems.length} arquivo(s) de alto risco exposto(s) em ${baseUrl}.`,
      details: {
        exposed: highItems.map(e => ({ path: e.name, url: e.url, description: e.description })),
      },
    });
  }

  if (otherItems.length > 0) {
    results.push({
      check: '🔍 Git Exposure — Arquivos de Configuração',
      status: 'WARN',
      severity: 'medium',
      message: `${otherItems.length} arquivo(s) de configuração acessível(is) em ${baseUrl}.`,
      details: { exposed: otherItems.map(e => ({ path: e.name, url: e.url })) },
    });
  }

  return results;
}

module.exports = { checkGitExposure };
