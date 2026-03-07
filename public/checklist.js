/* ═══════════════════════════════════════════════════════════════════
   SUPABASE GUARD — Checklist Page Logic
   ═══════════════════════════════════════════════════════════════════ */

// ─── Fix Instructions Map ─────────────────────────────────────────
const FIXES_MAP = {
  'RLS': {
    title: 'Ativar Row Level Security (RLS)',
    text: 'O RLS está desativado ou mal configurado em suas tabelas. Qualquer usuário anônimo pode ler, inserir ou excluir dados. Ative o RLS em todas as tabelas e crie políticas de acesso restritivas.',
    code: `-- Ativar RLS na tabela
ALTER TABLE nome_da_tabela ENABLE ROW LEVEL SECURITY;

-- Política: apenas o próprio usuário vê seus dados
CREATE POLICY "usuarios_proprios" ON nome_da_tabela
  FOR ALL
  USING (auth.uid() = user_id);

-- Política somente leitura para autenticados
CREATE POLICY "leitura_autenticados" ON nome_da_tabela
  FOR SELECT
  USING (auth.role() = 'authenticated');`,
    docs: 'https://supabase.com/docs/guides/database/row-level-security'
  },
  'REST API': {
    title: 'Restringir Acesso à REST API',
    text: 'Tabelas estão expostas publicamente via PostgREST sem autenticação. Revogue o acesso do role "anon" e configure políticas RLS para controlar quem pode acessar os dados.',
    code: `-- Revogar acesso público da tabela
REVOKE ALL ON TABLE nome_da_tabela FROM anon;
REVOKE ALL ON TABLE nome_da_tabela FROM public;

-- Conceder apenas para usuários autenticados
GRANT SELECT ON TABLE nome_da_tabela TO authenticated;

-- Ativar RLS
ALTER TABLE nome_da_tabela ENABLE ROW LEVEL SECURITY;`,
    docs: 'https://supabase.com/docs/guides/api/securing-your-api'
  },
  'CORS': {
    title: 'Configurar Headers de Segurança CORS',
    text: 'Os headers de segurança HTTP estão ausentes ou mal configurados. Configure os headers de segurança no servidor ou via middleware do seu framework.',
    code: `// Next.js — next.config.js
const securityHeaders = [
  { key: 'X-DNS-Prefetch-Control', value: 'on' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline'" }
];

module.exports = {
  async headers() {
    return [{ source: '/(.*)', headers: securityHeaders }];
  }
};`,
    docs: 'https://owasp.org/www-project-secure-headers/'
  },
  'JWT': {
    title: 'Configurar JWT Seguramente',
    text: 'O JWT Secret padrão do Supabase está em uso ou a configuração de JWT está vulnerável. Gere um novo JWT Secret e configure o tempo de expiração adequado.',
    code: `-- No Dashboard do Supabase:
-- Settings > API > JWT Settings

-- Gere um novo secret seguro (mínimo 32 chars):
-- openssl rand -base64 32

-- Configure no painel:
-- JWT Secret: <novo-secret-gerado>
-- JWT Expiry: 3600 (1 hora) ou menor

-- Para rotacionar o secret (invalida todos os tokens):
-- 1. Gere novo secret
-- 2. Atualize em Settings > API > JWT Secret
-- 3. Atualize SUPABASE_JWT_SECRET no seu .env`,
    docs: 'https://supabase.com/docs/guides/auth/jwts'
  },
  'Auth': {
    title: 'Configurar Autenticação Corretamente',
    text: 'A autenticação está mal configurada. O registro público pode estar habilitado desnecessariamente, ou as configurações de email/OAuth estão inseguras.',
    code: `-- Desabilitar registro público (apenas convite):
-- Dashboard > Authentication > Settings > Disable email signups

-- Configurar URL de redirecionamento seguro:
-- Dashboard > Authentication > URL Configuration
-- Site URL: https://seudominio.com
-- Redirect URLs: https://seudominio.com/auth/callback

-- Habilitar confirmação de email:
-- Dashboard > Authentication > Email > Confirm email

-- Rate limiting (via Edge Functions ou middleware):
-- Limite tentativas de login a 5 por 15 minutos`,
    docs: 'https://supabase.com/docs/guides/auth'
  },
  'Storage': {
    title: 'Proteger Buckets de Storage',
    text: 'Buckets de storage estão públicos ou sem políticas de acesso. Configure a visibilidade dos buckets e crie políticas RLS para controlar uploads e downloads.',
    code: `-- Via SQL:
-- Tornar bucket privado
UPDATE storage.buckets
SET public = false
WHERE name = 'nome_do_bucket';

-- Criar política RLS para storage
CREATE POLICY "upload_autenticados" ON storage.objects
  FOR INSERT
  USING (auth.role() = 'authenticated')
  WITH CHECK (bucket_id = 'nome_do_bucket' AND auth.uid()::text = (storage.foldername(name))[1]);

CREATE POLICY "leitura_propria" ON storage.objects
  FOR SELECT
  USING (auth.uid()::text = (storage.foldername(name))[1]);`,
    docs: 'https://supabase.com/docs/guides/storage/security/access-control'
  },
  'GraphQL': {
    title: 'Proteger Endpoint GraphQL',
    text: 'O endpoint GraphQL está exposto ou permite introspection pública. Limite o acesso à introspection e configure autenticação obrigatória.',
    code: `-- Desabilitar introspection em produção (via configuração do pg_graphql)
-- No Dashboard > Database > Extensions > pg_graphql

-- Ou via Edge Function para interceptar:
import { createClient } from '@supabase/supabase-js'

Deno.serve(async (req) => {
  const { query } = await req.json();
  // Bloquear queries de introspection
  if (query?.includes('__schema') || query?.includes('__type')) {
    return new Response(JSON.stringify({ errors: [{ message: 'Introspection disabled' }] }), { status: 403 });
  }
  // ... continuar
})`,
    docs: 'https://supabase.com/docs/guides/graphql'
  },
  'Service Key': {
    title: 'Proteger/Revogar Service Role Key',
    text: 'A service_role key foi exposta publicamente. Esta chave tem acesso total ao banco de dados sem restrições de RLS. Revogue imediatamente e gere uma nova.',
    code: `// AÇÃO IMEDIATA NECESSÁRIA:
// 1. Acesse: Dashboard > Settings > API > Service Role Key
// 2. Clique em "Reveal" e copie a chave atual
// 3. Clique em "Regenerate" para gerar nova chave
// 4. Atualize SUPABASE_SERVICE_ROLE_KEY no seu .env e em todos os servidores

// NUNCA exponha a service_role no frontend!
// ❌ ERRADO:
const supabase = createClient(url, serviceRoleKey); // no browser/client

// ✅ CORRETO — apenas no servidor/backend:
// Em um server action ou API route:
const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);`,
    docs: 'https://supabase.com/docs/guides/api/api-keys'
  },
  'Bundle': {
    title: 'Remover Credenciais do Bundle JavaScript',
    text: 'Chaves de API foram encontradas no código JavaScript público (bundle). Mova todas as chaves para variáveis de ambiente do servidor e nunca exponha service_role no cliente.',
    code: `// ❌ ERRADO — credenciais hardcoded no código:
const supabase = createClient(
  'https://xxx.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' // exposta no bundle!
);

// ✅ CORRETO — variáveis de ambiente:
// .env.local (nunca commitar no git):
NEXT_PUBLIC_SUPABASE_URL=https://xxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ... // anon key (pública) é OK
# SUPABASE_SERVICE_ROLE_KEY apenas no servidor

// No código:
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);`,
    docs: 'https://supabase.com/docs/guides/api/api-keys'
  },
  'DNS': {
    title: 'Verificar Configuração DNS',
    text: 'Problemas de DNS detectados para o projeto. Verifique os registros DNS e certifique-se que o domínio está corretamente configurado.',
    code: `# Verificar propagação DNS:
dig A seudominio.com
nslookup seudominio.com 8.8.8.8

# Verificar registros no Supabase Dashboard:
# Settings > Custom Domains

# Configurar HTTPS:
# Adicionar CNAME: xxx.supabase.co -> seudominio.com
# Ativar SSL no provedor DNS/CDN (Cloudflare, etc)`,
    docs: 'https://supabase.com/docs/guides/platform/custom-domains'
  },
  'Realtime': {
    title: 'Proteger Canais Realtime',
    text: 'Canais de Realtime estão acessíveis sem autenticação. Configure autorização nos canais para evitar exposição de dados em tempo real.',
    code: `// Habilitar RLS no Realtime (Dashboard > Database > Replication)
// Ou via código:

const supabase = createClient(url, anonKey);

// ❌ Canal público sem autorização:
supabase.channel('*').on('postgres_changes', ...)

// ✅ Canal com filtro por usuário autenticado:
const channel = supabase
  .channel('private-channel')
  .on('postgres_changes', {
    event: '*',
    schema: 'public',
    table: 'messages',
    filter: \`user_id=eq.\${userId}\`
  }, handleChange)
  .subscribe(async (status) => {
    if (status === 'SUBSCRIBED') { /* OK */ }
  });`,
    docs: 'https://supabase.com/docs/guides/realtime/authorization'
  },
  'RPC': {
    title: 'Proteger Funções RPC',
    text: 'Funções RPC (Remote Procedure Call) estão acessíveis publicamente sem autenticação. Adicione verificação de autenticação e autorização nas funções.',
    code: `-- Adicionar verificação de autenticação na função:
CREATE OR REPLACE FUNCTION minha_funcao(param text)
RETURNS json
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  -- Verificar se usuário está autenticado
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'Autenticação obrigatória';
  END IF;

  -- Verificar role se necessário
  IF auth.role() != 'authenticated' THEN
    RAISE EXCEPTION 'Acesso negado';
  END IF;

  -- Sua lógica aqui
  RETURN json_build_object('result', param);
END;
$$;

-- Revogar acesso público:
REVOKE EXECUTE ON FUNCTION minha_funcao FROM anon;
GRANT EXECUTE ON FUNCTION minha_funcao TO authenticated;`,
    docs: 'https://supabase.com/docs/guides/database/functions'
  },
  'Edge': {
    title: 'Proteger Edge Functions',
    text: 'Edge Functions estão acessíveis publicamente ou não verificam autenticação. Adicione verificação de JWT nas funções sensíveis.',
    code: `// Edge Function com verificação de autenticação:
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

Deno.serve(async (req) => {
  // Criar cliente com contexto do usuário
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL') ?? '',
    Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    { global: { headers: { Authorization: req.headers.get('Authorization')! } } }
  );

  // Verificar autenticação
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // Lógica protegida aqui...
  return new Response(JSON.stringify({ user_id: user.id }));
})`,
    docs: 'https://supabase.com/docs/guides/functions/auth'
  },
  'Hardening': {
    title: 'Aplicar Hardening de Segurança',
    text: 'Configurações de hardening estão ausentes. Aplique as melhores práticas de segurança no Supabase Dashboard e no servidor.',
    code: `-- Configurações recomendadas no Dashboard:

-- 1. Habilitar confirmação de email:
-- Authentication > Email Templates > Confirm signup: ON

-- 2. Desabilitar signup público (se não necessário):
-- Authentication > Settings > Disable email signups

-- 3. Configurar expiração de sessão:
-- Authentication > Settings > JWT Expiry: 3600

-- 4. Habilitar MFA para admins:
-- Authentication > MFA > Enable TOTP

-- 5. Configurar IP allowlist:
-- Settings > Network > Network Restrictions

-- 6. Habilitar Point-in-Time Recovery:
-- Database > Backups > Enable PITR`,
    docs: 'https://supabase.com/docs/guides/platform/hardening'
  },
  'Credential': {
    title: 'Revogar Credenciais Expostas',
    text: 'Credenciais sensíveis foram detectadas expostas publicamente. Revogue imediatamente todas as chaves comprometidas e atualize nos seus sistemas.',
    code: `# PASSOS URGENTES:

# 1. Revogar API Keys expostas:
# Dashboard > Settings > API > Regenerate anon key
# Dashboard > Settings > API > Regenerate service_role key

# 2. Revogar JWT Secret:
# Dashboard > Settings > API > JWT Settings > Regenerate

# 3. Atualizar variáveis de ambiente:
# .env.local, Vercel, Railway, Render, etc.

# 4. Verificar se foi commitado no git:
git log --all --full-history -p -- .env
git log --all --full-history -p -- "*.env*"

# Se encontrado no histórico git:
# - Revogar chaves IMEDIATAMENTE (já estão comprometidas)
# - Usar git-filter-repo ou BFG para limpar histórico`,
    docs: 'https://supabase.com/docs/guides/platform/migrating-and-upgrading-projects'
  },
  'Open Signup': {
    title: 'Desabilitar Registro Público',
    text: 'O registro público de usuários está habilitado. Qualquer pessoa pode criar uma conta. Se sua aplicação não precisa de cadastro público, desabilite.',
    code: `-- No Dashboard:
-- Authentication > Settings > Disable email signups: ON

-- Alternativa: exigir código de convite via Edge Function:
Deno.serve(async (req) => {
  const { email, invite_code } = await req.json();

  // Verificar código de convite
  const validCodes = ['CODIGO123', 'BETA2024'];
  if (!validCodes.includes(invite_code)) {
    return new Response(JSON.stringify({ error: 'Código inválido' }), { status: 400 });
  }

  // Criar usuário apenas com código válido
  const { data, error } = await supabaseAdmin.auth.admin.createUser({ email });
  return new Response(JSON.stringify({ data, error }));
})`,
    docs: 'https://supabase.com/docs/guides/auth/managing-user-data'
  },
  'Sensitive': {
    title: 'Remover Dados Sensíveis Expostos',
    text: 'Dados sensíveis (CPF, senhas, tokens, cartões) foram detectados acessíveis via API. Oculte essas colunas via políticas RLS ou remova do schema público.',
    code: `-- Ocultar colunas sensíveis via VIEW segura:
CREATE VIEW public.users_safe AS
SELECT id, nome, email, created_at
-- Excluindo: cpf, password_hash, credit_card, token
FROM users;

-- Conceder acesso apenas à view:
REVOKE ALL ON TABLE users FROM authenticated;
GRANT SELECT ON public.users_safe TO authenticated;

-- Adicionar RLS na tabela original:
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "apenas_proprio_perfil" ON users
  FOR SELECT USING (auth.uid() = id);

-- Mascarar dados via função:
CREATE FUNCTION mask_cpf(cpf text) RETURNS text AS $$
  SELECT '***.' || substring(cpf, 4, 3) || '.' || '***-' || right(cpf, 2);
$$ LANGUAGE sql IMMUTABLE;`,
    docs: 'https://supabase.com/docs/guides/database/column-level-security'
  }
};

// ─── Severity Config ──────────────────────────────────────────────
const SEV_CONFIG = {
  critical: { label: 'Crítico', color: '#ff0040', icon: '🔴', order: 0 },
  high:     { label: 'Alto',    color: '#ff8c00', icon: '🟠', order: 1 },
  medium:   { label: 'Médio',   color: '#e6e600', icon: '🟡', order: 2 },
  low:      { label: 'Baixo',   color: '#00bfff', icon: '🔵', order: 3 },
  info:     { label: 'Info',    color: '#a855f7', icon: '🟣', order: 4 }
};

const IMPACT_MAP = {
  critical: 'Comprometimento total dos dados. Ação imediata necessária.',
  high:     'Alto risco de exposição de dados sensíveis.',
  medium:   'Risco moderado. Pode facilitar ataques combinados.',
  low:      'Risco baixo. Boa prática corrigir.',
  info:     'Informativo. Verificar se aplica ao contexto.'
};

// ─── State ────────────────────────────────────────────────────────
let auditData = null;
let auditId = null;
let checkedItems = {};
let charts = {};

// ─── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', init);

async function init() {
  // Extract auditId from URL
  const parts = window.location.pathname.split('/');
  auditId = parts[parts.length - 1];

  if (!auditId || auditId === 'checklist') {
    showError('Nenhum ID de auditoria fornecido na URL.');
    return;
  }

  // Load saved checkbox state
  const saved = localStorage.getItem(`checklist-${auditId}`);
  checkedItems = saved ? JSON.parse(saved) : {};

  try {
    const resp = await fetch(`/api/audit/${auditId}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    auditData = await resp.json();
    if (!auditData || !auditData.results) throw new Error('Dados inválidos');
    render();
  } catch (err) {
    showError(`Não foi possível carregar o relatório: ${err.message}`);
  }
}

function showError(msg) {
  document.getElementById('loadingScreen').style.display = 'none';
  document.getElementById('errorMsg').textContent = msg;
  document.getElementById('errorScreen').style.display = 'flex';
}

// ─── Render ───────────────────────────────────────────────────────
function render() {
  document.getElementById('loadingScreen').style.display = 'none';
  document.getElementById('mainContent').style.display = 'block';

  renderHeader();
  renderStats();
  renderCharts();
  renderPriorityTable();
  renderChecklist();
}

// ─── Header ───────────────────────────────────────────────────────
function renderHeader() {
  const { projectUrl, score, grade, duration, totalChecks, results, evidence } = auditData;
  const g = grade || {};

  document.title = `Relatório — ${projectUrl || 'Supabase Guard'}`;
  document.getElementById('headerUrl').textContent = projectUrl || '—';

  const badge = document.getElementById('headerScoreBadge');
  badge.textContent = `${g.grade || '?'} — ${score || 0}/100`;
  badge.className = `cl-score-badge grade-${g.grade || 'F'}`;

  const date = evidence?.timestamp ? new Date(evidence.timestamp).toLocaleString('pt-BR') : '—';
  document.getElementById('headerDate').textContent = date;
  document.getElementById('headerAuditId').textContent = auditId?.substring(0, 12) + '...' || '—';
  document.getElementById('headerDuration').textContent = duration ? `Duração: ${duration}` : '';
  document.getElementById('headerChecks').textContent = `${totalChecks || results?.length || 0} verificações`;
  document.getElementById('footerDate').textContent = date;
  document.getElementById('footerAuditId').textContent = auditId || '—';
  document.getElementById('footerHash').textContent = evidence?.sha256
    ? evidence.sha256.substring(0, 16) + '...'
    : '—';
}

// ─── Stats ────────────────────────────────────────────────────────
function renderStats() {
  const results = auditData.results || [];

  const counts = {
    critical: results.filter(r => r.severity === 'critical' && r.status !== 'PASS').length,
    high:     results.filter(r => r.severity === 'high'     && r.status !== 'PASS').length,
    medium:   results.filter(r => r.severity === 'medium'   && r.status !== 'PASS').length,
    low:      results.filter(r => r.severity === 'low'      && r.status !== 'PASS').length,
    pass:     results.filter(r => r.status === 'PASS').length
  };

  const grid = document.getElementById('statsGrid');
  grid.innerHTML = `
    ${statCard('sev-critical', counts.critical, '🔴 Críticos', 'Vulnerabilidades que exigem ação imediata')}
    ${statCard('sev-high',     counts.high,     '🟠 Altos',    'Alto risco de comprometimento')}
    ${statCard('sev-medium',   counts.medium,   '🟡 Médios',   'Risco moderado a corrigir')}
    ${statCard('sev-low',      counts.low,      '🔵 Baixos',   'Melhorias de boas práticas')}
    ${statCard('sev-pass',     counts.pass,     '✅ Aprovados','Verificações sem problemas')}
  `;
}

function statCard(cls, num, label, title) {
  return `
    <div class="cl-stat-card ${cls}" title="${esc(title)}">
      <div class="cl-stat-number">${num}</div>
      <div class="cl-stat-label">${label}</div>
    </div>
  `;
}

// ─── Charts ───────────────────────────────────────────────────────
function renderCharts() {
  const results = auditData.results || [];

  Chart.defaults.color = '#8888aa';
  Chart.defaults.borderColor = '#1a1a2e';

  // 1. Severity Doughnut
  const sevCounts = {
    critical: results.filter(r => r.severity === 'critical' && r.status !== 'PASS').length,
    high:     results.filter(r => r.severity === 'high'     && r.status !== 'PASS').length,
    medium:   results.filter(r => r.severity === 'medium'   && r.status !== 'PASS').length,
    low:      results.filter(r => r.severity === 'low'      && r.status !== 'PASS').length,
    info:     results.filter(r => r.severity === 'info'     && r.status !== 'PASS').length
  };

  const sevLabels = ['Crítico', 'Alto', 'Médio', 'Baixo', 'Info'];
  const sevValues = [sevCounts.critical, sevCounts.high, sevCounts.medium, sevCounts.low, sevCounts.info];
  const sevColors = ['#ff0040', '#ff8c00', '#e6e600', '#00bfff', '#a855f7'];

  const sevFiltered = sevLabels.map((l, i) => ({ l, v: sevValues[i], c: sevColors[i] })).filter(x => x.v > 0);

  if (charts.severity) charts.severity.destroy();
  const ctxSev = document.getElementById('chartSeverity');
  if (sevFiltered.length > 0) {
    charts.severity = new Chart(ctxSev, {
      type: 'doughnut',
      data: {
        labels: sevFiltered.map(x => x.l),
        datasets: [{ data: sevFiltered.map(x => x.v), backgroundColor: sevFiltered.map(x => x.c), borderWidth: 2, borderColor: '#111118' }]
      },
      options: {
        cutout: '65%', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 8, boxWidth: 12 } } }
      }
    });
  } else {
    ctxSev.parentElement.innerHTML = '<p style="text-align:center;color:#6a6a8a;font-size:0.85rem;padding:2rem">Nenhuma vulnerabilidade encontrada ✅</p>';
  }

  // 2. Category Bar
  const categories = {};
  for (const r of results) {
    if (r.status === 'PASS') continue;
    const cat = (r.check || '').split(' — ')[0].split(' Deep')[0].split(' —')[0].trim().split(' ').slice(0, 2).join(' ');
    if (!categories[cat]) categories[cat] = 0;
    categories[cat]++;
  }

  const catSorted = Object.entries(categories)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  if (charts.category) charts.category.destroy();
  const ctxCat = document.getElementById('chartCategory');
  if (catSorted.length > 0) {
    charts.category = new Chart(ctxCat, {
      type: 'bar',
      data: {
        labels: catSorted.map(([k]) => k),
        datasets: [{
          label: 'Issues',
          data: catSorted.map(([, v]) => v),
          backgroundColor: catSorted.map(([, v]) => {
            if (v >= 5) return 'rgba(255,0,64,0.7)';
            if (v >= 3) return 'rgba(255,140,0,0.7)';
            return 'rgba(230,230,0,0.5)';
          }),
          borderRadius: 4,
          borderSkipped: false
        }]
      },
      options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: '#1a1a2e' }, ticks: { font: { size: 10 } } },
          y: { grid: { display: false }, ticks: { font: { size: 10 }, color: '#aaaacc' } }
        }
      }
    });
  }

  // 3. Status Pie
  const statusCounts = {
    PASS: results.filter(r => r.status === 'PASS').length,
    FAIL: results.filter(r => r.status === 'FAIL').length,
    WARN: results.filter(r => r.status === 'WARN').length,
    INFO: results.filter(r => r.status === 'INFO' || r.status === 'ERROR').length
  };

  if (charts.status) charts.status.destroy();
  charts.status = new Chart(document.getElementById('chartStatus'), {
    type: 'doughnut',
    data: {
      labels: ['Aprovado', 'Falhou', 'Alerta', 'Info'],
      datasets: [{
        data: [statusCounts.PASS, statusCounts.FAIL, statusCounts.WARN, statusCounts.INFO],
        backgroundColor: ['#00cc33', '#ff0040', '#ff8c00', '#a855f7'],
        borderWidth: 2, borderColor: '#111118'
      }]
    },
    options: {
      cutout: '65%', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { position: 'bottom', labels: { font: { size: 11 }, padding: 8, boxWidth: 12 } } }
    }
  });
}

// ─── Priority Table ───────────────────────────────────────────────
function renderPriorityTable() {
  const results = auditData.results || [];

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const issues = results
    .filter(r => r.status !== 'PASS')
    .sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5))
    .slice(0, 12);

  const tbody = document.getElementById('priorityTableBody');
  if (issues.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#6a6a8a;padding:2rem">Nenhuma vulnerabilidade encontrada</td></tr>';
    return;
  }

  tbody.innerHTML = issues.map((r, i) => {
    const sev = r.severity || 'info';
    const rowClass = ['critical', 'high', 'medium'].includes(sev) ? `row-${sev}` : '';
    return `
      <tr class="${rowClass}">
        <td><span class="cl-rank">#${i + 1}</span></td>
        <td><span class="cl-sev-badge sev-${sev}">${(SEV_CONFIG[sev]?.icon || '')} ${SEV_CONFIG[sev]?.label || sev}</span></td>
        <td>
          <div class="cl-check-name">${esc(r.check || '—')}</div>
        </td>
        <td><div class="cl-check-msg">${esc(r.message || '—')}</div></td>
        <td><div class="cl-impact">${esc(IMPACT_MAP[sev] || '—')}</div></td>
      </tr>
    `;
  }).join('');
}

// ─── Checklist ────────────────────────────────────────────────────
function renderChecklist() {
  const results = auditData.results || [];

  // Group by severity, only non-PASS
  const groups = {
    critical: [],
    high: [],
    medium: [],
    low: [],
    info: []
  };

  for (const r of results) {
    if (r.status === 'PASS') continue;
    const sev = r.severity || 'info';
    if (groups[sev]) groups[sev].push(r);
  }

  const container = document.getElementById('checklistContainer');
  container.innerHTML = '';

  const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];

  for (const sev of sevOrder) {
    const items = groups[sev];
    if (!items || items.length === 0) continue;

    const cfg = SEV_CONFIG[sev];
    const groupEl = document.createElement('div');
    groupEl.className = `cl-group group-${sev}`;

    groupEl.innerHTML = `
      <div class="cl-group-header">
        <span>${cfg.icon}</span>
        <span class="cl-group-label">${cfg.label}</span>
        <span class="cl-group-count">${items.length} item(s)</span>
      </div>
    `;

    for (let i = 0; i < items.length; i++) {
      const r = items[i];
      const itemId = `${sev}-${i}-${r.check?.replace(/\W/g, '') || 'item'}`;
      groupEl.appendChild(buildChecklistItem(r, itemId, sev));
    }

    container.appendChild(groupEl);
  }

  updateProgress();
}

function buildChecklistItem(r, itemId, sev) {
  const isChecked = !!checkedItems[itemId];
  const fixInfo = getFixInfo(r);

  const div = document.createElement('div');
  div.className = `cl-item${isChecked ? ' is-checked' : ''}`;
  div.dataset.id = itemId;

  div.innerHTML = `
    <div class="cl-item-header">
      <div class="cl-checkbox${isChecked ? ' checked' : ''}" onclick="toggleCheck('${itemId}', event)"></div>
      <div class="cl-item-main">
        <div class="cl-item-top">
          <span class="cl-sev-badge sev-${sev}">${SEV_CONFIG[sev]?.icon || ''} ${SEV_CONFIG[sev]?.label || sev}</span>
          <span class="cl-item-title">${esc(r.check || '—')}</span>
        </div>
        <div class="cl-item-msg">${esc(r.message || '')}</div>
      </div>
      ${fixInfo ? `<button class="cl-item-expand" onclick="toggleFix(this, event)">
        Ver correção <span class="cl-item-expand-arrow">▼</span>
      </button>` : ''}
    </div>
    ${fixInfo ? `
      <div class="cl-fix-panel">
        <div class="cl-fix-label">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14">
            <path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/>
          </svg>
          Como Corrigir
        </div>
        <div class="cl-fix-text">${fixInfo.text}</div>
        ${fixInfo.code ? `<pre class="cl-fix-code">${esc(fixInfo.code)}</pre>` : ''}
        ${r.details?.recommendation ? `<div class="cl-fix-text"><strong>Recomendação específica:</strong> ${esc(r.details.recommendation)}</div>` : ''}
        ${fixInfo.docs ? `<div class="cl-fix-docs">📖 Documentação: <a href="${fixInfo.docs}" target="_blank" rel="noopener noreferrer">${fixInfo.docs}</a></div>` : ''}
      </div>
    ` : ''}
  `;

  return div;
}

function getFixInfo(r) {
  const check = (r.check || '').toLowerCase();
  // Try to match by keyword in check name
  for (const [key, fix] of Object.entries(FIXES_MAP)) {
    if (check.includes(key.toLowerCase())) return fix;
  }
  // Fallback: use details.recommendation if available
  if (r.details?.recommendation) {
    return {
      text: r.details.recommendation,
      code: null,
      docs: null
    };
  }
  return null;
}

// ─── Checkbox Logic ───────────────────────────────────────────────
function toggleCheck(itemId, event) {
  event.stopPropagation();
  checkedItems[itemId] = !checkedItems[itemId];
  localStorage.setItem(`checklist-${auditId}`, JSON.stringify(checkedItems));

  const item = document.querySelector(`[data-id="${itemId}"]`);
  if (!item) return;

  const checkbox = item.querySelector('.cl-checkbox');
  if (checkedItems[itemId]) {
    item.classList.add('is-checked');
    checkbox.classList.add('checked');
  } else {
    item.classList.remove('is-checked');
    checkbox.classList.remove('checked');
  }

  updateProgress();
}

function toggleFix(btn, event) {
  event.stopPropagation();
  const panel = btn.closest('.cl-item').querySelector('.cl-fix-panel');
  if (!panel) return;
  const isOpen = panel.classList.toggle('open');
  btn.classList.toggle('open', isOpen);
}

function updateProgress() {
  const all = document.querySelectorAll('.cl-item');
  const total = all.length;
  const done = Object.values(checkedItems).filter(Boolean).length;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;

  document.getElementById('progressPill').textContent = `${done} / ${total} corrigido(s)`;
  document.getElementById('progressBar').style.width = `${pct}%`;
}

// ─── Utilities ────────────────────────────────────────────────────
function esc(str) {
  if (typeof str !== 'string') return String(str ?? '');
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
