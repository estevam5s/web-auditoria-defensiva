Comparação: Seu Sistema vs SupabaseGuard — estevamsouza.com.br
Visão Geral
Aspecto	Seu Sistema	SupabaseGuard
Duração	25.4s	~26s
Checks executados	26 módulos	10 etapas
Score final	0/100 (F)	N/A (sem score)
Audit ID + Hash	Sim (SHA-256)	Sim (UUID)
Auto-detecção Supabase	Não (mode GUEST sem key)	Sim (detectou URL + anon key)
Onde o SupabaseGuard foi MELHOR
Capacidade	SupabaseGuard	Seu Sistema
Auto-detecção de credenciais	Detectou SUPABASE_URL e ANON_KEY automaticamente do bundle JS	Rodou como GUEST sem anon key — perdeu contexto Supabase
OpenAPI Introspection	Descobriu 92 rotas (89 tabelas + 3 RPCs) via catálogo OpenAPI	Não fez OpenAPI introspection
REST Scan real	Testou 60 tabelas individualmente, encontrou ~35 com dados expostos com contagem de rows (ex: study_schedule = 112 rows, roadmap_items = 78 rows)	REST API: "Nenhuma tabela comum encontrada" (porque não tinha a key)
GraphQL Introspection	Descobriu schema com 930 types e 8 campos queryable, testou 8 probes	Apenas testou se endpoint existe
Relationship RLS Scan	Testou 72 combinações de joins entre tabelas, encontrou 1 leak indireto (study_levels → study_resources)	Não fez este tipo de teste
Auth Settings	Detectou signup aberto + email confirmation desabilitada — achados críticos	"Não foi possível verificar configuração de signup"
Realtime Probe	Conectou WebSocket e fez channel join probe — confirmou join anônimo	Detectou que está ativo mas sem teste de join
Hardening quantitativo	147 endpoints sem rate-limit, 68 com cache inseguro	Genérico: "6 headers ausentes"
RPC Scan real	Testou 3 RPCs com respostas reais (400/404)	"24 RPCs descobertas" mas sem testar com dados
Onde o SEU SISTEMA foi MELHOR
Capacidade	Seu Sistema	SupabaseGuard
Source Code Deep Analysis	142 secrets, 70 padrões inseguros, 1 source map, 6 erros em 66 assets	Apenas baixou 9 scripts, sem análise de segurança
Route Discovery	327 rotas escaneadas, encontrou 6 expostas incluindo 4 CRÍTICAS: /admin, /admin/, /admin/login, /admin/js/env.js	Não fez route discovery
Vulnerability Scanner	Testou XSS, clickjacking, CSRF, headers (1/10), rate limiting, métodos HTTP perigosos	Não tem scanner de vulnerabilidades web
Sensitive Data Detector	25 achados — 6 críticos, 4 altos, 8 médios, 7 baixos	Não tem módulo dedicado
Error Detector	22 problemas JS (6 erros, 7 avisos), SSL/TLS, performance, recursos quebrados	Não analisa erros
Storage Deep	49 buckets ocultos descobertos, 300 arquivos críticos públicos (.env, .pem, .sql, .csv por bucket)	Apenas testou listagem de buckets (resultado: 0)
Edge Functions Deep	114 funções testadas, 35 descobertas, 26 SENSÍVEIS sem auth (reset-password, payment, admin, delete-user, etc.)	Não testou Edge Functions
Credential/PII	GitHub Token em /admin/js/env.js, 5 tipos de PII expostos	Não tem detector de credenciais/PII
Stack Detection	8 tecnologias: React, Next.js, jQuery, Vercel, Cloudflare, Firebase, Supabase, HTTPS	Não faz fingerprinting
Bundle Key Scanner	63 bundles + 8 scripts dinâmicos analisados	Não tem módulo dedicado
robots.txt / sitemap	Encontrou robots.txt com 2 Disallow + sitemap com 10 URLs	Não analisa
Veredito Final