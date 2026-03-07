Deve verificar se esta implementado no sistema:

1. Auto-detecção de SUPABASE_URL e ANON_KEY a partir dos bundles JavaScript públicos, permitindo auditoria completa mesmo sem fornecimento manual das credenciais.
2. OpenAPI introspection: escaneie o endpoint /rest/v1/ para identificar todas as tabelas e funções RPC disponíveis, gerando um catálogo dinâmico de rotas.
3. REST Scan real: utilize a anon key detectada para testar cada tabela individualmente, verificando exposição de dados, contagem de registros e permissões.
4. Relationship RLS Scan: teste joins entre tabelas para identificar vazamentos indiretos de dados via relacionamentos.
5. GraphQL introspection: analise o endpoint GraphQL para mapear tipos, queries e possíveis exposições.
6. Auth Settings detection: verifique configurações de signup aberto, confirmação de email e outras fragilidades de autenticação.
7. Mantenha e amplie os módulos de segurança web geral (source code, routes, vulnerabilities, errors, storage deep, edge functions deep, PII, etc.), garantindo cobertura superior ao concorrente.

Priorize integração automática, cobertura máxima e relatórios detalhados com score, hash e audit ID."

Monte um plano de acao e faca