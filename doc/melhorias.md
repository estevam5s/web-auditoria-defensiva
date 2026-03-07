Veredito Final
Desta vez a comparação é muito mais equilibrada, e cada sistema tem pontos fortes claros:

SupabaseGuard ganha em profundidade Supabase-específica:

A auto-detecção de credenciais é um diferencial enorme. Seu sistema rodou "cego" sem a anon key, enquanto o concorrente detectou automaticamente do bundle JS e fez uma auditoria Supabase completa
O REST Scan real com contagem de rows, o GraphQL introspection com 930 types, e o Relationship RLS Scan (joins entre tabelas) são técnicas avançadas que seu sistema não possui
O Auth Settings detection encontrou problemas críticos reais (signup aberto + sem email confirmation) que seu sistema não conseguiu detectar