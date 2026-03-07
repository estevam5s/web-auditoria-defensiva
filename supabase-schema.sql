-- ═══════════════════════════════════════════════════════════════════
-- SUPABASE GUARD - Database Schema
-- Script completo para criação de tabelas, políticas e configurações
-- ═══════════════════════════════════════════════════════════════════

-- ============================================================
-- TABELA: audits
-- Armazena os resultados completos das auditorias
-- ============================================================
CREATE TABLE IF NOT EXISTS audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Identificação
    audit_id VARCHAR(255) UNIQUE NOT NULL,
    project_url TEXT NOT NULL,
    project_ref VARCHAR(255),
    
    -- Score e classificação
    score INTEGER DEFAULT 0,
    grade VARCHAR(10),
    grade_label VARCHAR(50),
    
    -- Estatísticas
    total_checks INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    warnings_count INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    
    -- Duração
    duration VARCHAR(50),
    
    -- Evidência
    evidence_sha256 TEXT,
    evidence_timestamp TIMESTAMP WITH TIME ZONE,
    
    -- Dados completos (JSON)
    results_json JSONB DEFAULT '[]',
    catalog_data_json JSONB DEFAULT '{}',
    
    -- Metadata do scan
    scan_type VARCHAR(50) DEFAULT 'full',
    options_json JSONB DEFAULT '{}',
    
    -- Status
    status VARCHAR(50) DEFAULT 'completed',
    
    -- IP e máquina do usuário
    user_ip INET,
    user_machine TEXT,
    user_os TEXT,
    user_region TEXT,
    user_browser TEXT
);

-- Índice para buscas rápidas
CREATE INDEX IF NOT EXISTS idx_audits_project_url ON audits(project_url);
CREATE INDEX IF NOT EXISTS idx_audits_audit_id ON audits(audit_id);
CREATE INDEX IF NOT EXISTS idx_audits_created_at ON audits(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_score ON audits(score);

-- ============================================================
-- TABELA: audit_results
-- Armazena cada resultado individual de check
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    audit_id UUID REFERENCES audits(id) ON DELETE CASCADE,
    
    -- Dados do resultado
    check_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    severity VARCHAR(50) NOT NULL,
    message TEXT,
    details_json JSONB DEFAULT '{}',
    
    -- Categoria
    category VARCHAR(100),
    check_type VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_audit_results_audit_id ON audit_results(audit_id);
CREATE INDEX IF NOT EXISTS idx_audit_results_severity ON audit_results(severity);
CREATE INDEX IF NOT EXISTS idx_audit_results_status ON audit_results(status);

-- ============================================================
-- TABELA: vulnerabilities
-- Armazena vulnerabilidades encontradas em cada auditoria
-- ============================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    audit_id UUID REFERENCES audits(id) ON DELETE CASCADE,
    
    -- Classificação
    severity VARCHAR(50) NOT NULL, -- critical, high, medium, low
    category VARCHAR(100) NOT NULL, -- rls, graphql, storage, auth, etc
    title VARCHAR(500) NOT NULL,
    description TEXT,
    
    -- Localização
    endpoint TEXT,
    table_name TEXT,
    file_path TEXT,
    
    -- Detalhes técnicos
    technical_details JSONB DEFAULT '{}',
    
    -- Recomendação
    recommendation TEXT,
    remediation_code TEXT, -- SQL ou código para correção
    
    -- Status
    status VARCHAR(50) DEFAULT 'open', -- open, fixed, ignored
    false_positive BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_audit_id ON vulnerabilities(audit_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_category ON vulnerabilities(category);

-- ============================================================
-- TABELA: exposed_secrets
-- Armazena segredos/chaves expostas encontradas
-- ============================================================
CREATE TABLE IF NOT EXISTS exposed_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    audit_id UUID REFERENCES audits(id) ON DELETE CASCADE,
    
    -- Classificação do segredo
    secret_type VARCHAR(100) NOT NULL, -- api_key, token, password, etc
    provider VARCHAR(100), -- aws, stripe, github, supabase, etc
    
    -- Localização
    source_file TEXT,
    source_url TEXT,
    line_number INTEGER,
    
    -- Valor (criptografado ou masked)
    masked_value TEXT,
    value_hash VARCHAR(255),
    
    -- Severity
    severity VARCHAR(50) DEFAULT 'high',
    
    -- Status
    status VARCHAR(50) DEFAULT 'detected',
    rotated BOOLEAN DEFAULT FALSE,
    rotated_at TIMESTAMP WITH TIME ZONE,
    
    -- Anotações
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_exposed_secrets_audit_id ON exposed_secrets(audit_id);
CREATE INDEX IF NOT EXISTS idx_exposed_secrets_type ON exposed_secrets(secret_type);

-- ============================================================
-- TABELA: scan_history
-- Histórico de scans por URL
-- ============================================================
CREATE TABLE IF NOT EXISTS scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    project_url TEXT NOT NULL,
    
    -- Status do scan
    status VARCHAR(50) NOT NULL, -- running, completed, failed, cancelled
    
    -- Progresso
    total_checks INTEGER DEFAULT 0,
    completed_checks INTEGER DEFAULT 0,
    progress_percentage INTEGER DEFAULT 0,
    
    -- Resultado
    score INTEGER,
    grade VARCHAR(10),
    
    -- Erro (se houver)
    error_message TEXT,
    
    -- Usuário
    user_ip INET,
    user_machine TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_project_url ON scan_history(project_url);
CREATE INDEX IF NOT EXISTS idx_scan_history_created_at ON scan_history(created_at DESC);

-- ============================================================
-- TABELA: user_sessions
-- Armazena sessões de usuários (opcional)
-- ============================================================
CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    session_token VARCHAR(255) UNIQUE NOT NULL,
    user_email VARCHAR(255),
    user_ip INET,
    user_machine TEXT,
    user_os TEXT,
    user_region TEXT,
    user_browser TEXT,
    
    -- Status
    is_active BOOLEAN DEFAULT TRUE,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_email ON user_sessions(user_email);

-- ============================================================
-- TABELA: audit_logs
-- Logs de auditoria do sistema
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100),
    entity_id UUID,
    
    -- Usuário
    user_email VARCHAR(255),
    user_ip INET,
    
    -- Dados
    old_values JSONB DEFAULT '{}',
    new_values JSONB DEFAULT '{}',
    
    -- Status
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);

-- ============================================================
-- POLÍTICAS RLS (Row Level Security)
-- ============================================================

-- Habilitar RLS em todas as tabelas
ALTER TABLE audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE exposed_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Políticas para audits
CREATE POLICY "Audits are viewable by owners" ON audits
    FOR SELECT USING (auth.uid() IS NOT NULL);

CREATE POLICY "Anyone can insert audits" ON audits
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Anyone can update audits" ON audits
    FOR UPDATE USING (true);

-- Políticas para audit_results
CREATE POLICY "Anyone can insert audit_results" ON audit_results
    FOR INSERT WITH CHECK (true);

-- Políticas para vulnerabilities
CREATE POLICY "Anyone can insert vulnerabilities" ON vulnerabilities
    FOR INSERT WITH CHECK (true);

-- Políticas para exposed_secrets
CREATE POLICY "Anyone can insert exposed_secrets" ON exposed_secrets
    FOR INSERT WITH CHECK (true);

-- Políticas para scan_history
CREATE POLICY "Anyone can insert scan_history" ON scan_history
    FOR INSERT WITH CHECK (true);

CREATE POLICY "Anyone can select scan_history" ON scan_history
    FOR SELECT USING (true);

-- Políticas para user_sessions
CREATE POLICY "Users can manage own sessions" ON user_sessions
    FOR ALL USING (auth.uid() IS NOT NULL);

-- Políticas para audit_logs
CREATE POLICY "Anyone can insert audit_logs" ON audit_logs
    FOR INSERT WITH CHECK (true);

-- ============================================================
-- FUNÇÕES AUXILIARES
-- ============================================================

-- Função para atualizar score médio de um projeto
CREATE OR REPLACE FUNCTION update_project_stats()
RETURNS TRIGGER AS $$
BEGIN
    -- Trigger logic can be added here if needed
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Função para gerar relatório resumido
CREATE OR REPLACE FUNCTION get_audit_summary(p_audit_id UUID)
RETURNS TABLE (
    audit_id VARCHAR(255),
    project_url TEXT,
    score INTEGER,
    grade VARCHAR(10),
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.audit_id,
        a.project_url,
        a.score,
        a.grade,
        (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'critical')::INTEGER,
        (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'high')::INTEGER,
        (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'medium')::INTEGER,
        (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'low')::INTEGER
    FROM audits a
    WHERE a.id = p_audit_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- VIEW: recent_audits
-- Visualização de auditorias recentes
-- ============================================================
CREATE OR REPLACE VIEW recent_audits AS
SELECT 
    a.id,
    a.audit_id,
    a.project_url,
    a.score,
    a.grade,
    a.grade_label,
    a.created_at,
    a.duration,
    a.user_ip,
    a.user_region,
    a.status,
    (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'critical') as critical_count,
    (SELECT COUNT(*) FROM audit_results ar WHERE ar.audit_id = a.id AND ar.severity = 'high') as high_count
FROM audits a
ORDER BY a.created_at DESC
LIMIT 100;

-- ============================================================
-- VIEW: vulnerabilities_by_severity
-- Visualização de vulnerabilidades por severidade
-- ============================================================
CREATE OR REPLACE VIEW vulnerabilities_by_severity AS
SELECT 
    v.audit_id,
    a.project_url,
    v.severity,
    v.category,
    v.title,
    v.endpoint,
    v.created_at,
    v.status
FROM vulnerabilities v
JOIN audits a ON v.audit_id = a.id
ORDER BY 
    CASE v.severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        ELSE 4 
    END,
    v.created_at DESC;

-- ============================================================
-- CONFIGURAÇÕES ADICIONAIS
-- ============================================================

-- Comentários nas tabelas
COMMENT ON TABLE audits IS 'Armazena os resultados completos das auditorias de segurança';
COMMENT ON TABLE audit_results IS 'Armazena cada resultado individual de check';
COMMENT ON TABLE vulnerabilities IS 'Armazena vulnerabilidades encontradas';
COMMENT ON TABLE exposed_secrets IS 'Armazena segredos/chaves expostas encontradas';
COMMENT ON TABLE scan_history IS 'Histórico de scans por URL';
COMMENT ON TABLE user_sessions IS 'Sessões de usuários';
COMMENT ON TABLE audit_logs IS 'Logs de auditoria do sistema';

-- Habilitar auto-update de timestamps
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- FIM DO SCRIPT
-- ============================================================
