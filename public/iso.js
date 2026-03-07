/* ============================================================
 * iso.js — ISO 27001:2022 Compliance Engine
 * Supabase Guard · Auditoria Defensiva
 * ============================================================ */

'use strict';

/* ----------------------------------------------------------
 * ISO 27001:2022 — 93 Controles (A.5 a A.8)
 * ---------------------------------------------------------- */
const ISO_CONTROLS = [

  /* ========================================================
   * A.5 — CONTROLES ORGANIZACIONAIS (37 controles)
   * ======================================================== */
  {
    id: 'A.5.1', name: 'Políticas de segurança da informação',
    description: 'Políticas de segurança da informação devem ser definidas, aprovadas pela direção, publicadas, comunicadas e reconhecidas pelo pessoal relevante e partes interessadas.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Elabore e aprove formalmente uma Política de Segurança da Informação (PSI). Divulgue a todos os colaboradores e partes interessadas. Realize revisões periódicas (mínimo anual).',
    iso27002: 'Controles baseados em políticas fornecem a base para a segurança da informação em toda a organização.',
    risk: 'high'
  },
  {
    id: 'A.5.2', name: 'Funções e responsabilidades de segurança da informação',
    description: 'Funções e responsabilidades de segurança da informação devem ser definidas e alocadas de acordo com as necessidades da organização.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Defina um RACI de segurança. Nomeie um responsável pela segurança (CISO/ISO). Documente responsabilidades em contratos e descritivos de cargo.',
    iso27002: 'A alocação de responsabilidades garante que os controles de segurança sejam gerenciados de forma eficaz.',
    risk: 'medium'
  },
  {
    id: 'A.5.3', name: 'Segregação de funções',
    description: 'Funções conflitantes e áreas de responsabilidade conflitantes devem ser segregadas.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Identifique funções conflitantes (ex: desenvolver e aprovar código, administrar sistema e auditar logs). Implante controles compensatórios onde segregação total não for viável.',
    iso27002: 'A segregação reduz o risco de uso indevido ou não autorizado de ativos da organização.',
    risk: 'medium'
  },
  {
    id: 'A.5.4', name: 'Responsabilidades da direção',
    description: 'A direção deve exigir que todo o pessoal aplique a segurança da informação de acordo com as políticas, procedimentos e regulamentos estabelecidos.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'A alta direção deve comprometer-se formalmente com a segurança. Inclua segurança em objetivos de desempenho. Realize treinamentos periódicos mandatórios.',
    iso27002: 'O comprometimento da direção é fundamental para a efetividade do SGSI.',
    risk: 'medium'
  },
  {
    id: 'A.5.5', name: 'Contato com autoridades',
    description: 'A organização deve estabelecer e manter contato com autoridades relevantes.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Mapeie autoridades relevantes (ANPD, CERT.br, reguladores setoriais). Estabeleça canais de comunicação. Defina procedimento de notificação de incidentes.',
    iso27002: 'Contatos com autoridades permitem resposta rápida a incidentes e conformidade regulatória.',
    risk: 'low'
  },
  {
    id: 'A.5.6', name: 'Contato com grupos de interesse especial',
    description: 'A organização deve estabelecer e manter contato com grupos de interesse especial ou outros fóruns especializados e associações profissionais de segurança.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Participe de grupos como FIRST, ISACs setoriais, comunidades de segurança. Monitore feeds de threat intelligence.',
    iso27002: 'Grupos de interesse fornecem inteligência sobre ameaças emergentes e boas práticas.',
    risk: 'low'
  },
  {
    id: 'A.5.7', name: 'Inteligência de ameaças',
    description: 'Informações relacionadas a ameaças de segurança da informação devem ser coletadas e analisadas para produzir inteligência sobre ameaças.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante um programa de Threat Intelligence. Subscreva feeds de CVEs e IOCs. Integre com SIEM. Revise e aja sobre alertas regularmente.',
    iso27002: 'A inteligência de ameaças permite defesa proativa e antecipação de ataques.',
    risk: 'medium'
  },
  {
    id: 'A.5.8', name: 'Segurança da informação no gerenciamento de projetos',
    description: 'A segurança da informação deve ser integrada no gerenciamento de projetos.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Inclua segurança em gates de aprovação de projetos. Realize análise de risco em novos projetos. Exija revisão de segurança antes de go-live.',
    iso27002: 'A integração de segurança em projetos evita vulnerabilidades introduzidas no desenvolvimento.',
    risk: 'medium'
  },
  {
    id: 'A.5.9', name: 'Inventário de informações e outros ativos associados',
    description: 'Um inventário de informações e outros ativos associados, incluindo proprietários, deve ser desenvolvido e mantido.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Crie e mantenha um inventário de ativos de informação (tabelas, APIs, buckets, serviços). Defina proprietários para cada ativo. Revise periodicamente.',
    iso27002: 'O inventário é a base para a gestão de risco e aplicação de controles adequados.',
    risk: 'medium'
  },
  {
    id: 'A.5.10', name: 'Uso aceitável de informações e outros ativos associados',
    description: 'Regras para o uso aceitável e procedimentos para manuseio de informações e outros ativos associados devem ser identificados, documentados e implementados.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Elabore Política de Uso Aceitável. Treine colaboradores. Inclua cláusulas nos contratos de trabalho e terceiros.',
    iso27002: 'Políticas de uso aceitável definem o comportamento esperado e reduzem riscos internos.',
    risk: 'low'
  },
  {
    id: 'A.5.11', name: 'Devolução de ativos',
    description: 'O pessoal e outras partes interessadas, conforme apropriado, devem devolver todos os ativos da organização mediante rescisão de seu emprego, contrato ou acordo.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante checklist de offboarding: revogação de acessos, devolução de equipamentos, transferência de responsabilidades. Automatize revogação de credenciais.',
    iso27002: 'A devolução de ativos garante que informações não sejam retidas indevidamente após término do vínculo.',
    risk: 'medium'
  },
  {
    id: 'A.5.12', name: 'Classificação da informação',
    description: 'A informação deve ser classificada de acordo com as necessidades de segurança da informação da organização com base na confidencialidade, integridade, disponibilidade e requisitos relevantes das partes interessadas.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Defina níveis de classificação (Público, Interno, Confidencial, Restrito). Classifique dados em tabelas do Supabase. Aplique controles de acesso proporcionais à classificação.',
    iso27002: 'A classificação garante que a informação receba nível adequado de proteção.',
    risk: 'medium'
  },
  {
    id: 'A.5.13', name: 'Rotulagem da informação',
    description: 'Um conjunto apropriado de procedimentos para rotulagem da informação deve ser desenvolvido e implementado de acordo com o esquema de classificação da informação adotado pela organização.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante rotulagem em documentos, e-mails e sistemas. Use metadados em APIs para indicar classificação. Configure cabeçalhos de resposta com nível de sensibilidade.',
    iso27002: 'A rotulagem facilita o manuseio correto da informação em toda a sua vida útil.',
    risk: 'low'
  },
  {
    id: 'A.5.14', name: 'Transferência da informação',
    description: 'Regras, procedimentos ou acordos de transferência da informação devem estar em vigor para todos os tipos de instalações de transferência dentro da organização e entre a organização e outras partes.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['.env', 'Key Exposure', 'Credential'],
    evaluator(results) {
      const envCheck = results.find(r => /\.env|Key Exposure/i.test(r.check));
      const credCheck = results.find(r => /Credential|PII/i.test(r.check));
      const issues = [envCheck, credCheck].filter(r => r && r.status === 'FAIL');
      if (issues.length >= 2) return { status: 'non-compliant', evidence: 'Credenciais e dados sensíveis expostos na transferência: ' + issues.map(r => r.check).join(', ') };
      if (issues.length === 1) return { status: 'partial', evidence: 'Problema parcial de transferência segura: ' + issues[0].check };
      return { status: 'partial', evidence: 'Transferência básica verificada (análise manual necessária para políticas formais)' };
    },
    remediation: 'Use HTTPS/TLS para todas as transferências. Implante DLP. Documente acordos de compartilhamento de dados. Evite envio de dados sensíveis por e-mail não criptografado.',
    iso27002: 'Controles de transferência protegem a informação durante o trânsito entre sistemas e partes.',
    risk: 'high'
  },
  {
    id: 'A.5.15', name: 'Controle de acesso',
    description: 'Regras para controlar o acesso físico e lógico a informações e outros ativos associados devem ser estabelecidas e implementadas com base nos requisitos de negócios e segurança da informação.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['RLS', 'Auth', 'Service Key'],
    evaluator(results) {
      const rls = results.find(r => /RLS Policy/i.test(r.check));
      const auth = results.find(r => /Auth Endpoints/i.test(r.check));
      const sk = results.find(r => /Service Key/i.test(r.check));
      const fails = [rls, auth, sk].filter(r => r && r.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Controles de acesso críticos falhos: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Controle de acesso parcialmente implementado. Falha em: ' + fails[0].check };
      const warns = [rls, auth, sk].filter(r => r && r.status === 'WARN');
      if (warns.length > 0) return { status: 'partial', evidence: 'Controles de acesso com alertas: ' + warns.map(r => r.check).join(', ') };
      return { status: 'compliant', evidence: 'Controles básicos de acesso (RLS, Auth, Service Key) verificados' };
    },
    remediation: 'Ative RLS em todas as tabelas. Use roles mínimas. Revogue service keys desnecessárias. Implante MFA. Revise acessos periodicamente.',
    iso27002: 'O controle de acesso é fundamental para garantir que apenas usuários autorizados acessem informações.',
    risk: 'critical'
  },
  {
    id: 'A.5.16', name: 'Gerenciamento de identidade',
    description: 'O ciclo de vida completo das identidades deve ser gerenciado.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['Auth', 'Open Signup'],
    evaluator(results) {
      const signup = results.find(r => /Open Signup/i.test(r.check));
      const auth = results.find(r => /Auth Settings/i.test(r.check));
      if (signup?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Cadastro aberto sem controle: qualquer pessoa pode criar contas' };
      if (auth?.status === 'FAIL') return { status: 'partial', evidence: 'Configurações de autenticação inadequadas' };
      return { status: 'partial', evidence: 'Identidade básica verificada (provisionamento/desprovisionamento manual necessário)' };
    },
    remediation: 'Implante processo formal de provisionamento/desprovisionamento. Restrinja cadastro a domínios autorizados. Use SSO corporativo. Revise contas periodicamente.',
    iso27002: 'O gerenciamento de identidade garante que cada usuário tenha identidade única e rastreável.',
    risk: 'high'
  },
  {
    id: 'A.5.17', name: 'Informações de autenticação',
    description: 'A alocação e o gerenciamento de informações de autenticação devem ser controlados por um processo de gerenciamento, incluindo aconselhamento ao pessoal sobre o manuseio adequado de informações de autenticação.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['Auth', 'JWT', 'Service Key'],
    evaluator(results) {
      const jwt = results.find(r => /JWT/i.test(r.check));
      const sk = results.find(r => /Service Key/i.test(r.check));
      const fails = [jwt, sk].filter(r => r && r.status === 'FAIL');
      if (fails.length >= 1) return { status: 'non-compliant', evidence: 'Informações de autenticação comprometidas: ' + fails.map(r => r.check).join(', ') };
      const warns = [jwt, sk].filter(r => r && r.status === 'WARN');
      if (warns.length > 0) return { status: 'partial', evidence: 'Alertas em autenticação: ' + warns.map(r => r.check).join(', ') };
      return { status: 'partial', evidence: 'Autenticação básica verificada (políticas de senha e rotação manual necessárias)' };
    },
    remediation: 'Use senhas fortes e únicas. Rotacione chaves regularmente. Nunca armazene credenciais em código. Use gerenciador de senhas. Implante políticas de expiração.',
    iso27002: 'Controles de autenticação previnem acesso não autorizado via credenciais comprometidas.',
    risk: 'high'
  },
  {
    id: 'A.5.18', name: 'Direitos de acesso',
    description: 'Os direitos de acesso a informações e outros ativos associados devem ser provisionados, revisados, modificados e removidos de acordo com a política de controle de acesso específica do tópico e as regras da organização.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['RLS', 'Auth', 'Service Key'],
    evaluator(results) {
      const rls = results.find(r => /RLS/i.test(r.check) && r.status === 'FAIL');
      const sk = results.find(r => /Service Key/i.test(r.check) && r.status === 'FAIL');
      if (rls && sk) return { status: 'non-compliant', evidence: 'Direitos de acesso excessivos: RLS desativado e Service Key exposta' };
      if (rls || sk) return { status: 'partial', evidence: 'Direitos de acesso parcialmente controlados' };
      return { status: 'partial', evidence: 'Direitos básicos verificados (revisão periódica e least privilege manual necessários)' };
    },
    remediation: 'Aplique princípio do mínimo privilégio. Revise acessos a cada 90 dias. Revogue acessos imediatamente após término do vínculo. Use roles granulares.',
    iso27002: 'O controle de direitos de acesso garante que usuários tenham apenas o acesso mínimo necessário.',
    risk: 'high'
  },
  {
    id: 'A.5.19', name: 'Segurança da informação nas relações com fornecedores',
    description: 'Processos e procedimentos devem ser definidos e implementados para gerenciar os riscos de segurança da informação associados ao uso de produtos ou serviços dos fornecedores.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Avalie segurança de fornecedores antes da contratação. Inclua requisitos de segurança em contratos (SLAs, SASTs, relatórios de pentest). Monitore continuamente.',
    iso27002: 'A gestão de fornecedores reduz riscos introduzidos pela cadeia de suprimentos.',
    risk: 'high'
  },
  {
    id: 'A.5.20', name: 'Tratamento da segurança da informação nos contratos com fornecedores',
    description: 'Requisitos relevantes de segurança da informação devem ser estabelecidos e acordados com cada fornecedor com base no tipo de relacionamento com o fornecedor.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Inclua cláusulas de segurança em todos os contratos: proteção de dados, notificação de incidentes, direito de auditoria, conformidade regulatória.',
    iso27002: 'Contratos com fornecedores estabelecem responsabilidades claras de segurança.',
    risk: 'medium'
  },
  {
    id: 'A.5.21', name: 'Gerenciamento da segurança da informação na cadeia de fornecimento de TIC',
    description: 'Processos e procedimentos devem ser definidos e implementados para gerenciar os riscos de segurança da informação associados à cadeia de fornecimento de produtos e serviços de TIC.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Avalie riscos de componentes de terceiros (npm, pip). Monitore CVEs de dependências. Use SBOMs. Prefira fornecedores com certificações de segurança.',
    iso27002: 'A segurança da cadeia de suprimentos de TIC protege contra ataques via componentes comprometidos.',
    risk: 'high'
  },
  {
    id: 'A.5.22', name: 'Monitoramento, revisão e gerenciamento de mudança dos serviços de fornecedores',
    description: 'A organização deve regularmente monitorar, revisar, avaliar e gerenciar mudanças nas práticas de segurança da informação dos fornecedores e na prestação de serviços.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Agende revisões periódicas de SLA com fornecedores. Monitore mudanças em serviços críticos (Supabase, CDN, cloud). Implante gestão de mudanças formal.',
    iso27002: 'O monitoramento contínuo de fornecedores garante que os níveis de segurança acordados sejam mantidos.',
    risk: 'medium'
  },
  {
    id: 'A.5.23', name: 'Segurança da informação para uso de serviços em nuvem',
    description: 'Os processos para aquisição, uso, gerenciamento e saída de serviços em nuvem devem ser estabelecidos de acordo com os requisitos de segurança da informação da organização.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['Stack Detection', 'Storage', 'Edge'],
    evaluator(results) {
      const storage = results.find(r => /Storage/i.test(r.check));
      const edge = results.find(r => /Edge/i.test(r.check));
      if (storage?.status === 'FAIL' || edge?.status === 'FAIL') {
        return { status: 'partial', evidence: 'Serviços em nuvem com configurações inadequadas: ' + [storage, edge].filter(r => r?.status === 'FAIL').map(r => r.check).join(', ') };
      }
      return { status: 'partial', evidence: 'Uso de Supabase (nuvem) detectado — políticas formais de governança de nuvem necessárias' };
    },
    remediation: 'Documente estratégia de nuvem. Implante CSPM. Avalie conformidade do provedor (SOC2, ISO 27001). Defina critérios de saída e portabilidade.',
    iso27002: 'A governança de nuvem garante que serviços externos atendam requisitos de segurança.',
    risk: 'high'
  },
  {
    id: 'A.5.24', name: 'Planejamento e preparação para gerenciamento de incidentes de segurança da informação',
    description: 'A organização deve planejar e se preparar para o gerenciamento de incidentes de segurança da informação definindo, estabelecendo e comunicando processos, funções e responsabilidades para o gerenciamento de incidentes.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Elabore Plano de Resposta a Incidentes (IRP). Defina equipe CSIRT. Realize simulações (tabletop exercises). Documente procedimentos de contenção, erradicação e recuperação.',
    iso27002: 'A preparação para incidentes reduz o tempo de resposta e o impacto de violações de segurança.',
    risk: 'high'
  },
  {
    id: 'A.5.25', name: 'Avaliação e decisão sobre eventos de segurança da informação',
    description: 'A organização deve avaliar os eventos de segurança da informação e decidir se eles devem ser categorizados como incidentes de segurança da informação.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Defina critérios de triagem de eventos. Implante SIEM para correlação. Treine equipe de SOC para classificação. Documente matriz de escalação.',
    iso27002: 'A avaliação eficiente de eventos permite resposta rápida e adequada a incidentes reais.',
    risk: 'medium'
  },
  {
    id: 'A.5.26', name: 'Resposta a incidentes de segurança da informação',
    description: 'Os incidentes de segurança da informação devem ser respondidos de acordo com os procedimentos documentados.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Execute IRP documentado. Contenha, erradique e recupere sistematicamente. Preserve evidências forenses. Notifique partes afetadas conforme LGPD/GDPR.',
    iso27002: 'A resposta estruturada minimiza o impacto e previne recorrência de incidentes.',
    risk: 'high'
  },
  {
    id: 'A.5.27', name: 'Aprendendo com os incidentes de segurança da informação',
    description: 'O conhecimento adquirido com incidentes de segurança da informação deve ser usado para fortalecer e melhorar os controles de segurança da informação.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Conduza post-mortems blameless após incidentes. Documente lições aprendidas. Atualize controles e procedimentos. Compartilhe com equipes relevantes.',
    iso27002: 'O aprendizado contínuo com incidentes fortalece a postura de segurança ao longo do tempo.',
    risk: 'medium'
  },
  {
    id: 'A.5.28', name: 'Coleta de evidências',
    description: 'A organização deve estabelecer e implementar procedimentos para identificação, coleta, aquisição e preservação de evidências relacionadas a eventos de segurança da informação.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Defina procedimentos forenses. Preserve logs íntegros. Use cadeia de custódia. Consulte jurídico sobre requisitos de evidência admissível.',
    iso27002: 'A coleta adequada de evidências é essencial para investigações e ações legais.',
    risk: 'medium'
  },
  {
    id: 'A.5.29', name: 'Segurança da informação durante interrupção',
    description: 'A organização deve planejar como manter a segurança da informação em um nível adequado durante a interrupção.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Integre segurança no BCP/DRP. Garanta que controles de acesso funcionem durante failover. Teste recuperação de backups regularmente.',
    iso27002: 'Manter segurança durante interrupções previne que situações de crise criem vulnerabilidades adicionais.',
    risk: 'high'
  },
  {
    id: 'A.5.30', name: 'Prontidão de TIC para continuidade de negócios',
    description: 'A prontidão de TIC deve ser planejada, implementada, mantida e testada com base nos objetivos de continuidade de negócios e nos requisitos de continuidade de TIC.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Defina RPO/RTO. Implante redundância. Teste failover regularmente. Documente procedimentos de recuperação. Considere DR em múltiplas regiões.',
    iso27002: 'A continuidade de TIC garante disponibilidade dos sistemas críticos mesmo durante falhas.',
    risk: 'high'
  },
  {
    id: 'A.5.31', name: 'Requisitos legais, estatutários, regulamentares e contratuais',
    description: 'Os requisitos legais, estatutários, regulamentares e contratuais relevantes para a segurança da informação e a abordagem da organização para atender a esses requisitos devem ser identificados, documentados e mantidos atualizados.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Mapeie requisitos legais aplicáveis (LGPD, GDPR, PCI-DSS, HIPAA). Mantenha registro de conformidade. Engaje jurídico e DPO. Realize auditorias de conformidade.',
    iso27002: 'O cumprimento de requisitos legais evita sanções e protege a reputação da organização.',
    risk: 'high'
  },
  {
    id: 'A.5.32', name: 'Direitos de propriedade intelectual',
    description: 'A organização deve implementar procedimentos apropriados para proteger os direitos de propriedade intelectual.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Documente licenças de software. Evite uso não autorizado de software proprietário. Registre propriedade intelectual desenvolvida internamente.',
    iso27002: 'A proteção de PI preserva ativos intangíveis e previne litígios.',
    risk: 'low'
  },
  {
    id: 'A.5.33', name: 'Proteção de registros',
    description: 'Os registros devem ser protegidos contra perda, destruição, falsificação, acesso não autorizado e liberação não autorizada.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante política de retenção de registros. Use armazenamento imutável para logs. Controle acesso a registros. Faça backup regular e verifique integridade.',
    iso27002: 'A proteção de registros garante evidências para auditoria, conformidade e investigações.',
    risk: 'medium'
  },
  {
    id: 'A.5.34', name: 'Privacidade e proteção de PII',
    description: 'A organização deve identificar e atender aos requisitos relativos à preservação da privacidade e proteção de PII de acordo com as leis e regulamentos aplicáveis quando relevante.',
    theme: 'org', autoAssess: true,
    checkKeywords: ['Credential', 'PII', 'Sensitive'],
    evaluator(results) {
      const cred = results.find(r => /Credential|PII|Sensitive/i.test(r.check));
      if (cred?.status === 'FAIL') return { status: 'non-compliant', evidence: 'PII ou dados sensíveis expostos: ' + cred.check };
      if (cred?.status === 'WARN') return { status: 'partial', evidence: 'Possível exposição de dados sensíveis: ' + cred.check };
      return { status: 'partial', evidence: 'Verificação técnica básica de PII realizada (programa de privacidade formal necessário)' };
    },
    remediation: 'Mapeie dados pessoais. Implante DPIA para novos projetos. Use pseudonimização/anonimização. Nomeie DPO. Documente bases legais de tratamento (LGPD).',
    iso27002: 'A proteção de PII é obrigação legal (LGPD/GDPR) e fundamental para a confiança dos usuários.',
    risk: 'critical'
  },
  {
    id: 'A.5.35', name: 'Revisão independente da segurança da informação',
    description: 'A abordagem da organização para gerenciar a segurança da informação e sua implementação, incluindo pessoas, processos e tecnologias, deve ser revisada de forma independente em intervalos planejados ou quando ocorrerem mudanças significativas.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Contrate auditoria externa anual. Realize pentests periódicos. Conduza revisões internas de SGSI. Implante programa de Bug Bounty.',
    iso27002: 'Revisões independentes identificam lacunas que auditorias internas podem não detectar.',
    risk: 'medium'
  },
  {
    id: 'A.5.36', name: 'Conformidade com políticas, regras e normas de segurança da informação',
    description: 'A conformidade com a política de segurança da informação da organização, as regras específicas de tópico, normas e qualquer outro requisito de segurança deve ser revisada regularmente.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Realize auditorias internas regulares. Monitore KPIs de conformidade. Use ferramentas de compliance automation. Corrija desvios com planos de ação.',
    iso27002: 'A revisão regular de conformidade garante efetividade contínua dos controles.',
    risk: 'medium'
  },
  {
    id: 'A.5.37', name: 'Procedimentos documentados de operação',
    description: 'Os procedimentos para as atividades de processamento de informações devem ser documentados e disponibilizados para o pessoal que deles necessitar.',
    theme: 'org', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Documente runbooks para operações críticas. Mantenha documentação atualizada. Use wikis ou ferramentas de gestão do conhecimento. Revise regularmente.',
    iso27002: 'Procedimentos documentados garantem consistência e resiliência operacional.',
    risk: 'low'
  },

  /* ========================================================
   * A.6 — CONTROLES DE PESSOAS (8 controles)
   * ======================================================== */
  {
    id: 'A.6.1', name: 'Triagem',
    description: 'Verificações de histórico de todos os candidatos a emprego devem ser realizadas antes de ingressar na organização e de forma contínua, levando em consideração as leis, regulamentos e ética aplicáveis.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante processo de background check. Verifique referências. Realize verificações conforme funções (acesso privilegiado requer triagem mais rigorosa). Repita periodicamente.',
    iso27002: 'A triagem reduz riscos de ameaças internas ao garantir que colaboradores tenham histórico confiável.',
    risk: 'high'
  },
  {
    id: 'A.6.2', name: 'Termos e condições de emprego',
    description: 'Os acordos contratuais com o pessoal devem declarar as responsabilidades dos funcionários e da organização em relação à segurança da informação.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Inclua cláusulas de segurança em contratos de trabalho: NDA, deveres de confidencialidade, reporte de incidentes, política de uso aceitável.',
    iso27002: 'Acordos formais estabelecem obrigações legais e conscientizam colaboradores sobre responsabilidades.',
    risk: 'medium'
  },
  {
    id: 'A.6.3', name: 'Conscientização, educação e treinamento de segurança da informação',
    description: 'O pessoal da organização e as partes interessadas relevantes devem receber conscientização, educação e treinamento adequados em segurança da informação e atualizações regulares das políticas e procedimentos da organização relevantes para sua função de trabalho.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Realize treinamentos de segurança no onboarding e anualmente. Conduza simulações de phishing. Treine desenvolvedores em OWASP. Meça efetividade do treinamento.',
    iso27002: 'Treinamento aumenta a conscientização e reduz erros humanos que causam incidentes.',
    risk: 'medium'
  },
  {
    id: 'A.6.4', name: 'Processo disciplinar',
    description: 'Um processo disciplinar deve ser formalizado e comunicado para agir em relação ao pessoal e outras partes interessadas relevantes que cometerem uma violação da política de segurança da informação.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Documente processo disciplinar proporcional ao nível de violação. Garanta aplicação consistente. Considere aspectos legais trabalhistas. Comunique previamente.',
    iso27002: 'Processos disciplinares servem como dissuasor e garantem consequências para violações de segurança.',
    risk: 'medium'
  },
  {
    id: 'A.6.5', name: 'Responsabilidades após encerramento ou mudança de emprego',
    description: 'As responsabilidades e deveres de segurança da informação que permanecem válidos após o encerramento ou mudança de emprego devem ser definidos, comunicados ao funcionário ou contratado e aplicados.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Inclua cláusulas pós-emprego (NDA, non-compete). Execute checklist de offboarding imediatamente. Revogue acessos no dia de saída. Recupere equipamentos e credenciais.',
    iso27002: 'Responsabilidades pós-emprego protegem informações confidenciais após saída do colaborador.',
    risk: 'high'
  },
  {
    id: 'A.6.6', name: 'Acordos de confidencialidade ou não divulgação',
    description: 'Acordos de confidencialidade ou não divulgação que reflitam as necessidades da organização de proteção de informações devem ser identificados, documentados, revisados regularmente e assinados pelo pessoal e por outras partes interessadas relevantes.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Elabore NDAs com cobertura adequada ao tipo de informação. Obtenha assinaturas antes do acesso a informações sensíveis. Revise NDAs periodicamente.',
    iso27002: 'NDAs criam obrigação legal de proteção de informações confidenciais.',
    risk: 'medium'
  },
  {
    id: 'A.6.7', name: 'Trabalho remoto',
    description: 'Medidas de segurança devem ser implementadas quando o pessoal trabalha remotamente para proteger as informações acessadas, processadas ou armazenadas fora das instalações da organização.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Exija VPN para acesso remoto. Aplique MDM em dispositivos corporativos. Defina política de BYOD. Use Zero Trust. Treine equipe sobre segurança em home office.',
    iso27002: 'Controles para trabalho remoto protegem dados acessados fora do ambiente controlado do escritório.',
    risk: 'high'
  },
  {
    id: 'A.6.8', name: 'Relatório de eventos de segurança da informação',
    description: 'A organização deve fornecer um mecanismo para que o pessoal relate eventos de segurança da informação observados ou suspeitos por meio dos canais de relatório apropriados de forma oportuna.',
    theme: 'people', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Crie canal anônimo de reporte (whistleblower). Defina procedimentos claros de reporte. Elimine cultura de medo de reporte. Treine equipe sobre o que e como reportar.',
    iso27002: 'Canais de reporte permitem detecção precoce de incidentes e ameaças internas.',
    risk: 'medium'
  },

  /* ========================================================
   * A.7 — CONTROLES FÍSICOS (14 controles)
   * ======================================================== */
  {
    id: 'A.7.1', name: 'Perímetros físicos de segurança',
    description: 'Perímetros de segurança devem ser definidos e usados para proteger áreas que contêm informações e outros ativos associados.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para infraestrutura física: implante controles de perímetro (guardas, cercas, catracas). Documente zonas de segurança.',
    iso27002: 'Perímetros físicos protegem infraestrutura crítica contra acesso não autorizado.',
    risk: 'low'
  },
  {
    id: 'A.7.2', name: 'Entrada física',
    description: 'Áreas seguras devem ser protegidas por controles de entrada adequados e pontos de acesso.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para data centers: use catracas biométricas, registro de visitantes, escolta de terceiros.',
    iso27002: 'Controles de entrada física previnem acesso não autorizado a áreas sensíveis.',
    risk: 'low'
  },
  {
    id: 'A.7.3', name: 'Segurança de escritórios, salas e instalações',
    description: 'A segurança física deve ser projetada e aplicada para escritórios, salas e instalações.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para instalações físicas: implante controles de acesso por área, câmeras CCTV, alarmes.',
    iso27002: 'A segurança de instalações protege equipamentos e informações contra ameaças físicas.',
    risk: 'low'
  },
  {
    id: 'A.7.4', name: 'Monitoramento de segurança física',
    description: 'As instalações devem ser monitoradas continuamente contra acesso físico não autorizado.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para instalações: CCTV 24/7, alarmes, monitoramento centralizado.',
    iso27002: 'O monitoramento físico detecta e dissuade intrusões físicas.',
    risk: 'low'
  },
  {
    id: 'A.7.5', name: 'Proteção contra ameaças físicas e ambientais',
    description: 'Proteção contra ameaças físicas e ambientais, como desastres naturais e outros desastres físicos intencionais ou não intencionais para infraestrutura, deve ser projetada e implementada.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para infraestrutura: proteção contra incêndio, inundação, terremoto. Use data centers com certificação Tier III/IV.',
    iso27002: 'Proteção ambiental garante disponibilidade de infraestrutura crítica.',
    risk: 'low'
  },
  {
    id: 'A.7.6', name: 'Trabalhando em áreas seguras',
    description: 'Medidas de segurança para trabalhar em áreas seguras devem ser projetadas e implementadas.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para áreas seguras físicas: defina regras de comportamento, proíba dispositivos pessoais, realize auditorias periódicas.',
    iso27002: 'Controles em áreas seguras evitam vazamentos e incidentes causados por pessoas em áreas restritas.',
    risk: 'low'
  },
  {
    id: 'A.7.7', name: 'Mesa limpa e tela limpa',
    description: 'Regras de mesa limpa para papéis e mídia de armazenamento removível e regras de tela limpa para instalações de processamento de informações devem ser definidas e aplicadas de forma apropriada.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'Defina política de mesa limpa. Bloqueio automático de telas. Destruição segura de documentos físicos. Não deixe informações sensíveis visíveis.',
    iso27002: 'Mesa e tela limpas previnem que informações sejam vistas por pessoas não autorizadas.',
    risk: 'low'
  },
  {
    id: 'A.7.8', name: 'Localização e proteção de equipamentos',
    description: 'Equipamentos devem ser localizados de forma segura e protegidos.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web hospedada em nuvem. Para infraestrutura própria: racks trancados, proteção contra vandalismo, localização em área controlada.',
    iso27002: 'A proteção de equipamentos previne danos físicos e acesso não autorizado.',
    risk: 'low'
  },
  {
    id: 'A.7.9', name: 'Segurança de ativos fora das instalações',
    description: 'Ativos fora das instalações devem ser protegidos.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'Criptografe dispositivos móveis. Use MDM. Não deixe laptops em carros. Reporte imediatamente perda ou roubo.',
    iso27002: 'Ativos fora das instalações são mais vulneráveis — controles compensatórios são essenciais.',
    risk: 'medium'
  },
  {
    id: 'A.7.10', name: 'Mídia de armazenamento',
    description: 'Mídias de armazenamento devem ser gerenciadas ao longo de seu ciclo de vida de aquisição, uso, transporte e descarte de acordo com o esquema de classificação e os requisitos de manuseio da organização.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'Implante política de gestão de mídia. Destruição segura (shredding, degauss). Criptografe mídias. Controle inventário de mídias removíveis.',
    iso27002: 'A gestão de mídia previne que dados sejam recuperados de mídias descartadas.',
    risk: 'medium'
  },
  {
    id: 'A.7.11', name: 'Utilitários de suporte',
    description: 'As instalações de processamento de informações devem ser protegidas contra falhas de energia e outras interrupções causadas por falhas em utilitários de suporte.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação em nuvem (gerenciado pelo provedor). Para infraestrutura própria: UPS, gerador, múltiplos links de internet.',
    iso27002: 'Utilitários de suporte garantem continuidade de operação em caso de falhas de infraestrutura.',
    risk: 'low'
  },
  {
    id: 'A.7.12', name: 'Segurança do cabeamento',
    description: 'Cabos que transportam energia ou dados devem ser protegidos contra interceptação, interferência ou dano.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação web. Para infraestrutura física: use cabeamento estruturado protegido, evite cabos expostos em áreas de acesso público.',
    iso27002: 'A segurança do cabeamento previne interceptação e dano à infraestrutura de comunicação.',
    risk: 'low'
  },
  {
    id: 'A.7.13', name: 'Manutenção de equipamentos',
    description: 'Os equipamentos devem ser mantidos corretamente para garantir disponibilidade, integridade e confidencialidade das informações.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'N/A para aplicação em nuvem. Para infraestrutura própria: realize manutenção preventiva, use apenas técnicos autorizados, apague dados antes de envio para manutenção.',
    iso27002: 'A manutenção adequada previne falhas e riscos de exposição durante serviços técnicos.',
    risk: 'low'
  },
  {
    id: 'A.7.14', name: 'Descarte seguro ou reutilização de equipamentos',
    description: 'Os itens de equipamento que contêm mídia de armazenamento devem ser verificados para garantir que quaisquer dados confidenciais e software licenciado tenham sido removidos ou sobrescritos com segurança antes do descarte ou reutilização.',
    theme: 'physical', autoAssess: false,
    checkKeywords: [], evaluator: null,
    remediation: 'Apague discos com padrão DoD. Destrua fisicamente mídias inutilizáveis. Documente descarte. Use fornecedor certificado para ITAD.',
    iso27002: 'O descarte seguro evita recuperação de dados de equipamentos aposentados.',
    risk: 'medium'
  },

  /* ========================================================
   * A.8 — CONTROLES TECNOLÓGICOS (34 controles)
   * ======================================================== */
  {
    id: 'A.8.1', name: 'Dispositivos endpoint do usuário',
    description: 'Informações armazenadas em, processadas por ou acessíveis por meio de dispositivos endpoint do usuário devem ser protegidas.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante MDM/EDR. Criptografe discos. Mantenha antivírus atualizado. Aplique hardening de SO. Gerencie patches. Revogue acesso de dispositivos perdidos/roubados.',
    iso27002: 'Dispositivos de usuário são frequentemente o ponto inicial de comprometimento — controles robustos são essenciais.',
    risk: 'high'
  },
  {
    id: 'A.8.2', name: 'Direitos de acesso privilegiado',
    description: 'A alocação e uso de direitos de acesso privilegiado devem ser restritos e gerenciados.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Service Key', 'Auth', 'RLS'],
    evaluator(results) {
      const sk = results.find(r => /Service Key/i.test(r.check));
      if (sk?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Service key exposta — acesso privilegiado irrestrito detectado' };
      const rls = results.find(r => /Deep RLS/i.test(r.check) && r.status === 'FAIL');
      if (rls) return { status: 'partial', evidence: 'Possível escalação de privilégio via misconfigurações de RLS' };
      if (sk?.status === 'WARN') return { status: 'partial', evidence: 'Alertas sobre uso de chaves privilegiadas' };
      return { status: 'partial', evidence: 'Verificação básica realizada (PAM e gestão formal de privilégios necessários)' };
    },
    remediation: 'Nunca use service key no frontend. Restrinja acesso privilegiado com just-in-time (JIT). Use PAM. Audite uso de contas privilegiadas. Rotacione credenciais.',
    iso27002: 'Privilégios excessivos são a principal causa de violações graves — controles rigorosos são essenciais.',
    risk: 'critical'
  },
  {
    id: 'A.8.3', name: 'Restrição de acesso à informação',
    description: 'O acesso a informações e outros ativos associados deve ser restrito de acordo com a política de controle de acesso específica do tópico estabelecida.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['RLS', 'REST API', 'GraphQL', 'Storage', 'Hidden Routes'],
    evaluator(results) {
      const checks = [
        results.find(r => /RLS Policy/i.test(r.check)),
        results.find(r => /REST|RPC/i.test(r.check)),
        results.find(r => /GraphQL/i.test(r.check)),
        results.find(r => /Storage/i.test(r.check)),
      ].filter(Boolean);
      const fails = checks.filter(r => r.status === 'FAIL');
      const warns = checks.filter(r => r.status === 'WARN');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Restrição de acesso falha em múltiplos pontos: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Restrição de acesso parcialmente implementada. Falha: ' + fails[0].check };
      if (warns.length > 0) return { status: 'partial', evidence: 'Alertas em controles de acesso: ' + warns.map(r => r.check).join(', ') };
      return { status: 'compliant', evidence: 'Restrições de acesso verificadas: RLS, API, GraphQL, Storage' };
    },
    remediation: 'Ative RLS em todas as tabelas. Desative endpoints não utilizados. Configure Storage policies. Revise permissões de GraphQL. Oculte rotas internas.',
    iso27002: 'A restrição de acesso garante que dados sejam acessíveis apenas a usuários autorizados.',
    risk: 'critical'
  },
  {
    id: 'A.8.4', name: 'Acesso ao código-fonte',
    description: 'O acesso de leitura e gravação ao código-fonte, ferramentas de desenvolvimento e bibliotecas de software deve ser gerenciado de forma adequada.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Source Code', 'Hidden Routes'],
    evaluator(results) {
      const src = results.find(r => /Source Code/i.test(r.check));
      if (src?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Código-fonte exposto publicamente: ' + src.check };
      if (src?.status === 'WARN') return { status: 'partial', evidence: 'Possível exposição de código-fonte' };
      return { status: 'partial', evidence: 'Verificação básica de exposição de código realizada (controles de repositório manuais necessários)' };
    },
    remediation: 'Não publique source maps em produção. Use repositórios privados. Configure acesso mínimo ao código. Revise secrets em histórico do git. Nunca comite credenciais.',
    iso27002: 'O controle de acesso ao código-fonte previne engenharia reversa e roubo de propriedade intelectual.',
    risk: 'high'
  },
  {
    id: 'A.8.5', name: 'Autenticação segura',
    description: 'Tecnologias e procedimentos de autenticação segura devem ser implementados com base nas restrições de acesso a informações e à política de controle de acesso específica do tópico.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Auth', 'JWT', 'Open Signup'],
    evaluator(results) {
      const jwt = results.find(r => /JWT/i.test(r.check));
      const auth = results.find(r => /Auth Endpoints|Auth Settings/i.test(r.check));
      const signup = results.find(r => /Open Signup/i.test(r.check));
      const fails = [jwt, auth, signup].filter(r => r?.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Autenticação insegura em múltiplos pontos: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Problema de autenticação: ' + fails[0].check };
      const warns = [jwt, auth, signup].filter(r => r?.status === 'WARN');
      if (warns.length > 0) return { status: 'partial', evidence: 'Alertas de autenticação: ' + warns.map(r => r.check).join(', ') };
      return { status: 'compliant', evidence: 'Autenticação básica (JWT, Auth endpoints, signup) verificada' };
    },
    remediation: 'Configure JWTs com expiração curta. Ative MFA. Restrinja signup a domínios confiáveis. Use PKCE em OAuth. Configure sessões seguras.',
    iso27002: 'Autenticação forte é a primeira linha de defesa contra acesso não autorizado.',
    risk: 'critical'
  },
  {
    id: 'A.8.6', name: 'Gerenciamento de capacidade',
    description: 'O uso de recursos deve ser monitorado e ajustado, e as projeções de requisitos de capacidade futuros devem ser feitas para garantir o desempenho requerido do sistema.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Hardening', 'Rate Limit'],
    evaluator(results) {
      const hardening = results.find(r => /Hardening|Rate Limit/i.test(r.check));
      if (hardening?.status === 'FAIL') return { status: 'partial', evidence: 'Controles de rate limiting ausentes — vulnerável a DoS' };
      if (hardening?.status === 'WARN') return { status: 'partial', evidence: 'Rate limiting com configuração inadequada' };
      return { status: 'partial', evidence: 'Verificação básica realizada (planejamento de capacidade manual necessário)' };
    },
    remediation: 'Implante rate limiting em APIs. Configure alertas de uso. Monitore métricas de performance. Defina SLAs. Use auto-scaling. Realize testes de carga.',
    iso27002: 'O gerenciamento de capacidade garante disponibilidade e previne indisponibilidades por sobrecarga.',
    risk: 'medium'
  },
  {
    id: 'A.8.7', name: 'Proteção contra malware',
    description: 'A proteção contra malware deve ser implementada e suportada por conscientização adequada do usuário.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Vulnerability', 'Source Code'],
    evaluator(results) {
      const vuln = results.find(r => /Vulnerability/i.test(r.check));
      if (vuln?.status === 'FAIL') return { status: 'partial', evidence: 'Vulnerabilidades detectadas que podem indicar comprometimento: ' + vuln.check };
      return { status: 'partial', evidence: 'Verificação básica realizada (antimalware em servidores e endpoints necessário)' };
    },
    remediation: 'Implante WAF. Use CSP para prevenir XSS. Escaneie dependências por malware. Monitore integridade de arquivos. Use antivírus em servidores.',
    iso27002: 'Proteção contra malware previne comprometimento e espionagem de sistemas.',
    risk: 'high'
  },
  {
    id: 'A.8.8', name: 'Gerenciamento de vulnerabilidades técnicas',
    description: 'As informações sobre vulnerabilidades técnicas dos sistemas de informação em uso devem ser obtidas, a exposição da organização a tais vulnerabilidades deve ser avaliada e as medidas apropriadas devem ser tomadas.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Vulnerability', 'Stack Detection'],
    evaluator(results) {
      const vuln = results.find(r => /Vulnerability/i.test(r.check));
      if (vuln?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Vulnerabilidades técnicas conhecidas identificadas: ' + (vuln.message || '') };
      if (vuln?.status === 'WARN') return { status: 'partial', evidence: 'Possíveis vulnerabilidades identificadas — análise manual necessária' };
      return { status: 'partial', evidence: 'Scan de vulnerabilidades realizado (programa formal de patch management necessário)' };
    },
    remediation: 'Implante programa de vulnerability management (VM). Use ferramentas de DAST/SAST. Monitore CVEs. Defina SLA de patch (crítico: 24h, alto: 7 dias, médio: 30 dias).',
    iso27002: 'O gerenciamento de vulnerabilidades é fundamental para manter sistemas seguros ao longo do tempo.',
    risk: 'critical'
  },
  {
    id: 'A.8.9', name: 'Gerenciamento de configuração',
    description: 'As configurações, incluindo configurações de segurança, de hardware, software, serviços e redes devem ser estabelecidas, documentadas, implementadas, monitoradas e revisadas.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Hardening', 'CORS', 'REST'],
    evaluator(results) {
      const hardening = results.find(r => /Hardening/i.test(r.check));
      const cors = results.find(r => /CORS/i.test(r.check));
      const fails = [hardening, cors].filter(r => r?.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Configurações de segurança inadequadas: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Configuração inadequada em: ' + fails[0].check };
      return { status: 'partial', evidence: 'Configurações básicas verificadas (baseline e IaC necessários)' };
    },
    remediation: 'Defina baselines de configuração (CIS Benchmarks). Use IaC (Terraform). Automatize verificação de conformidade de configuração. Documente todas as mudanças.',
    iso27002: 'Configurações seguras reduzem a superfície de ataque e previnem erros de configuração.',
    risk: 'high'
  },
  {
    id: 'A.8.10', name: 'Exclusão de informações',
    description: 'As informações armazenadas em sistemas de informação, dispositivos ou em qualquer outra mídia de armazenamento devem ser excluídas quando não mais necessárias.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Storage'],
    evaluator(results) {
      const storage = results.find(r => /Storage/i.test(r.check));
      if (storage?.status === 'FAIL') return { status: 'partial', evidence: 'Políticas de storage inadequadas — possível retenção indevida de dados' };
      return { status: 'partial', evidence: 'Storage verificado (políticas de retenção e exclusão formal necessárias)' };
    },
    remediation: 'Defina política de retenção de dados. Implante exclusão automática após período definido. Garanta exclusão segura em Supabase Storage. Documente procedimentos de exclusão.',
    iso27002: 'A exclusão adequada de dados garante conformidade com LGPD e reduz risco de exposição.',
    risk: 'medium'
  },
  {
    id: 'A.8.11', name: 'Mascaramento de dados',
    description: 'O mascaramento de dados deve ser usado de acordo com a política de controle de acesso específica do tópico da organização e outros requisitos específicos do tópico relacionados, e requisitos de negócios, levando em consideração a legislação aplicável.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Credential', 'PII', 'Sensitive'],
    evaluator(results) {
      const cred = results.find(r => /Credential|PII|Sensitive/i.test(r.check));
      if (cred?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Dados sensíveis expostos sem mascaramento: ' + cred.check };
      if (cred?.status === 'WARN') return { status: 'partial', evidence: 'Possível exposição de dados sensíveis' };
      return { status: 'partial', evidence: 'Verificação básica realizada (mascaramento em logs, APIs e UI necessário)' };
    },
    remediation: 'Mascare CPF, cartão de crédito e dados sensíveis em logs. Use tokenização para dados de pagamento. Pseudonimize dados em ambientes de teste. Configure mascaramento no Supabase.',
    iso27002: 'O mascaramento de dados reduz o impacto de exposições acidentais ou maliciosas.',
    risk: 'high'
  },
  {
    id: 'A.8.12', name: 'Prevenção de vazamento de dados',
    description: 'Medidas de prevenção de vazamento de dados devem ser aplicadas a sistemas, redes e qualquer outro dispositivo que processe, armazene ou transmita informações sensíveis.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Bundle Key', 'Credential', '.env', 'Key Exposure'],
    evaluator(results) {
      const bundle = results.find(r => /Bundle Key/i.test(r.check));
      const cred = results.find(r => /Credential|PII/i.test(r.check));
      const env = results.find(r => /\.env|Key Exposure/i.test(r.check));
      const fails = [bundle, cred, env].filter(r => r?.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Múltiplos vazamentos de dados detectados: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Vazamento detectado em: ' + fails[0].check };
      const warns = [bundle, cred, env].filter(r => r?.status === 'WARN');
      if (warns.length > 0) return { status: 'partial', evidence: 'Possíveis vazamentos: ' + warns.map(r => r.check).join(', ') };
      return { status: 'compliant', evidence: 'Verificações de DLP realizadas — bundle keys, credenciais e .env verificados' };
    },
    remediation: 'Use variáveis de ambiente no servidor (nunca no frontend). Escaneie código por secrets. Configure .gitignore. Use git-secrets ou similar. Revogue imediatamente credenciais expostas.',
    iso27002: 'DLP é essencial para detectar e prevenir exfiltração de dados sensíveis.',
    risk: 'critical'
  },
  {
    id: 'A.8.13', name: 'Backup das informações',
    description: 'Cópias de backup das informações, software e sistemas devem ser mantidas e testadas regularmente de acordo com a política de backup específica do tópico acordada.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Configure backups automáticos do banco de dados Supabase. Teste restauração regularmente. Armazene backups em região diferente. Defina RPO e RTO. Use regra 3-2-1.',
    iso27002: 'Backups regulares e testados são fundamentais para recuperação de incidentes e continuidade.',
    risk: 'high'
  },
  {
    id: 'A.8.14', name: 'Redundância das instalações de processamento de informações',
    description: 'As instalações de processamento de informações devem ser implementadas com redundância suficiente para atender aos requisitos de disponibilidade.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Use múltiplas zonas de disponibilidade. Configure failover automático. Monitore disponibilidade com alertas. Supabase oferece HA — configure adequadamente.',
    iso27002: 'Redundância garante disponibilidade de serviços críticos mesmo com falhas de componentes.',
    risk: 'high'
  },
  {
    id: 'A.8.15', name: 'Log de atividades',
    description: 'Logs que registram atividades, exceções, falhas e outros eventos relevantes devem ser produzidos, armazenados, protegidos e analisados.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Error Detector'],
    evaluator(results) {
      const err = results.find(r => /Error|Logging/i.test(r.check));
      if (err?.status === 'FAIL') return { status: 'partial', evidence: 'Erros sendo expostos — logs podem estar inadequados: ' + err.check };
      return { status: 'partial', evidence: 'Verificação básica de erros realizada (sistema formal de logging necessário)' };
    },
    remediation: 'Configure logging centralizado (ELK, Splunk). Logue acessos, erros, autenticações e mudanças críticas. Proteja logs contra adulteração. Defina período de retenção. Use alertas.',
    iso27002: 'Logs são essenciais para detecção de incidentes, investigações forenses e conformidade.',
    risk: 'high'
  },
  {
    id: 'A.8.16', name: 'Atividades de monitoramento',
    description: 'Redes, sistemas e aplicações devem ser monitorados por comportamento anômalo e ações apropriadas tomadas para avaliar potenciais incidentes de segurança da informação.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Error Detector', 'Vulnerability'],
    evaluator(results) {
      const err = results.find(r => /Error/i.test(r.check));
      if (err?.status === 'FAIL') return { status: 'partial', evidence: 'Monitoramento inadequado — erros críticos não detectados ou expostos' };
      return { status: 'partial', evidence: 'Verificação básica realizada (SIEM e monitoramento contínuo necessários)' };
    },
    remediation: 'Implante SIEM. Configure alertas de anomalia. Monitore logs do Supabase em tempo real. Use IDS/IPS. Defina runbooks de resposta a alertas.',
    iso27002: 'O monitoramento contínuo permite detecção precoce de ameaças e atividades suspeitas.',
    risk: 'high'
  },
  {
    id: 'A.8.17', name: 'Sincronização de relógio',
    description: 'Os relógios dos sistemas de processamento de informações usados pela organização devem ser sincronizados com fontes de tempo aprovadas.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Configure NTP em todos os servidores. Use fontes de tempo confiáveis (pool.ntp.org). Verifique sincronização regularmente. Logs com timestamps precisos facilitam investigações.',
    iso27002: 'Sincronização de tempo garante correlação correta de eventos em investigações e conformidade.',
    risk: 'low'
  },
  {
    id: 'A.8.18', name: 'Uso de programas utilitários privilegiados',
    description: 'O uso de programas utilitários que podem ser capazes de sobrepor os controles do sistema e da aplicação deve ser restrito e rigorosamente controlado.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Service Key', 'Hidden Routes'],
    evaluator(results) {
      const sk = results.find(r => /Service Key/i.test(r.check));
      const routes = results.find(r => /Hidden Routes|Route Discovery/i.test(r.check));
      if (sk?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Programas com acesso privilegiado sem controle (service key exposta)' };
      if (routes?.status === 'FAIL') return { status: 'partial', evidence: 'Rotas administrativas potencialmente expostas' };
      return { status: 'partial', evidence: 'Verificação básica realizada (controle formal de utilitários privilegiados necessário)' };
    },
    remediation: 'Restrinja uso de service key. Monitore uso de funções administrativas. Revogue permissões não utilizadas. Use princípio de mínimo privilégio.',
    iso27002: 'O controle de utilitários privilegiados previne uso indevido de capacidades que bypassam controles normais.',
    risk: 'high'
  },
  {
    id: 'A.8.19', name: 'Instalação de software em sistemas operacionais',
    description: 'Procedimentos e medidas devem ser implementados para gerenciar de forma segura a instalação de software em sistemas operacionais.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Use apenas software de fontes confiáveis. Assine digitalmente pacotes. Gerencie dependências com lock files. Audite software instalado regularmente.',
    iso27002: 'O controle de instalação de software previne introdução de malware e software não autorizado.',
    risk: 'medium'
  },
  {
    id: 'A.8.20', name: 'Segurança de redes',
    description: 'Redes e dispositivos de rede devem ser protegidos, gerenciados e controlados para proteger as informações nos sistemas e aplicações.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['CORS', 'DNS', 'Hardening'],
    evaluator(results) {
      const cors = results.find(r => /CORS/i.test(r.check));
      const dns = results.find(r => /DNS/i.test(r.check));
      const hard = results.find(r => /Hardening/i.test(r.check));
      const fails = [cors, dns, hard].filter(r => r?.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Múltiplos problemas de segurança de rede: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Problema de rede: ' + fails[0].check };
      return { status: 'partial', evidence: 'Verificação básica de rede realizada (segmentação e firewall manuais necessários)' };
    },
    remediation: 'Configure CORS restritivo. Use DNSSEC. Implante WAF. Segmente redes. Use HTTPS everywhere. Configure headers de segurança. Realize testes de penetração.',
    iso27002: 'A segurança de rede forma o perímetro de defesa da aplicação.',
    risk: 'high'
  },
  {
    id: 'A.8.21', name: 'Segurança dos serviços de rede',
    description: 'Mecanismos de segurança, níveis de serviço e requisitos de serviço de todos os serviços de rede devem ser identificados, implementados e monitorados.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['CORS', 'DNS', 'REST'],
    evaluator(results) {
      const cors = results.find(r => /CORS/i.test(r.check));
      const dns = results.find(r => /DNS/i.test(r.check));
      if (cors?.status === 'FAIL') return { status: 'partial', evidence: 'Serviços de rede com configuração insegura (CORS)' };
      if (dns?.status === 'FAIL') return { status: 'partial', evidence: 'Serviços DNS com problemas de segurança' };
      return { status: 'partial', evidence: 'Verificação básica realizada (SLAs e monitoramento de serviços de rede necessários)' };
    },
    remediation: 'Defina SLAs para serviços de rede. Monitore disponibilidade. Configure alertas de degradação. Use CDN para performance e disponibilidade. Implante DNSSEC.',
    iso27002: 'A segurança dos serviços de rede garante que a infraestrutura de comunicação seja confiável e segura.',
    risk: 'medium'
  },
  {
    id: 'A.8.22', name: 'Segregação de redes',
    description: 'Grupos de serviços de informação, usuários e sistemas de informação devem ser segregados em redes.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Segmente redes (produção, desenvolvimento, DMZ). Use VLANs. Implante microsegmentação. Controle tráfego entre segmentos com firewall.',
    iso27002: 'A segregação de redes limita o movimento lateral de atacantes e reduz o raio de explosão de incidentes.',
    risk: 'high'
  },
  {
    id: 'A.8.23', name: 'Filtragem da web',
    description: 'O acesso a sites externos deve ser gerenciado para reduzir a exposição a conteúdo malicioso.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante proxy web com filtragem de categorias. Bloqueie sites maliciosos conhecidos. Configure DNS sinkholes. Use Secure Web Gateway (SWG).',
    iso27002: 'A filtragem web previne acesso a conteúdo malicioso e reduz vetores de ataque.',
    risk: 'medium'
  },
  {
    id: 'A.8.24', name: 'Uso de criptografia',
    description: 'Regras para o uso efetivo de criptografia, incluindo gerenciamento de chaves criptográficas, devem ser definidas e implementadas.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['JWT', 'CORS', 'Hardening'],
    evaluator(results) {
      const jwt = results.find(r => /JWT/i.test(r.check));
      const hard = results.find(r => /Hardening/i.test(r.check));
      if (jwt?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Criptografia de tokens (JWT) inadequada' };
      if (hard?.status === 'FAIL') return { status: 'partial', evidence: 'Configurações de criptografia com problemas: ' + hard.check };
      if (jwt?.status === 'WARN') return { status: 'partial', evidence: 'Alertas na configuração criptográfica de JWTs' };
      return { status: 'partial', evidence: 'Verificação básica de criptografia realizada (política formal e gestão de chaves necessárias)' };
    },
    remediation: 'Use TLS 1.3. Configure JWT com algoritmos fortes (RS256). Implante KMS para gestão de chaves. Rotacione chaves regularmente. Audite configurações de criptografia.',
    iso27002: 'Criptografia forte protege dados em trânsito e em repouso contra interceptação.',
    risk: 'high'
  },
  {
    id: 'A.8.25', name: 'Ciclo de vida de desenvolvimento seguro',
    description: 'Regras para o desenvolvimento seguro de software e sistemas devem ser estabelecidas e aplicadas.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Source Code', 'Edge'],
    evaluator(results) {
      const src = results.find(r => /Source Code/i.test(r.check));
      const edge = results.find(r => /Edge/i.test(r.check));
      if (src?.status === 'FAIL') return { status: 'partial', evidence: 'Problemas de segurança no código-fonte detectados' };
      if (edge?.status === 'FAIL') return { status: 'partial', evidence: 'Edge functions com configuração inadequada' };
      return { status: 'partial', evidence: 'Verificação básica de código realizada (SDL formal necessário)' };
    },
    remediation: 'Implante SAST/DAST no CI/CD. Use revisão de código com foco em segurança. Treine desenvolvedores em OWASP. Siga OWASP SAMM. Realize threat modeling.',
    iso27002: 'SDL integrado garante que segurança seja considerada desde o design até a operação.',
    risk: 'high'
  },
  {
    id: 'A.8.26', name: 'Requisitos de segurança de aplicações',
    description: 'Os requisitos de segurança da informação devem ser identificados, especificados e aprovados ao desenvolver ou adquirir aplicações.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['GraphQL', 'Edge', 'REST'],
    evaluator(results) {
      const gql = results.find(r => /GraphQL/i.test(r.check));
      const edge = results.find(r => /Edge/i.test(r.check));
      const rest = results.find(r => /REST|RPC/i.test(r.check));
      const fails = [gql, edge, rest].filter(r => r?.status === 'FAIL');
      if (fails.length >= 2) return { status: 'non-compliant', evidence: 'Requisitos de segurança de aplicação não atendidos: ' + fails.map(r => r.check).join(', ') };
      if (fails.length === 1) return { status: 'partial', evidence: 'Requisito não atendido: ' + fails[0].check };
      return { status: 'partial', evidence: 'Verificação básica realizada (requisitos formais de segurança no backlog necessários)' };
    },
    remediation: 'Defina requisitos de segurança no backlog. Use histórias de usuário de segurança. Realize threat modeling. Valide requisitos em user acceptance testing (UAT).',
    iso27002: 'Requisitos de segurança definidos upfront evitam vulnerabilidades custosas de corrigir depois.',
    risk: 'high'
  },
  {
    id: 'A.8.27', name: 'Princípios de engenharia de sistemas seguros',
    description: 'Princípios para a engenharia de sistemas seguros devem ser estabelecidos, documentados, mantidos e aplicados a quaisquer atividades de desenvolvimento de sistemas de informação.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Stack Detection'],
    evaluator(results) {
      const stack = results.find(r => /Stack/i.test(r.check));
      // Stack Detection é informativo — não penaliza mas fornece evidência
      const techCount = stack?.details?.technologies?.length || 0;
      return { status: 'partial', evidence: techCount > 0 ? `Stack identificada (${techCount} tecnologias) — princípios de engenharia segura requerem avaliação manual` : 'Verificação básica realizada (princípios de engenharia segura requerem avaliação manual)' };
    },
    remediation: 'Aplique Security by Design. Use OWASP Security Design Principles (least privilege, defense in depth, fail-safe defaults). Realize threat modeling com STRIDE.',
    iso27002: 'Princípios de engenharia segura garantem que sistemas sejam resistentes a ataques por design.',
    risk: 'high'
  },
  {
    id: 'A.8.28', name: 'Codificação segura',
    description: 'Os princípios de codificação segura devem ser aplicados ao desenvolvimento de software.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Source Code', 'Vulnerability'],
    evaluator(results) {
      const src = results.find(r => /Source Code/i.test(r.check));
      const vuln = results.find(r => /Vulnerability/i.test(r.check));
      if (src?.status === 'FAIL' && vuln?.status === 'FAIL') return { status: 'non-compliant', evidence: 'Problemas de codificação e vulnerabilidades detectadas' };
      if (src?.status === 'FAIL' || vuln?.status === 'FAIL') return { status: 'partial', evidence: 'Problemas de codificação: ' + [src, vuln].filter(r => r?.status === 'FAIL').map(r => r.check).join(', ') };
      return { status: 'partial', evidence: 'Verificação básica realizada (revisão manual de código e SAST necessários)' };
    },
    remediation: 'Treine desenvolvedores em OWASP Top 10. Use linters de segurança. Faça code review com checklist de segurança. Implante SAST automatizado no pipeline.',
    iso27002: 'Codificação segura previne classes inteiras de vulnerabilidades (XSS, SQLi, IDOR, etc.).',
    risk: 'high'
  },
  {
    id: 'A.8.29', name: 'Teste de segurança no desenvolvimento e aceitação',
    description: 'Processos de teste de segurança devem ser definidos e implementados no ciclo de vida de desenvolvimento.',
    theme: 'tech', autoAssess: true,
    checkKeywords: ['Vulnerability', 'Source Code', 'GraphQL'],
    evaluator(results) {
      const vuln = results.find(r => /Vulnerability/i.test(r.check));
      if (vuln?.status === 'FAIL') return { status: 'partial', evidence: 'Vulnerabilidades detectadas — testes de segurança insuficientes ou ausentes' };
      if (vuln?.status === 'WARN') return { status: 'partial', evidence: 'Alertas de segurança — testes adicionais recomendados' };
      return { status: 'partial', evidence: 'Verificação básica realizada (testes de segurança formais no pipeline necessários)' };
    },
    remediation: 'Implante SAST (Semgrep, SonarQube), DAST (ZAP, Burp) e SCA no CI/CD. Realize pentests periódicos. Use IAST em staging. Automatize testes de segurança.',
    iso27002: 'Testes de segurança identificam vulnerabilidades antes que cheguem à produção.',
    risk: 'high'
  },
  {
    id: 'A.8.30', name: 'Desenvolvimento terceirizado',
    description: 'A organização deve direcionar, monitorar e revisar as atividades relacionadas ao desenvolvimento de sistemas terceirizados.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Inclua requisitos de segurança em contratos com desenvolvedores externos. Realize revisão de código. Exija entrega de relatórios de SAST. Retenha direito de auditoria.',
    iso27002: 'Supervisão de desenvolvimento terceirizado garante que fornecedores atendam padrões de segurança.',
    risk: 'high'
  },
  {
    id: 'A.8.31', name: 'Separação dos ambientes de desenvolvimento, teste e produção',
    description: 'Os ambientes de desenvolvimento, teste e produção devem ser separados e protegidos.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Use projetos Supabase separados para dev/staging/prod. Nunca use dados de produção em desenvolvimento sem anonimização. Controle quem pode acessar cada ambiente.',
    iso27002: 'A separação de ambientes previne contaminação de produção por código de desenvolvimento e vazamento de dados.',
    risk: 'high'
  },
  {
    id: 'A.8.32', name: 'Gerenciamento de mudanças',
    description: 'Mudanças em instalações de processamento de informações e sistemas de informação devem estar sujeitas a procedimentos de gerenciamento de mudanças.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Implante processo formal de Change Management. Use aprovações para mudanças em produção. Documente todas as mudanças. Realize testes antes de deploy. Use feature flags.',
    iso27002: 'Gerenciamento de mudanças previne indisponibilidades e vulnerabilidades introduzidas por mudanças não controladas.',
    risk: 'medium'
  },
  {
    id: 'A.8.33', name: 'Informações de teste',
    description: 'As informações de teste devem ser apropriadamente selecionadas, protegidas e gerenciadas.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Nunca use dados de produção em testes. Use dados sintéticos ou anonimizados. Restrinja acesso a ambientes de teste. Destrua dados de teste após uso.',
    iso27002: 'Proteção de dados de teste previne exposição de informações de produção em ambientes menos controlados.',
    risk: 'medium'
  },
  {
    id: 'A.8.34', name: 'Proteção de sistemas de informação durante teste de auditoria',
    description: 'Testes de auditoria e outras atividades de garantia envolvendo avaliação de sistemas operacionais devem ser planejados e acordados entre o testador e a gerência adequada.',
    theme: 'tech', autoAssess: false,
    checkKeywords: [],
    evaluator: null,
    remediation: 'Obtenha autorização formal antes de pentests. Use janela de manutenção para testes invasivos. Monitore sistemas durante testes. Defina escopo e regras de engajamento.',
    iso27002: 'Testes planejados e autorizados garantem que atividades de auditoria não causem indisponibilidades.',
    risk: 'low'
  }
];

/* ----------------------------------------------------------
 * Avaliação de controles
 * ---------------------------------------------------------- */
function assessControls(auditResults) {
  return ISO_CONTROLS.map(ctrl => {
    let assessment;
    if (!auditResults || auditResults.length === 0) {
      assessment = { status: ctrl.autoAssess ? 'manual' : 'manual', evidence: 'Nenhum dado de auditoria disponível' };
    } else if (!ctrl.autoAssess || !ctrl.evaluator) {
      assessment = { status: 'manual', evidence: 'Requer verificação manual — controle organizacional ou de processo' };
    } else {
      try {
        assessment = ctrl.evaluator(auditResults);
      } catch (e) {
        assessment = { status: 'manual', evidence: 'Erro na avaliação automática — verificação manual necessária' };
      }
    }
    // N/A para controles físicos
    if (ctrl.theme === 'physical') {
      assessment = { status: 'na', evidence: 'Não aplicável — controle físico (aplicação web hospedada em nuvem)' };
    }
    return { ...ctrl, _status: assessment.status, _evidence: assessment.evidence };
  });
}

/* ----------------------------------------------------------
 * ISO 27004 — Métricas
 * ---------------------------------------------------------- */
function buildMetrics(assessedControls) {
  const auto = assessedControls.filter(c => c.autoAssess && c.theme !== 'physical');
  const compliant = assessedControls.filter(c => c._status === 'compliant').length;
  const partial   = assessedControls.filter(c => c._status === 'partial').length;
  const nonCompl  = assessedControls.filter(c => c._status === 'non-compliant').length;
  const manual    = assessedControls.filter(c => c._status === 'manual').length;
  const na        = assessedControls.filter(c => c._status === 'na').length;

  const evaluated = compliant + partial + nonCompl;
  const complianceRate = evaluated > 0 ? Math.round((compliant / evaluated) * 100) : 0;
  const coverageRate = Math.round((auto.length / assessedControls.filter(c => c.theme !== 'physical').length) * 100);

  return {
    totalControls: 93,
    autoAssessed: auto.length,
    compliant,
    partial,
    nonCompliant: nonCompl,
    manual,
    na,
    complianceRate,
    coverageRate,
    byTheme: {
      org:      { total: 37, assessed: auto.filter(c => c.theme === 'org').length },
      people:   { total: 8,  assessed: 0 },
      physical: { total: 14, assessed: 0 },
      tech:     { total: 34, assessed: auto.filter(c => c.theme === 'tech').length }
    }
  };
}

/* ----------------------------------------------------------
 * ISO 27005 — Risk Register
 * ---------------------------------------------------------- */
function severityToLikelihood(sev) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[sev] || 2;
}

function severityToImpact(sev) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[sev] || 2;
}

function getTreatment(result) {
  const sev = result.severity;
  if (sev === 'critical') return 'Mitigar imediatamente';
  if (sev === 'high') return 'Mitigar em 7 dias';
  if (sev === 'medium') return 'Mitigar em 30 dias';
  if (sev === 'low') return 'Monitorar e aceitar';
  return 'Aceitar';
}

function getRiskLabel(level) {
  if (level >= 20) return { label: 'Crítico', cls: 'critical' };
  if (level >= 12) return { label: 'Alto', cls: 'high' };
  if (level >= 6)  return { label: 'Médio', cls: 'medium' };
  return { label: 'Baixo', cls: 'low' };
}

function buildRiskRegister(auditResults) {
  if (!auditResults) return [];
  return auditResults
    .filter(r => r.status === 'FAIL' || r.status === 'WARN')
    .map(r => {
      const likelihood = severityToLikelihood(r.severity);
      const impact     = severityToImpact(r.severity);
      const level      = likelihood * impact;
      const riskInfo   = getRiskLabel(level);
      return {
        threat:      r.check,
        description: r.message || '',
        likelihood,
        impact,
        level,
        riskLabel:   riskInfo.label,
        riskCls:     riskInfo.cls,
        treatment:   getTreatment(r),
        severity:    r.severity,
        status:      r.status,
        remediation: (r.details && r.details.remediation) || r.recommendation || ''
      };
    })
    .sort((a, b) => b.level - a.level);
}

/* ----------------------------------------------------------
 * Risk Matrix 5×5 helper
 * ---------------------------------------------------------- */
function buildRiskMatrix(risks) {
  // matrix[row=likelihood 5..1][col=impact 1..5] = count of risks
  const matrix = Array.from({ length: 5 }, () => Array(5).fill(0));
  risks.forEach(r => {
    const row = 5 - r.likelihood; // likelihood 5 → row 0 (top)
    const col = r.impact - 1;     // impact 1 → col 0 (left)
    matrix[row][col]++;
  });
  return matrix;
}

/* ----------------------------------------------------------
 * Exports
 * ---------------------------------------------------------- */
window.ISOEngine = {
  controls: ISO_CONTROLS,
  assessControls,
  buildMetrics,
  buildRiskRegister,
  buildRiskMatrix,
  getRiskLabel
};
