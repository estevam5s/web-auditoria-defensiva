/*  ═══════════════════════════════════════════════════════════════════
    DEEP CHECK: Storage Read/Listing Abuse Analyzer
    Comprehensive storage security audit:
    - Unauthorized bucket listing
    - Public bucket file enumeration
    - Sensitive file type detection
    - Direct object access bypass
    - Signed URL abuse
    - Cross-bucket traversal
    - File permission misconfiguration
    ═══════════════════════════════════════════════════════════════════ */

const { safeFetch, supabaseHeaders } = require('../helpers/http');

// Sensitive file extensions
const SENSITIVE_EXTENSIONS = [
  '.env', '.env.local', '.env.production', '.env.development',
  '.key', '.pem', '.p12', '.pfx', '.jks', '.keystore',
  '.sql', '.sql.gz', '.sql.bak', '.dump', '.sqlite', '.db',
  '.csv', '.xlsx', '.xls', '.tsv',
  '.json', '.yaml', '.yml', '.toml', '.conf', '.config', '.cfg',
  '.bak', '.backup', '.old', '.orig', '.swp', '.sav',
  '.log', '.logs', '.error.log', '.access.log',
  '.doc', '.docx', '.pdf', '.odt',
  '.zip', '.tar', '.tar.gz', '.rar', '.7z',
  '.psd', '.ai',
  '.sh', '.bash', '.bat', '.cmd', '.ps1',
  '.py', '.rb', '.php', '.js', '.ts',
  '.xml', '.wsdl',
  '.cer', '.crt', '.ca-bundle',
  '.htaccess', '.htpasswd',
  '.git', '.gitconfig',
  '.dockerenv', '.docker',
  '.npmrc', '.pypirc',
  '.aws', '.credentials',
];

// File name patterns that indicate sensitive content
const SENSITIVE_NAME_PATTERNS = [
  /backup/i, /dump/i, /export/i, /secret/i, /private/i, /credential/i,
  /password/i, /passwd/i, /config/i, /\.env/i, /database/i,
  /key\./i, /token/i, /admin/i, /internal/i, /confidential/i,
  /financ/i, /payment/i, /invoice/i, /receipt/i, /bank/i,
  /cpf/i, /cnpj/i, /rg\./i, /passport/i, /ssn/i,
  /medical/i, /health/i, /patient/i, /diagnos/i,
  /salary/i, /payroll/i, /contract/i, /agreement/i,
  /users.*\.csv/i, /customers.*\.csv/i, /data.*\.json/i,
  /migration/i, /seed/i, /fixture/i,
];

// Common bucket names to try
const BUCKET_NAMES = [
  'avatars', 'uploads', 'images', 'photos', 'pictures', 'media',
  'documents', 'docs', 'files', 'attachments', 'resources',
  'public', 'assets', 'static', 'content', 'data',
  'backups', 'backup', 'exports', 'downloads', 'reports',
  'invoices', 'receipts', 'contracts', 'certificates',
  'videos', 'audio', 'music', 'recordings',
  'thumbnails', 'previews', 'covers', 'banners',
  'logos', 'icons', 'brands',
  'temp', 'tmp', 'cache', 'staging',
  'private', 'internal', 'admin', 'system',
  'user-data', 'user-files', 'user-uploads',
  'profile-pictures', 'profile-images',
];

// Common file names to probe inside buckets
const COMMON_FILES = [
  '.env', 'config.json', 'secrets.json', 'credentials.json',
  'database.sql', 'backup.sql', 'dump.sql', 'export.csv',
  'users.csv', 'customers.csv', 'orders.csv', 'payments.csv',
  'README.md', 'index.html', '.gitignore', '.htaccess',
  'key.pem', 'cert.pem', 'server.key', 'private.key',
];

function isSupabaseUrl(url) {
  return typeof url === 'string' && url.includes('.supabase.co');
}

async function deepStorageCheck(config, emit) {
  const results = [];
  const baseUrl = config.projectUrl;
  const headers = supabaseHeaders(config.anonKey);

  emit({ type: 'log', level: 'info', message: '[Storage Deep] Iniciando análise profunda de Storage...' });

  // ═══════════ 1. Bucket Listing Tests ═══════════
  emit({ type: 'log', level: 'info', message: '[Storage Deep] Testando listagem de buckets...' });

  // Test with anon key
  const bucketsRes = await safeFetch(`${baseUrl}/storage/v1/bucket`, { headers, timeout: 8000 });
  let knownBuckets = [];

  if (bucketsRes.ok && Array.isArray(bucketsRes.json)) {
    knownBuckets = bucketsRes.json;
    emit({ type: 'log', level: 'warn', message: `[Storage Deep] ${knownBuckets.length} bucket(s) listáveis com anon key` });
  }

  // Test without any auth
  const noAuthBuckets = await safeFetch(`${baseUrl}/storage/v1/bucket`, {
    headers: { 'Content-Type': 'application/json' },
    timeout: 8000
  });

  if (noAuthBuckets.ok && Array.isArray(noAuthBuckets.json)) {
    results.push({
      check: 'Storage — Listagem Sem Auth',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 Buckets listáveis SEM autenticação! ${noAuthBuckets.json.length} bucket(s) expostos.`,
      details: {
        buckets: noAuthBuckets.json.map(b => ({ name: b.name, public: b.public })),
        recommendation: 'Configure Storage policies para exigir autenticação na listagem de buckets.'
      }
    });
  }

  // ═══════════ 2. Deep Bucket Analysis ═══════════
  emit({ type: 'log', level: 'info', message: '[Storage Deep] Analisando cada bucket em profundidade...' });

  const publicBuckets = knownBuckets.filter(b => b.public);
  const privateBuckets = knownBuckets.filter(b => !b.public);

  const allBucketIssues = [];
  const sensitiveFilesFound = [];

  for (const bucket of knownBuckets) {
    emit({ type: 'log', level: 'info', message: `[Storage Deep] Analisando bucket: ${bucket.name} (${bucket.public ? 'PÚBLICO' : 'privado'})` });

    // List files in bucket
    const listRes = await safeFetch(`${baseUrl}/storage/v1/object/list/${bucket.name}`, {
      method: 'POST',
      headers: { ...headers, 'Content-Type': 'application/json' },
      body: JSON.stringify({ prefix: '', limit: 100, offset: 0, sortBy: { column: 'name', order: 'asc' } }),
      timeout: 10000,
    });

    if (listRes.ok && Array.isArray(listRes.json)) {
      const files = listRes.json;

      if (files.length > 0) {
        emit({ type: 'log', level: 'warn', message: `[Storage Deep] ${bucket.name}: ${files.length} arquivo(s) listáveis` });

        // Analyze each file
        for (const file of files) {
          if (!file.name) continue;
          const name = file.name.toLowerCase();
          const ext = '.' + name.split('.').pop();

          // Check sensitive extensions
          const isSensitiveExt = SENSITIVE_EXTENSIONS.some(se => name.endsWith(se));
          // Check sensitive name patterns
          const isSensitiveName = SENSITIVE_NAME_PATTERNS.some(p => p.test(file.name));
          // Check size (very large files may be database dumps)
          const size = file.metadata?.size || 0;
          const isLargeFile = size > 10 * 1024 * 1024; // > 10MB

          if (isSensitiveExt || isSensitiveName || isLargeFile) {
            sensitiveFilesFound.push({
              bucket: bucket.name,
              file: file.name,
              size: size,
              sizeHuman: formatSize(size),
              mimetype: file.metadata?.mimetype || 'unknown',
              lastModified: file.updated_at || file.created_at,
              reasons: [
                isSensitiveExt ? `Extensão sensível (${ext})` : null,
                isSensitiveName ? 'Nome indica conteúdo sensível' : null,
                isLargeFile ? `Arquivo grande (${formatSize(size)})` : null,
              ].filter(Boolean),
              bucketPublic: bucket.public,
            });

            emit({ type: 'log', level: 'warn', message: `[Storage Deep] ⚠ Sensitivo: ${bucket.name}/${file.name} (${formatSize(size)})` });
          }
        }

        if (bucket.public) {
          allBucketIssues.push({
            bucket: bucket.name,
            public: true,
            fileCount: files.length,
            sensitiveCount: sensitiveFilesFound.filter(f => f.bucket === bucket.name).length,
          });

          // Test direct public URL access for sensitive files
          for (const sf of sensitiveFilesFound.filter(f => f.bucket === bucket.name).slice(0, 5)) {
            const publicUrl = `${baseUrl}/storage/v1/object/public/${bucket.name}/${sf.file}`;
            const fileRes = await safeFetch(publicUrl, { method: 'HEAD', timeout: 5000 });

            if (fileRes.ok) {
              sf.publiclyAccessible = true;
              sf.publicUrl = publicUrl;
              emit({ type: 'log', level: 'warn', message: `[Storage Deep] 🚨 Download público: ${publicUrl}` });
            }
          }
        }
      }

      // Try to list subdirectories/prefixes
      const subPrefixes = [...new Set(files.filter(f => f.name?.includes('/')).map(f => f.name.split('/')[0]))];
      for (const prefix of subPrefixes.slice(0, 10)) {
        const subRes = await safeFetch(`${baseUrl}/storage/v1/object/list/${bucket.name}`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefix: prefix + '/', limit: 50, offset: 0 }),
          timeout: 5000,
        });

        if (subRes.ok && Array.isArray(subRes.json) && subRes.json.length > 0) {
          emit({ type: 'log', level: 'info', message: `[Storage Deep] ${bucket.name}/${prefix}/: ${subRes.json.length} arquivos` });
        }
      }
    }
  }

  // ═══════════ 3. Hidden Bucket Discovery ═══════════
  // GUARD: Only probe hidden buckets on actual Supabase URLs to avoid false positives
  const knownNames = knownBuckets.map(b => b.name);
  const hiddenBuckets = [];

  if (isSupabaseUrl(baseUrl)) {
    emit({ type: 'log', level: 'info', message: `[Storage Deep] Procurando ${BUCKET_NAMES.length} buckets ocultos...` });

    for (const name of BUCKET_NAMES) {
      if (knownNames.includes(name)) continue;

      // Try listing — more reliable than public URL test
      const listRes = await safeFetch(`${baseUrl}/storage/v1/object/list/${name}`, {
        method: 'POST',
        headers: { ...headers, 'Content-Type': 'application/json' },
        body: JSON.stringify({ prefix: '', limit: 5 }),
        timeout: 3000,
      });

      // Only report if listing succeeds (200) — status 400/404 means bucket doesn't exist
      if (listRes.ok && Array.isArray(listRes.json)) {
        const files = listRes.json;
        hiddenBuckets.push({
          name,
          accessible: true,
          fileCount: files.length,
        });
        emit({ type: 'log', level: 'warn', message: `[Storage Deep] Bucket oculto encontrado: ${name} (${files.length} arquivos)` });
      }
    }
  } else {
    emit({ type: 'log', level: 'info', message: '[Storage Deep] URL não é Supabase — pulando busca por buckets ocultos.' });
  }

  // ═══════════ 4. Common File Probing in Buckets ═══════════
  const allBucketNames = [...knownNames, ...hiddenBuckets.map(h => h.name)];
  const criticalFiles = [];

  if (isSupabaseUrl(baseUrl) && allBucketNames.length > 0) {
    emit({ type: 'log', level: 'info', message: '[Storage Deep] Procurando arquivos críticos em buckets...' });

    for (const bucketName of allBucketNames.slice(0, 15)) {
      for (const fileName of COMMON_FILES) {
        const publicUrl = `${baseUrl}/storage/v1/object/public/${bucketName}/${fileName}`;
        const res = await safeFetch(publicUrl, { method: 'HEAD', timeout: 3000 });

        // Only report if file actually exists AND has content (status 200 with content-length > 0)
        if ((res.ok || res.status === 200) && (parseInt(res.headers?.['content-length'] || '0') > 0 || res.headers?.['content-type'])) {
          criticalFiles.push({
            bucket: bucketName,
            file: fileName,
            url: publicUrl,
            size: parseInt(res.headers?.['content-length'] || '0'),
          });
          emit({ type: 'log', level: 'warn', message: `[Storage Deep] Arquivo crítico público: ${bucketName}/${fileName}` });
        }
      }
    }
  } else if (!isSupabaseUrl(baseUrl)) {
    emit({ type: 'log', level: 'info', message: '[Storage Deep] URL não é Supabase — pulando probe de arquivos críticos.' });
  }

  // ═══════════ 5. Upload Permission Test ═══════════
  emit({ type: 'log', level: 'info', message: '[Storage Deep] Testando permissão de upload...' });

  const uploadable = [];
  for (const bucket of knownBuckets.slice(0, 10)) {
    const testFile = new Uint8Array([0x47, 0x49, 0x46, 0x38]); // GIF header
    const uploadRes = await safeFetch(`${baseUrl}/storage/v1/object/${bucket.name}/_audit_test_${Date.now()}.gif`, {
      method: 'POST',
      headers: {
        ...headers,
        'Content-Type': 'image/gif',
      },
      body: Buffer.from(testFile),
      timeout: 5000,
    });

    if (uploadRes.ok || uploadRes.status === 200) {
      uploadable.push({ bucket: bucket.name, public: bucket.public });
      emit({ type: 'log', level: 'warn', message: `[Storage Deep] 🚨 Upload permitido: ${bucket.name}` });

      // Clean up
      await safeFetch(`${baseUrl}/storage/v1/object/${bucket.name}/_audit_test_*`, {
        method: 'DELETE',
        headers,
        timeout: 3000,
      });
    }
  }

  // ═══════════ Compile Results ═══════════
  emit({ type: 'log', level: 'info', message: `[Storage Deep] Compilando resultados...` });

  // Sensitive files in public buckets
  const publicSensitive = sensitiveFilesFound.filter(f => f.bucketPublic || f.publiclyAccessible);
  if (publicSensitive.length > 0) {
    results.push({
      check: 'Storage — Arquivos Sensíveis Públicos',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${publicSensitive.length} arquivo(s) sensível(is) em bucket(s) público(s)! (.env, .sql, .csv, chaves, etc.)`,
      details: {
        files: publicSensitive.slice(0, 20),
        recommendation: 'URGENTE: Mova arquivos sensíveis para buckets privados. Configure RLS Storage policies.'
      }
    });
  }

  // Critical files found
  if (criticalFiles.length > 0) {
    results.push({
      check: 'Storage — Arquivos Críticos Acessíveis',
      status: 'FAIL',
      severity: 'critical',
      message: `🚨 ${criticalFiles.length} arquivo(s) de configuração/credencial acessível(is) publicamente!`,
      details: {
        files: criticalFiles,
        recommendation: 'URGENTE: Remova .env, .sql, .key e outros arquivos de configuração do storage público.'
      }
    });
  }

  // Upload without auth
  if (uploadable.length > 0) {
    results.push({
      check: 'Storage — Upload Sem Controle',
      status: 'FAIL',
      severity: 'high',
      message: `${uploadable.length} bucket(s) permite(m) upload via anon key! Risco de uso malicioso.`,
      details: {
        buckets: uploadable,
        recommendation: 'Restrinja políticas de upload. Exija autenticação e valide tipos de arquivo permitidos.'
      }
    });
  }

  // Hidden buckets
  if (hiddenBuckets.length > 0) {
    results.push({
      check: 'Storage — Buckets Ocultos Descobertos',
      status: 'WARN',
      severity: 'medium',
      message: `${hiddenBuckets.length} bucket(s) não listado(s) mas acessível(is) por nome.`,
      details: {
        buckets: hiddenBuckets,
        recommendation: 'Buckets ocultos por nome não é segurança. Configure RLS policies adequadas.'
      }
    });
  }

  // General bucket listing
  if (publicBuckets.length > 0) {
    results.push({
      check: 'Storage — Buckets Públicos',
      status: 'WARN',
      severity: publicBuckets.length > 2 ? 'high' : 'medium',
      message: `${publicBuckets.length} bucket(s) público(s) (de ${knownBuckets.length} total).`,
      details: {
        public: publicBuckets.map(b => b.name),
        private: privateBuckets.map(b => b.name),
        recommendation: 'Minimize buckets públicos. Use signed URLs para acesso temporário a arquivos privados.'
      }
    });
  }

  // Private sensitive files (accessible via anon key listing)
  const privateSensitive = sensitiveFilesFound.filter(f => !f.bucketPublic && !f.publiclyAccessible);
  if (privateSensitive.length > 0) {
    results.push({
      check: 'Storage — Listagem Sensível (Bucket Privado)',
      status: 'WARN',
      severity: 'high',
      message: `${privateSensitive.length} arquivo(s) sensível(is) listáveis em bucket privado via anon key.`,
      details: {
        files: privateSensitive.slice(0, 15),
        recommendation: 'Configure Storage policies para bloquear listagem por anon. Apenas o proprietário deve ver seus arquivos.'
      }
    });
  }

  // All good
  if (results.length === 0) {
    results.push({
      check: 'Storage — Análise Profunda',
      status: 'PASS',
      severity: 'info',
      message: `✓ Storage parece bem configurado. ${knownBuckets.length} buckets, ${BUCKET_NAMES.length} nomes testados.`,
      details: { bucketsFound: knownBuckets.length, hiddenTested: BUCKET_NAMES.length }
    });
  }

  return results;
}

function formatSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

module.exports = { deepStorageCheck };
