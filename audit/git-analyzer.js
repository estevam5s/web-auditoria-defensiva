/*  ═══════════════════════════════════════════════════════════════════
    GIT COMMIT HISTORY ANALYZER
    Analyzes git history for security issues and patterns
    ═══════════════════════════════════════════════════════════════════ */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const SECURITY_PATTERNS = [
  { pattern: /password|pwd|senha/gi, severity: 'high', type: 'credential' },
  { pattern: /api[_-]?key|apikey/gi, severity: 'critical', type: 'api_key' },
  { pattern: /secret|token|auth/gi, severity: 'high', type: 'secret' },
  { pattern: /aws[_-]?key|aws[_-]?secret/gi, severity: 'critical', type: 'aws_key' },
  { pattern: /supabase[_-]?key|SUPABASE/gi, severity: 'critical', type: 'supabase_key' },
  { pattern: /private[_-]?key|PRIVATE/gi, severity: 'critical', type: 'private_key' },
  { pattern: /database|db[_-]?pass/gi, severity: 'critical', type: 'db_credential' },
  { pattern: /stripe|payment|billing/gi, severity: 'high', type: 'payment_credential' },
  { pattern: /jwt[_-]?secret|SIGNING_KEY/gi, severity: 'critical', type: 'jwt_secret' },
  { pattern: /github[_-]?token|gh[ps]_[a-zA-Z0-9]+/gi, severity: 'critical', type: 'github_token' },
  { pattern: /firebase|google[_-]?api/gi, severity: 'high', type: 'firebase_key' },
  { pattern: /twilio|sendgrid|mailgun/gi, severity: 'high', type: 'api_service' },
  { pattern: /eval|exec|system|shell/gi, severity: 'high', type: 'code_injection' },
  { pattern: /sql[_-]?injection|SQL[_-]?INJECTION/gi, severity: 'critical', type: 'sqli' },
  { pattern: /xss|script.*injection/gi, severity: 'high', type: 'xss' },
  { pattern: /hardcoded|hard[_-]?coded/gi, severity: 'medium', type: 'hardcoded' },
  { pattern: /TODO|FIXME|HACK/gi, severity: 'low', type: 'technical_debt' },
  { pattern: /disable|skip|ignore.*security/gi, severity: 'high', type: 'security_bypass' },
  { pattern: /http:\/\/(?!localhost)/gi, severity: 'medium', type: 'insecure_http' },
  { pattern: /console\.log|debugger/gi, severity: 'low', type: 'debug_code' },
];

const DANGEROUS_FILE_EXTENSIONS = [
  '.env', '.env.local', '.env.production',
  '.pem', '.key', '.p12', '.keystore',
  '.sql', '.dump', '.backup',
  '.log', '.trace',
  'id_rsa', 'id_ed25519'
];

async function analyzeGitHistory(projectPath, maxCommits = 100) {
  const results = {
    commits: [],
    totalCommits: 0,
    securityIssues: [],
    secretsFound: [],
    riskyFiles: [],
    contributors: [],
    commitPatterns: [],
    lastScan: new Date().toISOString()
  };

  try {
    if (!fs.existsSync(projectPath)) {
      return { error: 'Project path not found', ...results };
    }

    // Get commit count
    try {
      const countOutput = execSync('git rev-list --count HEAD', {
        cwd: projectPath,
        encoding: 'utf8',
        timeout: 10000
      });
      results.totalCommits = parseInt(countOutput.trim()) || 0;
    } catch {}

    // Get recent commits with details
    try {
      const logFormat = '%H|%an|%ae|%ad|%s|%P';
      const commitsOutput = execSync(
        `git log --format="${logFormat}" -n ${maxCommits}`,
        { cwd: projectPath, encoding: 'utf8', timeout: 30000 }
      );

      const commitLines = commitsOutput.split('\n').filter(l => l.trim());
      
      for (const line of commitLines) {
        const [hash, author, email, date, message, parents] = line.split('|');
        
        const commit = {
          hash: hash?.substring(0, 7),
          fullHash: hash,
          author: author?.trim(),
          email: email?.trim(),
          date: date?.trim(),
          message: message?.trim(),
          parents: parents?.trim()?.split(' ').filter(Boolean) || []
        };

        // Check for security issues in commit message
        for (const secPattern of SECURITY_PATTERNS) {
          if (secPattern.pattern.test(commit.message)) {
            results.securityIssues.push({
              commitHash: commit.hash,
              author: commit.author,
              date: commit.date,
              message: commit.message,
              severity: secPattern.severity,
              type: secPattern.type,
              pattern: secPattern.pattern.source
            });
          }
        }

        // Get changed files in this commit
        try {
          const filesOutput = execSync(
            `git diff-tree --no-commit-id --name-only -r ${hash}`,
            { cwd: projectPath, encoding: 'utf8', timeout: 5000 }
          );
          
          const files = filesOutput.split('\n').filter(f => f.trim());
          
          for (const file of files) {
            // Check for dangerous file extensions
            for (const ext of DANGEROUS_FILE_EXTENSIONS) {
              if (file.includes(ext)) {
                results.riskyFiles.push({
                  commitHash: commit.hash,
                  file: file,
                  date: commit.date,
                  author: commit.author
                });
              }
            }
          }
        } catch {}

        results.commits.push(commit);
      }
    } catch (e) {
      results.commitsError = e.message;
    }

    // Get contributors
    try {
      const contribOutput = execSync(
        'git shortlog -sn -n 20',
        { cwd: projectPath, encoding: 'utf8', timeout: 10000 }
      );

      const contribLines = contribOutput.split('\n').filter(l => l.trim());
      for (const line of contribLines) {
        const match = line.trim().match(/^\s*(\d+)\s+(.+)$/);
        if (match) {
          results.contributors.push({
            name: match[2],
            commits: parseInt(match[1])
          });
        }
      }
    } catch {}

    // Analyze commit message patterns
    const messagePatterns = {
      feat: { regex: /^(feat|feature)\s*:/i, label: 'Feature' },
      fix: { regex: /^(fix|bugfix)\s*:/i, label: 'Bug Fix' },
      refactor: { regex: /^refactor\s*:/i, label: 'Refactor' },
      docs: { regex: /^docs?\s*:/i, label: 'Documentation' },
      security: { regex: /^(security|sec)\s*:/i, label: 'Security' },
      breaking: { regex: /BREAKING|breaking\s*change/i, label: 'Breaking Change' }
    };

    for (const [key, pattern] of Object.entries(messagePatterns)) {
      const count = results.commits.filter(c => pattern.regex.test(c.message)).length;
      if (count > 0) {
        results.commitPatterns.push({
          type: key,
          label: pattern.label,
          count
        });
      }
    }

  } catch (error) {
    results.error = error.message;
  }

  return results;
}

async function checkForExposedSecrets(projectPath) {
  const findings = [];

  // Files to check for secrets
  const sensitiveFiles = [
    '.env', '.env.local', '.env.production', '.env.development',
    'config.js', 'config.ts', 'settings.js',
    'secrets.json', 'credentials.json',
    '.npmrc', '.pypirc',
    'docker-compose.yml', 'Dockerfile'
  ];

  // Patterns to check in files
  const secretPatterns = [
    { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret', pattern: /aws_secret_access_key\s*[=:]\s*["'][^"']{40}["']/gi },
    { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
    { name: 'Private Key', pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g },
    { name: 'Supabase Key', pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+/g },
    { name: 'Database URL', pattern: /(postgres|mysql|mongodb):\/\/[^\s"']+/gi },
    { name: 'Stripe Key', pattern: /sk_live_[a-zA-Z0-9]{20,}/g },
    { name: 'API Key Generic', pattern: /api[_-]?key\s*[=:]\s*["'][a-zA-Z0-9_]{20,}["']/gi }
  ];

  try {
    // Check git status for uncommitted changes
    try {
      const statusOutput = execSync('git status --short', {
        cwd: projectPath,
        encoding: 'utf8',
        timeout: 5000
      });

      const statusFiles = statusOutput.split('\n')
        .filter(l => l.trim())
        .map(l => l.substring(3).trim());

      for (const file of statusFiles) {
        for (const pattern of sensitiveFiles) {
          if (file.includes(pattern)) {
            findings.push({
              type: 'sensitive_file',
              severity: 'high',
              file: file,
              status: 'uncommitted',
              description: `Sensitive file has uncommitted changes: ${file}`
            });
          }
        }
      }
    } catch {}

    // Check for secrets in recent git diff
    try {
      const diffOutput = execSync('git diff HEAD~50 --name-only', {
        cwd: projectPath,
        encoding: 'utf8',
        timeout: 10000
      });

      const changedFiles = diffOutput.split('\n').filter(f => f.trim());
      
      for (const file of changedFiles) {
        if (file.includes('.env') || file.includes('config')) {
          findings.push({
            type: 'sensitive_file_changed',
            severity: 'medium',
            file: file,
            description: `Sensitive configuration file was modified`
          });
        }
      }
    } catch {}

  } catch (error) {
    findings.push({
      type: 'error',
      severity: 'low',
      error: error.message
    });
  }

  return findings;
}

module.exports = {
  analyzeGitHistory,
  checkForExposedSecrets,
  SECURITY_PATTERNS
};
