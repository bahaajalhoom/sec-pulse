// ============================================================================
// CONFIGURATION & CONSTANTS: ATTACK VECTORS, CANARY PAYLOADS & DESCRIPTIONS
// ============================================================================
import {
  AttackIntensity,
  SecurityProbePayload,
  VulnerabilityCategory,
} from '@/types/security';

export const APP_CONFIG = {
  name: 'SecuriPulse',
  nameAr: 'سيكيوريبلس - درع الأمان',
  version: '3.0.0',
  description: 'منصة محاكاة الهجمات الأمنية وفحص الثغرات التفاعلي لأصحاب المواقع والمطورين',
  descriptionEn: 'Interactive Defensive Threat Simulation & Security Posture Auditor for Web Developers',
} as const;

export const INTENSITY_PROFILES: Record<
  AttackIntensity,
  {
    labelAr: string;
    labelEn: string;
    descriptionAr: string;
    descriptionEn: string;
    badgeClass: string;
    probesCount: number;
    recommendedFor: string;
  }
> = {
  gentle: {
    labelAr: 'ضعيف (سطحي آمن)',
    labelEn: 'Gentle (Passive Baseline)',
    descriptionAr: 'فحص ترويسات الأمان (Headers)، فحص شهادة SSL، فحص ملف robots.txt، بدون إرسال استعلامات ضاغطة على الخادم.',
    descriptionEn: 'Passive metadata analysis, HTTP security headers, SSL/TLS validation, robots/sitemap inspection. Zero server stress.',
    badgeClass: 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40',
    probesCount: 16,
    recommendedFor: 'المواقع الحية على الإنترنت والإنتاج (Production)',
  },
  standard: {
    labelAr: 'وسط (اختبار متوازن)',
    labelEn: 'Standard (Balanced Audit)',
    descriptionAr: 'اختبارات حقن تجريبية آمنة (Canaries)، فحص مصادقة الرموز (Tokens)، فحص منافذ الويب الشائعة، وفحص تسريبات CORS.',
    descriptionEn: 'Safe canary parameter injection, auth token validation, standard exposed port probes, CORS policy checks.',
    badgeClass: 'bg-blue-950/60 text-blue-400 border border-blue-800/40',
    probesCount: 32,
    recommendedFor: 'بيئات الاختبار والمواقع التجريبية (Staging & Dev)',
  },
  rigorous: {
    labelAr: 'صعب (فحص مكثف واختبار صمود)',
    labelEn: 'Rigorous (Deep Stress & Fuzzing)',
    descriptionAr: 'محاكاة هجمات مركبة، تشويش المدخلات (Fuzzing)، فحص صمود الخادم أمام المعدل العالي، فحص مسارات الاستحواذ على النطاق.',
    descriptionEn: 'Advanced parameter fuzzing, boundary tampering, rate-limiting resilience test, dangling subdomain discovery.',
    badgeClass: 'bg-rose-950/60 text-rose-400 border border-rose-800/40',
    probesCount: 48,
    recommendedFor: 'السيرفرات المحلية واختبارات الجاهزية قبل الإطلاق (Pre-launch)',
  },
};

export const CATEGORY_METADATA: Record<
  VulnerabilityCategory,
  {
    nameAr: string;
    nameEn: string;
    icon: string;
    shortDescAr: string;
    shortDescEn: string;
  }
> = {
  sqli: {
    nameAr: 'حقن قواعد البيانات (SQLi)',
    nameEn: 'SQL Injection Canaries',
    icon: 'Database',
    shortDescAr: 'محاكاة إرسال رموز استعلام ملتوية لمعرفة هل يعالج الخادم المدخلات مباشرة بدون تشفير',
    shortDescEn: 'Tests whether database queries safely sanitize inputs using parameterization',
  },
  xss: {
    nameAr: 'حقن النصوص البرمجية (XSS)',
    nameEn: 'Cross-Site Scripting (XSS)',
    icon: 'CodeXml',
    shortDescAr: 'إرسال وسوم نصية تجريبية للتأكد من قيام المتصفح بتنظيفها ومنع سرقة ملفات الارتباط (Cookies)',
    shortDescEn: 'Validates that user inputs are encoded and sanitized before rendering in DOM',
  },
  auth: {
    nameAr: 'كسر المصادقة والجلسات (Broken Auth)',
    nameEn: 'Broken Authentication',
    icon: 'KeyRound',
    shortDescAr: 'محاكاة إرسال طلبات بدون تصريح أو برؤوس JWT مزيفة للتأكد من حماية المسارات السرية',
    shortDescEn: 'Audits endpoint protection against missing tokens, replay, and token tampering',
  },
  ports: {
    nameAr: 'فحص المنافذ المكشوفة (Open Ports)',
    nameEn: 'Open Ports & Exposed DBs',
    icon: 'Radio',
    shortDescAr: 'فحص هل المنافذ الحساسة (مثل 5432 أو 6379 أو 8080) مكشوفة للعامة على الإنترنت',
    shortDescEn: 'Discovers exposed database ports and debug services on public network interfaces',
  },
  subdomain: {
    nameAr: 'الاستحواذ على النطاق الفرعي (Subdomain Takeover)',
    nameEn: 'Subdomain Takeover & DNS',
    icon: 'Globe',
    shortDescAr: 'فحص سجلات CNAME المعلقة التي تشير إلى منصات محذوفة تمكن المهاجم من سرقة نطاقك',
    shortDescEn: 'Checks dangling CNAME records pointing to unclaimed hosting services',
  },
  headers: {
    nameAr: 'ترويسات الحماية وسياسة الأمان (Security Headers)',
    nameEn: 'Security Headers & Policies',
    icon: 'ShieldCheck',
    shortDescAr: 'التحقق من ترويسات HSTS و CSP و X-Frame-Options لمنع هجمات التضمين والنقر الخبيث',
    shortDescEn: 'Audits essential defensive HTTP headers preventing iframe clickjacking and mime sniffing',
  },
  ssrf: {
    nameAr: 'تزوير طلبات الخادم (SSRF)',
    nameEn: 'Server-Side Request Forgery',
    icon: 'Server',
    shortDescAr: 'محاكاة توجيه الخادم لطلب عناوين سحابية داخلية سرية مثل AWS Metadata لمنع اختراق البنية التحتية',
    shortDescEn: 'Tests whether backend endpoints can be coerced into requesting internal cloud metadata (169.254.169.254)',
  },
  idor: {
    nameAr: 'كسر عزل كائنات البيانات (IDOR / BOLA)',
    nameEn: 'Broken Object Level Auth (IDOR)',
    icon: 'UserCheck',
    shortDescAr: 'فحص التلاعب بمعرفات السجلات (IDs) للتأكد من منع أي مستخدم من الوصول لبيانات غيره',
    shortDescEn: 'Validates tenant isolation and prevents unauthorized object parameter tampering',
  },
  sensitive_files: {
    nameAr: 'تسريب الملفات وسجلات النسخ (.env & .git)',
    nameEn: 'Sensitive Files & Git Leaks',
    icon: 'FileWarning',
    shortDescAr: 'فحص تسريب ملفات البيئة السرية ومستودعات Git والنسخ الاحتياطية المتروكة في مسار الموقع',
    shortDescEn: 'Detects exposed sensitive files like .env, .git/config, and database backup dumps',
  },
  rate_limiting: {
    nameAr: 'تقييد معدل الطلبات والصمود (Rate Limiting)',
    nameEn: 'Rate Limiting & DoS Resilience',
    icon: 'Hourglass',
    shortDescAr: 'فحص قدرة السيرفر على صد الهجمات المتكررة ومنع استنزاف الموارد عبر تفعيل Rate Limiting',
    shortDescEn: 'Tests backend throttling and HTTP 429 response enforcement against burst traffic',
  },
  cmd_injection: {
    nameAr: 'حقن أوامر نظام التشغيل (OS Command Injection)',
    nameEn: 'OS Command Injection Canaries',
    icon: 'Terminal',
    shortDescAr: 'فحص حقن محارف تنفيذ الأوامر (| و ;) في المدخلات التي تعالج مهام النظام أو الملفات',
    shortDescEn: 'Checks if user parameters can execute arbitrary operating system terminal commands',
  },
  cors_leak: {
    nameAr: 'تسريب سياسات النطاق المشترك (CORS Leakage)',
    nameEn: 'CORS Origin Misconfiguration',
    icon: 'Share2',
    shortDescAr: 'فحص هل يعكس السيرفر أي نطاق خارجي مع تفعيل ملفات تعريف الارتباط وبيانات الاعتماد',
    shortDescEn: 'Tests dangerous origin reflection allowing external web origins to steal private sessions',
  },
  csrf: {
    nameAr: 'حماية تزوير الطلبات (CSRF Protection)',
    nameEn: 'Cross-Site Request Forgery (CSRF)',
    icon: 'ShieldAlert',
    shortDescAr: 'التحقق من وجود رموز Anti-CSRF وسياسات SameSite لمنع تنفيذ عمليات نيابة عن المستخدم',
    shortDescEn: 'Verifies state-changing endpoints enforce anti-CSRF tokens and SameSite cookie policies',
  },
  graphql: {
    nameAr: 'كشف مخططات GraphQL (Introspection Leak)',
    nameEn: 'GraphQL Introspection & Schema Leak',
    icon: 'Layers',
    shortDescAr: 'فحص هل واجهة GraphQL تكشف هيكل الجداول والعلاقات البرمجية بالكامل للعامة في الإنتاج',
    shortDescEn: 'Detects public schema introspection enabled on production GraphQL endpoints',
  },
  directory_traversal: {
    nameAr: 'التنقل في مسارات الملفات (Path Traversal ../)',
    nameEn: 'Directory & Path Traversal',
    icon: 'FolderTree',
    shortDescAr: 'محاكاة التلاعب بمسارات تحميل وعرض الملفات للوصول لملفات النظام الحساسة مثل /etc/passwd',
    shortDescEn: 'Audits file download and view parameters against directory traversal dot-dot-slash vectors',
  },
  mass_assignment: {
    nameAr: 'التعيين الجماعي والتلاعب بالصلاحيات (Mass Assignment)',
    nameEn: 'Mass Assignment & Role Escalation',
    icon: 'Sliders',
    shortDescAr: 'محاكاة إرسال حقول إدارية سرية (مثل isAdmin: true) أثناء التسجيل أو التحديث لمعرفة هل يقبلها الخادم',
    shortDescEn: 'Checks if DTO binding permits unauthorized role escalation or field injection',
  },
};

// ============================================================================
// DEFAULT EDITABLE CANARY PROBES (PRE-ATTACK INSPECTOR CATALOG)
// ============================================================================
export const INITIAL_PROBES: SecurityProbePayload[] = [
  // 1. SQL INJECTION PROBES
  {
    id: 'sqli-01',
    category: 'sqli',
    name: 'SQL Tautology Canary Test',
    nameAr: 'اختبار الحشو المنطقي لقواعد البيانات (Tautology 1=1)',
    description: 'Sends a benign tautological condition to verify if query sanitization handles quotes cleanly.',
    descriptionAr: 'يرسل شرطاً منطقياً بديهياً لفحص ما إذا كان استعلام قاعدة البيانات يدمج النصوص دون عزل (Sanitization).',
    method: 'GET',
    targetPath: '/api/search?q=%27%20OR%201%3D1%20--',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
      'Accept': 'application/json, text/html',
    },
    payloadCode: "' OR 1=1 --",
    canaryExpectedOutcome: 'Server must treat input as literal text, never alter query logic or return unescaped database errors.',
    canaryExpectedOutcomeAr: 'يجب على الخادم معاملة النص ككلمة بحث عادية، وعدم تغيير هيكل الاستعلام أو إظهار خطأ SQL.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'sqli-02',
    category: 'sqli',
    name: 'SQL Error-Based Disclosure Check',
    nameAr: 'كشف أخطاء قواعد البيانات المكشوفة (Error Disclosure)',
    description: 'Sends malformed punctuation to test if internal SQL dialect/database stack traces are leaked in HTTP 500.',
    descriptionAr: 'يرسل علامات ترقيم غير مكتملة لفحص هل يسرّب الخادم رسائل خطأ تكشف نوع قاعدة البيانات وإصدارها للمخترق.',
    method: 'POST',
    targetPath: '/api/v1/auth/login',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: JSON.stringify({ email: "admin'\"", password: "test" }, null, 2),
    canaryExpectedOutcome: 'Server must return generic 400/401 response without disclosing PostgreSQL, MySQL, or SQLite syntax traces.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم رسالة عامة "بيانات غير صالحة" دون ذكر أي تفاصيل برمجية داخلية.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // 2. CROSS-SITE SCRIPTING (XSS) PROBES
  {
    id: 'xss-01',
    category: 'xss',
    name: 'Reflected Script Canary Probe',
    nameAr: 'فحص انعكاس وسوم الجافاسكريبت (Reflected Script Tag)',
    description: 'Tests if user inputs in URL parameters are reflected back raw into HTML without HTML entity escaping.',
    descriptionAr: 'فحص ما إذا كانت متغيرات الرابط تظهر كما هي في الصفحة بدون تشفير الكيانات (HTML Escaping).',
    method: 'GET',
    targetPath: '/?ref=%3Cscript%3Econsole.log(%22securipulse_canary%22)%3C%2Fscript%3E',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: '<script>console.log("securipulse_canary")</script>',
    canaryExpectedOutcome: 'Output must be safely entity-encoded (&lt;script&gt;) or blocked by Content-Security-Policy.',
    canaryExpectedOutcomeAr: 'يجب تحويل الأقواس لرموز نصية آمنة لمنع المتصفح من تشغيل الكود.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 3. BROKEN AUTHENTICATION & ACCESS CONTROL
  {
    id: 'auth-01',
    category: 'auth',
    name: 'Protected API Route Authorization Omission',
    nameAr: 'فحص حماية المسارات الإدارية بدون رمز تصريح (Missing Auth Header)',
    description: 'Probes common internal endpoints without providing an Authorization bearer token.',
    descriptionAr: 'محاولة الدخول على مسارات إدارية حساسة بدون إرسال تصريح لفحص هل الخادم محمي بالكامل.',
    method: 'GET',
    targetPath: '/api/admin/users',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
      'Accept': 'application/json',
    },
    payloadCode: '// Empty Authorization Header Test\nGET /api/admin/users HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must immediately reject with HTTP 401 Unauthorized or 403 Forbidden.',
    canaryExpectedOutcomeAr: 'يجب أن يرفض الخادم الطلب فوراً برمز 401 أو 403 دون إظهار أي بيانات مستخدمين.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'auth-02',
    category: 'auth',
    name: 'JWT Algorithm "None" Signature Bypass Probe',
    nameAr: 'اختبار تجاوز توقيع رموز JWT (Algorithm None Probe)',
    description: 'Sends an unsigned JWT token with alg: none to check if the backend enforces cryptographic signature validation.',
    descriptionAr: 'إرسال رمز JWT مفكك التوقيع لفحص هل يتحقق الباك إند من صحة التوقيع المشفر أم يقبل الرموز المزيفة.',
    method: 'GET',
    targetPath: '/api/user/profile',
    headers: {
      'Authorization': 'Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlNlY3VyaVB1bHNlIn0.',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'Header: {"alg":"none","typ":"JWT"}\nPayload: {"sub":"canary-user","role":"admin"}',
    canaryExpectedOutcome: 'Token must be rejected as invalid signature (HTTP 401).',
    canaryExpectedOutcomeAr: 'يجب رفض الرمز فوراً لعدم وجود توقيع رقمي صالح.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 4. OPEN PORTS & EXPOSED ASSETS
  {
    id: 'ports-01',
    category: 'ports',
    name: 'Exposed Database & Microservice Port Audit',
    nameAr: 'فحص منافذ قواعد البيانات المباشرة (Ports 5432, 6379, 8080)',
    description: 'Simulates safe banner checking on commonly misconfigured ports like Redis, PostgreSQL, and Node debuggers.',
    descriptionAr: 'فحص هل قواعد البيانات مثل بوستجرس أو ريديس مكشوفة برقم IP العام دون جدار ناري.',
    method: 'HEAD',
    targetPath: ':5432',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'TCP SYN Canary Probe to Port 5432 (Postgres) / 6379 (Redis)',
    canaryExpectedOutcome: 'Database ports should never be exposed to the public internet; only accessible via private VPC.',
    canaryExpectedOutcomeAr: 'يجب أن تكون منافذ قواعد البيانات مغلقة عن الإنترنت العام ومحصورة بالشبكة الداخلية.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 5. SUBDOMAIN TAKEOVER & DNS HYGIENE
  {
    id: 'subdomain-01',
    category: 'subdomain',
    name: 'Dangling CNAME & Cloud Service Record Audit',
    nameAr: 'فحص سجلات CNAME المعلقة ومضيفات السحابة المهجورة',
    description: 'Audits DNS canonical name mappings for orphaned targets on AWS S3, Vercel, GitHub Pages, or Heroku.',
    descriptionAr: 'التأكد من أن النطاقات الفرعية لا تشير إلى خدمات سحابية تم حذفها مما يتيح للغير حجزها باسمك.',
    method: 'GET',
    targetPath: '/dns-hygiene-audit',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'DNS Query: CNAME record verification & NXDOMAIN error check',
    canaryExpectedOutcome: 'No CNAME records pointing to unclaimed resources with NXDOMAIN status.',
    canaryExpectedOutcomeAr: 'عدم وجود سجلات توجه لمشاريع محذوفة تتيح للغرباء السيطرة على دومينك الفرعي.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // 6. DEFENSIVE SECURITY HEADERS & POLICIES
  {
    id: 'headers-01',
    category: 'headers',
    name: 'HSTS & Clickjacking Protection Audit',
    nameAr: 'فحص ترويسات HSTS و X-Frame-Options (منع التضمين الخبيث)',
    description: 'Verifies presence of Strict-Transport-Security, X-Frame-Options, and X-Content-Type-Options headers.',
    descriptionAr: 'التحقق من إلزام المتصفح بتشفير HTTPS ومنع وضع موقعك داخل إطار وهمي (iFrame) لسرقة نقرات المستخدمين.',
    method: 'HEAD',
    targetPath: '/',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Response must include: Strict-Transport-Security, X-Frame-Options: DENY, and X-Content-Type-Options: nosniff.',
    canaryExpectedOutcomeAr: 'يجب أن تحتوي ترويسات الاستجابة على HSTS و X-Frame-Options.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // 7. SSRF (SERVER-SIDE REQUEST FORGERY)
  {
    id: 'ssrf-01',
    category: 'ssrf',
    name: 'Cloud Metadata (AWS/GCP) SSRF Canary',
    nameAr: 'فحص منع الوصول لبيانات السحابة الداخلية (AWS 169.254.169.254)',
    description: 'Sends loopback and cloud metadata canary addresses to proxy/fetch endpoints to verify network boundary enforcement.',
    descriptionAr: 'محاكاة إرسال عنوان السحابة الداخلي (169.254.169.254) لفحص هل يمنع الخادم جلب بيانات السيرفر الحساسة.',
    method: 'POST',
    targetPath: '/api/proxy?url=http://169.254.169.254/latest/meta-data/',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data/' }, null, 2),
    canaryExpectedOutcome: 'Server must reject requests targeting private, link-local, or loopback IP ranges with HTTP 400 or 403.',
    canaryExpectedOutcomeAr: 'يجب على الخادم حظر أي طلب يوجه لشبكات السحابة الداخلية أو Localhost.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 8. IDOR / BOLA (BROKEN OBJECT LEVEL AUTH)
  {
    id: 'idor-01',
    category: 'idor',
    name: 'Object Identifier Tampering & Tenant Isolation',
    nameAr: 'فحص التلاعب بمعرف الكائنات وعزل الحسابات (IDOR / BOLA)',
    description: 'Probes resource endpoints with alternative or sequential identifiers to ensure session ownership checks exist.',
    descriptionAr: 'محاكاة التلاعب بمعرف المستخدم أو الطلب بالرابط للتأكد من أن الخادم يتحقق من ملكية الجلسة للبيانات.',
    method: 'GET',
    targetPath: '/api/users/1',
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'GET /api/users/1 HTTP/1.1\nAuthorization: Bearer <unprivileged_session_token>',
    canaryExpectedOutcome: 'Requests for records not owned by the current session must return HTTP 403 or 404.',
    canaryExpectedOutcomeAr: 'يجب رفض الوصول لأي سجل لا يملكه المستخدم الحالي برمز 403 أو 404.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 9. SENSITIVE FILES & GIT METADATA LEAKS
  {
    id: 'sensitive-01',
    category: 'sensitive_files',
    name: 'Exposed Environment (.env) & Secrets Audit',
    nameAr: 'فحص كشف ملفات المتغيرات السرية (.env & config)',
    description: 'Verifies that .env, .env.local, and server secrets cannot be downloaded directly over HTTP.',
    descriptionAr: 'التأكد من أن ملفات البيئة والمتغيرات السرية محجوبة تماماً ولا يمكن تنزيلها من المتصفح.',
    method: 'GET',
    targetPath: '/.env',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'GET /.env HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must return HTTP 404 or 403, never returning sensitive key-value pairs.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم 404 أو 403 ولا يسمح أبداً بعرض المفاتيح السرية.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-02',
    category: 'sensitive_files',
    name: 'Git Source Repository Exposure (.git/config)',
    nameAr: 'فحص كشف مستودع كود المصدر (.git/config)',
    description: 'Probes whether the version control directory is exposed, which allows attackers to rebuild source code.',
    descriptionAr: 'فحص هل مجلد التحكم بالإصدار .git مكشوف مما يتيح للمخترق تحميل الكود المصدري للموقع.',
    method: 'GET',
    targetPath: '/.git/config',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'GET /.git/config HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Must return HTTP 404 or 403 forbidden.',
    canaryExpectedOutcomeAr: 'يجب حجب مجلد Git بالكامل وإرجاع 404 أو 403.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // 10. RATE LIMITING & DOS RESILIENCE
  {
    id: 'ratelimit-01',
    category: 'rate_limiting',
    name: 'Burst Traffic Throttling & 429 Enforcement',
    nameAr: 'فحص الصمود أمام الفيضان البرمجي وتقييد المعدل (Rate Limiting 429)',
    description: 'Simulates rapid successive requests to sensitive routes to check if rate limiting is actively enforced.',
    descriptionAr: 'محاكاة إرسال طلبات متتالية سريعة لفحص هل يفعل الخادم رمز 429 Too Many Requests لحماية نفسه.',
    method: 'GET',
    targetPath: '/api/health',
    headers: {
      'User-Agent': 'SecuriPulse-Burst-Canary/3.0',
    },
    payloadCode: 'Burst probe: 10 parallel requests dispatched within 100ms window',
    canaryExpectedOutcome: 'Excessive request bursts should trigger HTTP 429 or response latency throttling.',
    canaryExpectedOutcomeAr: 'يجب أن يقوم السيرفر بتهدئة الطلبات المتسارعة وتفعيل Rate Limiting.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 11. OS COMMAND INJECTION CANARIES
  {
    id: 'cmd-01',
    category: 'cmd_injection',
    name: 'OS Command Separator & Pipe Canary',
    nameAr: 'فحص محارف تنفيذ أوامر النظام (| و ; و &&)',
    description: 'Sends benign separator characters into parameters to verify system shells are not invoked dynamically.',
    descriptionAr: 'إرسال محارف فصل الأوامر لفحص ما إذا كان الموقع يمرر المدخلات إلى طرفية السيرفر (Terminal).',
    method: 'GET',
    targetPath: '/api/ping?host=127.0.0.1%3B%20echo%20securipulse',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: '127.0.0.1; echo securipulse',
    canaryExpectedOutcome: 'Input must be strictly validated as an IP address; shell execution must never occur.',
    canaryExpectedOutcomeAr: 'يجب التحقق من صحة المدخلات كعنوان IP دون تشغيل طرفية النظام.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 12. CORS ORIGIN LEAKAGE & MISCONFIGURATION
  {
    id: 'cors-01',
    category: 'cors_leak',
    name: 'Untrusted Origin Reflection with Credentials',
    nameAr: 'فحص انعكاس النطاقات الخارجية المشبوهة في CORS',
    description: 'Tests whether an arbitrary attacker Origin header is reflected with Access-Control-Allow-Credentials: true.',
    descriptionAr: 'اختبار هل يقبل السيرفر أي موقع خارجي في ترويسة CORS مع السماح بنقل الكوكيز الحساسة.',
    method: 'OPTIONS',
    targetPath: '/api/user/data',
    headers: {
      'Origin': 'https://evil-untrusted-site.com',
      'Access-Control-Request-Method': 'POST',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'OPTIONS /api/user/data HTTP/1.1\nOrigin: https://evil-untrusted-site.com',
    canaryExpectedOutcome: 'Server must never reflect arbitrary untrusted origins when credentials are supported.',
    canaryExpectedOutcomeAr: 'يجب عدم قبول أي نطاق غريب أو السماح له بتبادل البيانات الحساسة.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 13. CSRF & STATE MUTATION PROTECTION
  {
    id: 'csrf-01',
    category: 'csrf',
    name: 'Cross-Site Request Forgery State Change Check',
    nameAr: 'فحص حماية طلبات تعديل البيانات من التزوير (CSRF Check)',
    description: 'Tests whether state-changing POST requests require anti-CSRF tokens or custom headers.',
    descriptionAr: 'فحص هل تتطلب طلبات POST الحساسة ترويسات مخصصة أو رموز حماية لمنع الهجمات الموجهة من مواقع أخرى.',
    method: 'POST',
    targetPath: '/api/user/update-status',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'action=status_update&canary=test',
    canaryExpectedOutcome: 'State mutations must validate origin/referrer or require a cryptographically signed anti-CSRF token.',
    canaryExpectedOutcomeAr: 'يجب التحقق من ترويسة Origin أو رمز الحماية في كل طلب تعديل.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 14. GRAPHQL INTROSPECTION & EXCESSIVE EXPOSURE
  {
    id: 'graphql-01',
    category: 'graphql',
    name: 'GraphQL Production Schema Introspection Audit',
    nameAr: 'فحص كشف مخططات GraphQL للعامة (Introspection Probe)',
    description: 'Sends a standard introspection query to check if the complete database schema is exposed in production.',
    descriptionAr: 'إرسال استعلام استكشافي لمعرفة هل يكشف GraphQL تفاصيل كل الجداول البرمجية والحقول للعامة.',
    method: 'POST',
    targetPath: '/api/graphql',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: JSON.stringify({ query: '{ __schema { types { name } } }' }),
    canaryExpectedOutcome: 'GraphQL schema introspection should be disabled in production environments.',
    canaryExpectedOutcomeAr: 'يجب إيقاف خاصية Introspection في بيئة الإنتاج لمنع استكشاف المخطط بالكامل.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 15. DIRECTORY & PATH TRAVERSAL
  {
    id: 'traversal-01',
    category: 'directory_traversal',
    name: 'Path Traversal Dot-Dot-Slash Canary Probe',
    nameAr: 'فحص القفز بين المجلدات في مسارات الملفات (Path Traversal ../)',
    description: 'Sends relative directory traversal sequences in download and asset paths to check boundary jail enforcement.',
    descriptionAr: 'محاكاة إرسال ../ في روابط عرض الملفات للتأكد من أن السيرفر يمنع الخروج من المجلد المصرح به.',
    method: 'GET',
    targetPath: '/api/download?file=..%2F..%2F..%2Fetc%2Fpasswd',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: 'GET /api/download?file=../../../etc/passwd HTTP/1.1\n',
    canaryExpectedOutcome: 'Server must normalize paths, prevent root escaping, and return HTTP 400 or 403.',
    canaryExpectedOutcomeAr: 'يجب تنظيف المسار ومنع الوصول للمجلدات العلوية من السيرفر.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // 16. MASS ASSIGNMENT & ROLE ESCALATION
  {
    id: 'mass-01',
    category: 'mass_assignment',
    name: 'Parameter Tampering & Privilege Escalation Canary',
    nameAr: 'فحص التعيين الجماعي للبيانات وتصعيد الصلاحيات (isAdmin: true)',
    description: 'Injects unauthorized privilege fields (isAdmin, role) into payload to verify strict schema DTO validation.',
    descriptionAr: 'إرسال خصائص إدارية غير مصرح بها أثناء تحديث البيانات لمعرفة هل يفلتر السيرفر المدخلات بدقة.',
    method: 'POST',
    targetPath: '/api/user/profile',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.0',
    },
    payloadCode: JSON.stringify({ name: 'Canary User', role: 'admin', isAdmin: true }, null, 2),
    canaryExpectedOutcome: 'Privilege properties must be stripped by strict validation schemas (e.g. Zod DTO).',
    canaryExpectedOutcomeAr: 'يجب على الخادم رفض أو تجاهل الحقول الإدارية واعتماد المدخلات المصرح بها فقط.',
    intensityLevel: 'standard',
    enabled: true,
  },
];

// ============================================================================
// BEGINNER-FRIENDLY CODE FIX RECIPES (COPIED IN 1-CLICK)
// ============================================================================
export const REMEDIATION_RECIPES = {
  headers: {
    titleAr: 'حل ترويسات الأمان في Next.js',
    titleEn: 'Next.js Security Headers Middleware Solution',
    fileName: 'middleware.ts',
    code: `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const response = NextResponse.next();

  // ترويسات الأمان القياسية الموصى بها عالمياً
  response.headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  return response;
}

export const config = {
  matcher: '/((?!api|_next/static|_next/image|favicon.ico).*)',
};`,
  },
  sqli: {
    titleAr: 'الحماية من حقن قواعد البيانات (استعلامات معيارية)',
    titleEn: 'Parameterized Queries Defense (Prisma / SQL)',
    fileName: 'src/lib/db.ts',
    code: `// ❌ خطأ فادح: الدمج المباشر للنصوص في الاستعلام
// const users = await db.query(\`SELECT * FROM users WHERE email = '\${userInput}'\`);

// ✅ الحل الصحيح: استخدام الاستعلام المعياري (Parameterized Query)
// في PostgreSQL / Node-PG:
const result = await db.query(
  'SELECT id, email, created_at FROM users WHERE email = $1',
  [userInput] // يتم عزل وتشفير القيمة تلقائياً دون تنفيذها كأمر
);

// أو باستخدام Prisma ORM (محمي تلقائياً):
const user = await prisma.user.findUnique({
  where: { email: userInput },
});`,
  },
  cors: {
    titleAr: 'ضبط سياسة CORS الآمنة للمواقع',
    titleEn: 'Secure CORS Configuration (Express / Next.js API)',
    fileName: 'src/app/api/cors.ts',
    code: `// قائمة النطاقات المسموح لها فقط بالوصول إلى واجهة موقعك
const ALLOWED_ORIGINS = [
  'https://yourdomain.com',
  'https://admin.yourdomain.com',
];

export function setCorsHeaders(origin: string | null) {
  const isAllowed = origin && ALLOWED_ORIGINS.includes(origin);
  
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}`,
  },
  xss: {
    titleAr: 'تطهير مدخلات المستخدمين لمنع XSS',
    titleEn: 'Input Sanitization with DOMPurify / React Escaping',
    fileName: 'src/lib/sanitize.ts',
    code: `import DOMPurify from 'isomorphic-dompurify';

// تطهير أي نص HTML يدخله المستخدم قبل عرضه في الصفحة
export function cleanUserInput(dirtyInput: string): string {
  return DOMPurify.sanitize(dirtyInput, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a'],
    ALLOWED_ATTR: ['href'],
  });
}

// في React: استخدم الأقواس العادية دائماً لأنها تشفر الرموز تلقائياً:
// <div>{userInput}</div> // ✅ آمن 100%
// ❌ تجنب استخدام: dangerouslySetInnerHTML دون تطهير`,
  },
  ssrf: {
    titleAr: 'الحماية من ثغرات SSRF وعزل الشبكة السحابية',
    titleEn: 'SSRF Boundary Defense & IP Whitelisting',
    fileName: 'src/lib/safe-fetch.ts',
    code: `import ipaddr from 'ipaddr.js';

export function isSafeUrl(targetUrl: string): boolean {
  try {
    const url = new URL(targetUrl);
    if (!['http:', 'https:'].includes(url.protocol)) return false;

    // حظر عناوين الـ Localhost والـ Cloud Metadata (169.254.169.254)
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '169.254.169.254') {
      return false;
    }

    if (ipaddr.isValid(url.hostname)) {
      const addr = ipaddr.parse(url.hostname);
      const range = addr.range();
      if (['private', 'loopback', 'linkLocal', 'carrierGradeNat'].includes(range)) {
        return false; // حظر أي شبكة داخلية
      }
    }

    return true;
  } catch {
    return false;
  }
}`,
  },
  rate_limiting: {
    titleAr: 'تفعيل تقييد معدل الطلبات (Rate Limiting)',
    titleEn: 'Rate Limiting Defense (Upstash Redis / Token Bucket)',
    fileName: 'src/lib/rate-limiter.ts',
    code: `import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(20, '10 s'), // 20 طلب لكل 10 ثوانٍ
  analytics: true,
});

export async function checkRateLimit(ip: string) {
  const { success, limit, remaining, reset } = await ratelimit.limit(ip);
  if (!success) {
    return new Response('Too Many Requests', {
      status: 429,
      headers: {
        'Retry-After': String(Math.ceil((reset - Date.now()) / 1000)),
      },
    });
  }
  return null;
}`,
  },
  mass_assignment: {
    titleAr: 'منع التعيين الجماعي عبر مخططات Zod الصارمة',
    titleEn: 'Mass Assignment Prevention with Zod DTO Validation',
    fileName: 'src/lib/validations/user.ts',
    code: `import { z } from 'zod';

// ✅ تحديد الحقول المصرح للمستخدم بتعديلها فقط وحجب isAdmin و role
export const UpdateProfileSchema = z.object({
  name: z.string().min(2).max(50),
  bio: z.string().max(200).optional(),
  avatarUrl: z.string().url().optional(),
}).strict(); // strict() ترفض أي حقل إضافي لم يتم تعريفه

export type UpdateProfileInput = z.infer<typeof UpdateProfileSchema>;`,
  },
  idor: {
    titleAr: 'سد ثغرات IDOR والتحقق من ملكية البيانات',
    titleEn: 'IDOR Prevention with Session Ownership Checks',
    fileName: 'src/app/api/orders/[id]/route.ts',
    code: `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { getServerSession } from 'next-auth';

export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });

  // ✅ التحقق دائماً من ملكية السجل: ID المطلوب + معرف المستخدم الحالي
  const order = await prisma.order.findFirst({
    where: {
      id: params.id,
      userId: session.user.id, // يمنع التلاعب والوصول لطلبات مستخدمين آخرين
    },
  });

  if (!order) return new Response('Not Found', { status: 404 });
  return NextResponse.json(order);
}`,
  },
};
