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
  nameAr: 'سيكيوريبلس - درع الأمان الشامل',
  version: '3.5.0',
  description: 'منصة محاكاة الهجمات الأمنية وفحص الثغرات التفاعلي الرسمي لأصحاب المواقع والمطورين',
  descriptionEn: 'Comprehensive Web & API Threat Simulation and Vulnerability Auditing Platform',
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
    labelAr: 'فحص مسالم (18 فحص سطحي)',
    labelEn: 'Gentle (18 Passive Checks)',
    descriptionAr: 'فحص الترويسات الدفاعية (HSTS, CSP, XFO)، تسريب الإصدارات (Server, X-Powered-By)، الكوكيز، وملفات التكوين الحساسة دون ضغط.',
    descriptionEn: 'Passive metadata analysis, HTTP security headers, cookie flags, and sensitive file checks with zero server strain.',
    badgeClass: 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/40',
    probesCount: 18,
    recommendedFor: 'المواقع الحية على الإنترنت والإنتاج (Production)',
  },
  standard: {
    labelAr: 'فحص قياسي (35 فحص متوازن)',
    labelEn: 'Standard (35 Balanced Audits)',
    descriptionAr: 'يشمل الفحص المسالم بالإضافة لاختبارات المصادقة (Auth, JWT)، سياسات CORS، تزوير السحابة (SSRF)، عزل الكائنات (IDOR)، وGraphQL.',
    descriptionEn: 'Comprehensive API authorization barrier tests, CORS policies, cloud SSRF isolation, IDOR, and GraphQL schema exposure.',
    badgeClass: 'bg-blue-950/60 text-blue-400 border border-blue-800/40',
    probesCount: 35,
    recommendedFor: 'بيئات الاختبار والمواقع التجريبية (Staging & Dev)',
  },
  rigorous: {
    labelAr: 'فحص احترافي كامل (42 فحص عميق)',
    labelEn: 'Rigorous (42 Full Suite Probes)',
    descriptionAr: 'الفحص الأمني الأقصى! يختبر كل صغيرة وكبيرة: حقن SQLi، انعكاس وسوم XSS، أوامر النظام (Command Injection)، والقفز في المجلدات (Traversal).',
    descriptionEn: 'Complete deep security audit testing edge-case injection canaries, rate limiting stress, traversal, and mass assignment.',
    badgeClass: 'bg-rose-950/60 text-rose-400 border border-rose-800/40',
    probesCount: 42,
    recommendedFor: 'الفحص الأمني الكامل واختبارات الجاهزية قبل الإطلاق (Pre-launch & Security Audits)',
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
  headers: {
    nameAr: 'ترويسات الحماية وسياسة الأمان (Security Headers)',
    nameEn: 'Security Headers & Policies',
    icon: 'ShieldCheck',
    shortDescAr: 'التحقق من ترويسات HSTS و CSP و X-Frame-Options و Referrer-Policy لمنع هجمات التضمين والنقر والتنصت',
    shortDescEn: 'Audits essential defensive HTTP headers preventing iframe clickjacking, MIME sniffing, and downgrade attacks',
  },
  sensitive_files: {
    nameAr: 'تسريب الملفات والنسخ (.env & .git)',
    nameEn: 'Sensitive Files & Git Leaks',
    icon: 'FileWarning',
    shortDescAr: 'فحص تسريب ملفات البيئة السرية ومستودعات Git والنسخ الاحتياطية ووثائق Swagger المتروكة',
    shortDescEn: 'Detects exposed sensitive files like .env, .git/config, swagger docs, and database backup dumps',
  },
  auth: {
    nameAr: 'كسر المصادقة والتحكم بالوصول (Broken Auth)',
    nameEn: 'Broken Authentication & Access Control',
    icon: 'KeyRound',
    shortDescAr: 'محاكاة إرسال طلبات بدون تصريح أو برؤوس JWT مزيفة للتأكد من حماية المسارات السرية والإدارية',
    shortDescEn: 'Audits endpoint protection against missing tokens, replay attacks, and token signature tampering',
  },
  cors_leak: {
    nameAr: 'تسريب سياسات النطاق المشترك (CORS Leakage)',
    nameEn: 'CORS Origin Misconfiguration',
    icon: 'Share2',
    shortDescAr: 'فحص هل يعكس السيرفر أي نطاق خارجي مع تفعيل ملفات تعريف الارتباط وبيانات الاعتماد',
    shortDescEn: 'Tests dangerous origin reflection allowing external web origins to steal private sessions',
  },
  sqli: {
    nameAr: 'حقن قواعد البيانات (SQLi)',
    nameEn: 'SQL Injection Canaries',
    icon: 'Database',
    shortDescAr: 'محاكاة إرسال رموز استعلام ملتوية لمعرفة هل يعالج الخادم المدخلات مباشرة بدون تشفير أو يسرب أخطاء',
    shortDescEn: 'Tests whether database queries safely sanitize inputs using parameterization and hide syntax errors',
  },
  xss: {
    nameAr: 'حقن النصوص البرمجية (XSS)',
    nameEn: 'Cross-Site Scripting (XSS)',
    icon: 'CodeXml',
    shortDescAr: 'إرسال وسوم نصية تجريبية للتأكد من قيام المتصفح بتنظيفها ومنع سرقة ملفات الارتباط (Cookies)',
    shortDescEn: 'Validates that user inputs are encoded and sanitized before rendering in DOM',
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
};

// ============================================================================
// THE FULL 42 COMPREHENSIVE SECURITY AUDIT PROBES (OFFICIAL SUITE)
// ============================================================================
export const INITIAL_PROBES: SecurityProbePayload[] = [
  // --- 1. HEADERS & HTTP DEFENSIVE POSTURE (GENTLE / PASSIVE) ---
  {
    id: 'headers-hsts',
    category: 'headers',
    name: 'Strict-Transport-Security (HSTS) Audit',
    nameAr: 'فحص ترويسة التشفير الإلزامي (HSTS Header)',
    description: 'Verifies presence of Strict-Transport-Security to ensure browsers always enforce HTTPS encryption.',
    descriptionAr: 'التحقق من وجود ترويسة HSTS لإلزام المتصفح بالاتصال المشفر ومنع هجمات التحويل لـ HTTP غير الآمن.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Response must include: Strict-Transport-Security with max-age >= 31536000.',
    canaryExpectedOutcomeAr: 'يجب أن تحتوي ترويسات الاستجابة على HSTS مع مدة لا تقل عن سنة.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-csp',
    category: 'headers',
    name: 'Content-Security-Policy (CSP) Inspection',
    nameAr: 'فحص سياسة أمان المحتوى (Content-Security-Policy)',
    description: 'Checks if Content-Security-Policy is present to mitigate Cross-Site Scripting (XSS) and unauthorized framing.',
    descriptionAr: 'التحقق من تفعيل سياسة CSP التي تحدد مصادر النصوص والسكربتات المسموح بتحميلها وتمنع تضمين الموقع بصفحات أخرى.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Response should contain Content-Security-Policy defining script-src and frame-ancestors.',
    canaryExpectedOutcomeAr: 'يجب أن يرسل الخادم ترويسة Content-Security-Policy لحماية المحتوى.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-xfo',
    category: 'headers',
    name: 'Clickjacking Protection (X-Frame-Options)',
    nameAr: 'فحص منع التضمين الخادع والنقر المضلل (X-Frame-Options)',
    description: 'Ensures X-Frame-Options is set to DENY or SAMEORIGIN to prevent invisible iframe clickjacking attacks.',
    descriptionAr: 'التأكد من منع فتح موقعك داخل إطار وهمي خفي بمواقع خارجية لخداع المستخدم وسرقة نقراته.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'X-Frame-Options must be set to DENY or SAMEORIGIN (or CSP frame-ancestors).',
    canaryExpectedOutcomeAr: 'يجب أن تكون قيمة X-Frame-Options مضبوطة على DENY أو SAMEORIGIN.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-xcto',
    category: 'headers',
    name: 'MIME Sniffing Prevention (X-Content-Type-Options)',
    nameAr: 'فحص منع التخمين الخاطئ لنوع المحتوى (nosniff)',
    description: 'Verifies X-Content-Type-Options: nosniff to stop browsers from executing non-executable files as scripts.',
    descriptionAr: 'التحقق من وجود ترويسة X-Content-Type-Options: nosniff لمنع المتصفح من تشغيل ملفات الصور أو النصوص كبرمجيات.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Response must include: X-Content-Type-Options: nosniff.',
    canaryExpectedOutcomeAr: 'يجب أن تتضمن الاستجابة ترويسة X-Content-Type-Options: nosniff.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-referrer',
    category: 'headers',
    name: 'Referrer-Policy Privacy & Leakage Audit',
    nameAr: 'فحص سياسة تسريب رابط الإحالة (Referrer-Policy)',
    description: 'Checks Referrer-Policy to prevent leaking sensitive query tokens or internal paths in the Referer header.',
    descriptionAr: 'التحقق من وجود Referrer-Policy لمنع إرسال الروابط الداخلية والرموز الحساسة للمواقع الخارجية عند النقر.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Referrer-Policy should be strict-origin-when-cross-origin, same-origin, or no-referrer.',
    canaryExpectedOutcomeAr: 'يجب ضبط Referrer-Policy على strict-origin-when-cross-origin كحد أدنى.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-permissions',
    category: 'headers',
    name: 'Hardware API Restrictions (Permissions-Policy)',
    nameAr: 'فحص تقييد صلاحيات العتاد والمستشعرات (Permissions-Policy)',
    description: 'Audits Permissions-Policy to ensure camera, microphone, and geolocation APIs cannot be abused by embedded third parties.',
    descriptionAr: 'فحص هل يقيد السيرفر استخدام الكاميرا والميكروفون والموقع الجغرافي لمنع السكربتات المضمنة من استغلالها.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Permissions-Policy should disable unused device hardware APIs (camera=(), microphone=()).',
    canaryExpectedOutcomeAr: 'يجب أن تحتوي ترويسة Permissions-Policy على تقييد للعتاد غير المستخدم.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-server-leak',
    category: 'headers',
    name: 'Server & Operating System Banner Disclosure',
    nameAr: 'فحص تسريب إصدار السيرفر ونظام التشغيل (Server Banner Leak)',
    description: 'Inspects Server header for disclosure of exact web server version numbers (e.g., nginx/1.18.0, Apache/2.4.41).',
    descriptionAr: 'فحص هل يسرّب الخادم رقم إصداره الدقيق (مثل Apache أو Nginx) مما يسهل على المهاجم استهداف الثغرات المعروفة لتلك النسخة.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server header should be generic or omitted without exposing detailed version numbers.',
    canaryExpectedOutcomeAr: 'يجب إخفاء رقم إصدار السيرفر أو تقليله لاسم عام دون تفاصيل.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-powered-by',
    category: 'headers',
    name: 'Application Framework Header Disclosure (X-Powered-By)',
    nameAr: 'فحص تسريب لغة البرمجة وإطار العمل (X-Powered-By Leak)',
    description: 'Detects X-Powered-By or X-AspNet-Version headers that disclose underlying backend frameworks (Express, PHP, Next.js).',
    descriptionAr: 'التحقق من عدم وجود ترويسة X-Powered-By التي تكشف إطار العمل مثل Express أو PHP لتقليل بصمة الهجوم.',
    method: 'HEAD',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'HEAD / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'X-Powered-By and framework signature headers should be completely removed.',
    canaryExpectedOutcomeAr: 'يجب حذف ترويسة X-Powered-By بالكامل من استجابات الخادم.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-cache-control',
    category: 'headers',
    name: 'Sensitive Route Cache-Control Posture',
    nameAr: 'فحص سياسة التخزين المؤقت للمسارات الخاصة (Cache-Control)',
    description: 'Verifies that API and user authentication endpoints specify no-store or no-cache to avoid proxy caching.',
    descriptionAr: 'فحص هل تمنع مسارات الـ API وسيطات التخزين المؤقت (Proxies) من تخزين بيانات المستخدمين الحساسة.',
    method: 'GET',
    targetPath: '/api/user',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5', 'Accept': 'application/json' },
    payloadCode: 'GET /api/user HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'API endpoints must return Cache-Control: no-store, no-cache, private.',
    canaryExpectedOutcomeAr: 'يجب أن تعيد مسارات الـ API ترويسة Cache-Control: no-store لمنع حفظ البيانات الحساسة.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'headers-cookie-security',
    category: 'headers',
    name: 'Session Cookie Security Flags (HttpOnly, Secure, SameSite)',
    nameAr: 'فحص حماية ملفات الارتباط (HttpOnly & Secure & SameSite)',
    description: 'Checks Set-Cookie headers for HttpOnly (XSS protection), Secure (HTTPS only), and SameSite attributes.',
    descriptionAr: 'التحقق من حماية الكوكيز بخصائص HttpOnly (لمنع قراءتها عبر جافاسكريبت) و Secure و SameSite.',
    method: 'GET',
    targetPath: '/',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET / HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'All session cookies must include HttpOnly, Secure, and SameSite=Lax/Strict flags.',
    canaryExpectedOutcomeAr: 'يجب أن تحتوي ملفات تعريف الارتباط على علامات HttpOnly و Secure و SameSite.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // --- 2. SENSITIVE FILES & CONFIGURATION DISCLOSURE (GENTLE / PASSIVE) ---
  {
    id: 'sensitive-01',
    category: 'sensitive_files',
    name: 'Exposed Environment Secrets File (/.env)',
    nameAr: 'فحص كشف ملف المتغيرات والبيئة السرية (/.env Exposure)',
    description: 'Verifies that .env configuration files cannot be downloaded directly over HTTP.',
    descriptionAr: 'التأكد من أن ملفات البيئة والمتغيرات السرية (.env) محجوبة تماماً ولا يمكن تنزيلها أو قراءتها.',
    method: 'GET',
    targetPath: '/.env',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /.env HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must return HTTP 404 or 403, never returning text/plain secret key-value pairs.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم 404 أو 403 ولا يسمح أبداً بعرض المفاتيح السرية.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-02',
    category: 'sensitive_files',
    name: 'Git Repository Metadata Disclosure (/.git/config)',
    nameAr: 'فحص كشف مستودع كود المصدر (/.git/config)',
    description: 'Probes whether the version control directory is exposed, allowing reconstruction of entire source code.',
    descriptionAr: 'فحص هل مجلد التحكم بالإصدار .git مكشوف مما يتيح للمخترق تحميل الكود المصدري للموقع بالكامل.',
    method: 'GET',
    targetPath: '/.git/config',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /.git/config HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Must return HTTP 404 or 403 forbidden.',
    canaryExpectedOutcomeAr: 'يجب حجب مجلد Git بالكامل وإرجاع 404 أو 403.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-03',
    category: 'sensitive_files',
    name: 'macOS Directory Metadata File Exposure (/.DS_Store)',
    nameAr: 'فحص تسريب ملفات الفهرسة لنظام ماك (/.DS_Store)',
    description: 'Checks for exposed .DS_Store files which reveal hidden directory names and private asset file structures.',
    descriptionAr: 'فحص هل ملف .DS_Store مكشوف للعامة مما يسرب أسماء المجلدات والملفات المخفية على السيرفر.',
    method: 'GET',
    targetPath: '/.DS_Store',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /.DS_Store HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must return 404 or 403, blocking binary directory store metadata.',
    canaryExpectedOutcomeAr: 'يجب حظر ملفات .DS_Store وإرجاع 404 أو 403.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-04',
    category: 'sensitive_files',
    name: 'Node.js Package Manifest Exposure (/package.json)',
    nameAr: 'فحص كشف ملف مكتبات واعتمادات المشروع (/package.json)',
    description: 'Detects if package.json is publicly readable, disclosing internal library versions with known CVEs.',
    descriptionAr: 'فحص هل ملف package.json متاح للعامة مما يكشف إصدارات المكتبات المستخدمة ويسهل استغلال ثغراتها.',
    method: 'GET',
    targetPath: '/package.json',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /package.json HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Should return HTTP 404 or 403; package manifests must remain outside public root.',
    canaryExpectedOutcomeAr: 'يجب ألا يكون ملف package.json في مجلد العرض العام للموقع.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-05',
    category: 'sensitive_files',
    name: 'Database Backup & SQL Dump Leakage (/backup.sql)',
    nameAr: 'فحص تسريب النسخ الاحتياطية لقواعد البيانات (/backup.sql)',
    description: 'Checks for common neglected database dump files (backup.sql, dump.sql, db.sql) in document root.',
    descriptionAr: 'فحص هل توجد نسخ احتياطية لقواعد البيانات متروكة بالخطأ في المسار العام للموقع.',
    method: 'GET',
    targetPath: '/backup.sql',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /backup.sql HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Must return 404 Not Found; database backups must never reside in web root.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد السيرفر 404 ولا يسمح بتنزيل ملفات النسخ الاحتياطي.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-06',
    category: 'sensitive_files',
    name: 'Container Blueprint Exposure (/Dockerfile)',
    nameAr: 'فحص كشف ملف بناء الحاوية السحابية (/Dockerfile)',
    description: 'Tests if Dockerfile or docker-compose.yml is served, exposing internal network topologies and base images.',
    descriptionAr: 'فحص هل ملف Dockerfile مكشوف مما يوضح تكوين السيرفر الداخلي والبرمجيات المجهزة.',
    method: 'GET',
    targetPath: '/Dockerfile',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /Dockerfile HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Must return HTTP 404; container specifications must not be publicly served.',
    canaryExpectedOutcomeAr: 'يجب حجب ملفات Docker وملفات إدارة الحاويات برمز 404.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-07',
    category: 'sensitive_files',
    name: 'RFC 9116 Vulnerability Disclosure Policy (/.well-known/security.txt)',
    nameAr: 'فحص وجود سياسة الإبلاغ الأمني الرسمية (security.txt)',
    description: 'Checks for standard security.txt policy defining contact points for ethical security researchers.',
    descriptionAr: 'التحقق من وجود ملف security.txt القياسي (RFC 9116) لتسهيل تواصل الباحثين الأمنيين عند اكتشاف ثغرات.',
    method: 'GET',
    targetPath: '/.well-known/security.txt',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /.well-known/security.txt HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Advisable to publish security.txt with security contact and policy instructions.',
    canaryExpectedOutcomeAr: 'يفضل وجود ملف security.txt في المسار القياسي لتوضيح قنوات التواصل الأمني.',
    intensityLevel: 'gentle',
    enabled: true,
  },
  {
    id: 'sensitive-08',
    category: 'sensitive_files',
    name: 'Robots.txt Sensitive Disallow Path Audit (/robots.txt)',
    nameAr: 'فحص مسارات الحظر الخاصة في ملف (/robots.txt)',
    description: 'Parses robots.txt to identify if sensitive private admin or staging directories are advertised to crawlers.',
    descriptionAr: 'فحص ملف robots.txt للتأكد من عدم كشف مسارات حساسة للمخترقين عبر بنود Disallow.',
    method: 'GET',
    targetPath: '/robots.txt',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /robots.txt HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'robots.txt should not disclose secret or unauthenticated administrative paths.',
    canaryExpectedOutcomeAr: 'يجب ألا يكشف ملف robots.txt مسارات الإدارة الحساسة التي تثير فضول المهاجمين.',
    intensityLevel: 'gentle',
    enabled: true,
  },

  // --- 3. AUTHENTICATION & ACCESS CONTROL (STANDARD AUDIT) ---
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
      'User-Agent': 'SecuriPulse-Auditor/3.5',
      'Accept': 'application/json',
    },
    payloadCode: 'GET /api/admin/users HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Server must immediately reject with HTTP 401 Unauthorized or 403 Forbidden.',
    canaryExpectedOutcomeAr: 'يجب أن يرفض الخادم الطلب فوراً برمز 401 أو 403 دون إظهار أي بيانات مستخدمين.',
    intensityLevel: 'standard',
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
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'Header: {"alg":"none","typ":"JWT"}\nPayload: {"sub":"canary-user","role":"admin"}',
    canaryExpectedOutcome: 'Token must be rejected as invalid signature (HTTP 401).',
    canaryExpectedOutcomeAr: 'يجب رفض الرمز فوراً لعدم وجود توقيع رقمي صالح.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'auth-03',
    category: 'auth',
    name: 'Administrative Portal Interface Discovery (/admin)',
    nameAr: 'فحص كشف بوابات ولوحات التحكم الإدارية (/admin)',
    description: 'Probes default admin login paths to verify they are either non-standard, IP-whitelisted, or MFA protected.',
    descriptionAr: 'فحص هل مسارات الإدارة الافتراضية مثل /admin مكشوفة بدون تقييد وصول أو تحقق ثنائي.',
    method: 'GET',
    targetPath: '/admin',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /admin HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Admin consoles should be isolated, require MFA, or return 404/403 to unauthorized IPs.',
    canaryExpectedOutcomeAr: 'يجب تقييد لوحة الإدارة بحماية قوية أو عزلها برقم IP موثوق.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'auth-04',
    category: 'auth',
    name: 'OpenAPI / Swagger Documentation Exposure (/api-docs)',
    nameAr: 'فحص كشف وثائق الـ API ومخططاتها للعامة (/api-docs)',
    description: 'Checks if interactive Swagger UI or OpenAPI specs are exposed in production, revealing internal API blueprints.',
    descriptionAr: 'فحص هل وثائق الـ Swagger التفاعلية متاحة لأي زائر مما يكشف كل مسارات ومعاملات السيرفر.',
    method: 'GET',
    targetPath: '/api-docs',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /api-docs HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'API documentation should be authenticated or restricted to development environments.',
    canaryExpectedOutcomeAr: 'يفضل حجب واجهات التوثيق التفاعلية في بيئة الإنتاج أو اشتراط تسجيل دخول.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'auth-05',
    category: 'auth',
    name: 'Invalid Bearer Token Rejection Enforcement',
    nameAr: 'فحص رفض رموز التصريح التالفة أو المنتهية (Malformed Token)',
    description: 'Sends a corrupted authorization token to verify backend returns proper 401 instead of crashing with 500.',
    descriptionAr: 'إرسال رمز تصريح غير صالح للتأكد من أن الخادم يعيد 401 بانسيابية ولا ينهار بخطأ 500 داخلي.',
    method: 'GET',
    targetPath: '/api/user/session',
    headers: {
      'Authorization': 'Bearer corrupted_test_token_securipulse',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'GET /api/user/session HTTP/1.1\nAuthorization: Bearer corrupted_test_token',
    canaryExpectedOutcome: 'Server must gracefully return HTTP 401 without unhandled internal exceptions.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد السيرفر 401 دون حدوث أخطاء استثناء داخلية.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 4. CORS ORIGIN LEAKAGE & MISCONFIGURATION (STANDARD) ---
  {
    id: 'cors-01',
    category: 'cors_leak',
    name: 'Untrusted Origin Reflection with Credentials',
    nameAr: 'فحص انعكاس النطاقات الخارجية المشبوهة في CORS مع الاعتماد',
    description: 'Tests whether an arbitrary attacker Origin header is reflected with Access-Control-Allow-Credentials: true.',
    descriptionAr: 'اختبار هل يقبل السيرفر أي موقع خارجي في ترويسة CORS مع السماح بنقل الكوكيز الحساسة.',
    method: 'OPTIONS',
    targetPath: '/api/user/data',
    headers: {
      'Origin': 'https://evil-untrusted-site.com',
      'Access-Control-Request-Method': 'POST',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'OPTIONS /api/user/data HTTP/1.1\nOrigin: https://evil-untrusted-site.com',
    canaryExpectedOutcome: 'Server must never reflect arbitrary untrusted origins when credentials are supported.',
    canaryExpectedOutcomeAr: 'يجب عدم قبول أي نطاق غريب أو السماح له بتبادل البيانات الحساسة.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'cors-02',
    category: 'cors_leak',
    name: 'Wildcard CORS Header on Sensitive API Endpoints',
    nameAr: 'فحص سياسة النجمة العامة (CORS: *) على مسارات الـ API',
    description: 'Verifies private APIs do not indiscriminately broadcast Access-Control-Allow-Origin: * to the world.',
    descriptionAr: 'التأكد من أن مسارات الـ API الخاصة لا ترسل علامة النجمة العامة (*) التي تتيح لأي موقع استدعاء الواجهة.',
    method: 'OPTIONS',
    targetPath: '/api/v1/auth',
    headers: {
      'Origin': 'https://random-third-party.com',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'OPTIONS /api/v1/auth HTTP/1.1\nOrigin: https://random-third-party.com',
    canaryExpectedOutcome: 'Private API endpoints must whitelist specific trusted origins, not wildcard (*).',
    canaryExpectedOutcomeAr: 'يجب تقييد مسارات البيانات بنطاق موقعك المحدد فقط.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 5. SERVER-SIDE REQUEST FORGERY (SSRF) ---
  {
    id: 'ssrf-01',
    category: 'ssrf',
    name: 'AWS / GCP Cloud Metadata Boundary Probe (169.254.169.254)',
    nameAr: 'فحص حماية بيانات السحابة الداخلية (AWS / GCP Metadata SSRF)',
    description: 'Sends cloud metadata IP (169.254.169.254) to proxy/redirect parameters to ensure cloud IAM keys cannot be stolen.',
    descriptionAr: 'محاكاة إرسال عنوان السحابة الداخلي (169.254.169.254) لفحص هل يمنع الخادم جلب بيانات السيرفر الحساسة ومفاتيح IAM.',
    method: 'POST',
    targetPath: '/api/proxy?url=http://169.254.169.254/latest/meta-data/',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: JSON.stringify({ targetUrl: 'http://169.254.169.254/latest/meta-data/' }, null, 2),
    canaryExpectedOutcome: 'Server must reject requests targeting private, link-local, or loopback IP ranges with HTTP 400 or 403.',
    canaryExpectedOutcomeAr: 'يجب على الخادم حظر أي طلب يوجه لشبكات السحابة الداخلية أو Localhost.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'ssrf-02',
    category: 'ssrf',
    name: 'Loopback Localhost Internal Probe (127.0.0.1)',
    nameAr: 'فحص حظر استدعاء الخدمات الداخلية على Localhost (127.0.0.1)',
    description: 'Tests whether fetch/webhook utilities can be tricked into communicating with internal services running on 127.0.0.1.',
    descriptionAr: 'فحص هل يمنع الخادم استدعاء خوادم وقواعد البيانات الداخلية العاملة على Localhost عبر الروابط المدخلة.',
    method: 'GET',
    targetPath: '/api/fetch?url=http://127.0.0.1:80/admin',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /api/fetch?url=http://127.0.0.1:80/admin HTTP/1.1\n',
    canaryExpectedOutcome: 'Localhost addresses must be strictly blocked by IP validation filters.',
    canaryExpectedOutcomeAr: 'يجب حظر عناوين Localhost تماماً بواسطة مرشحات فحص الـ IP.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 6. BROKEN OBJECT LEVEL AUTH (IDOR / BOLA) ---
  {
    id: 'idor-01',
    category: 'idor',
    name: 'Sequential User ID Tampering Check (/api/users/1)',
    nameAr: 'فحص التلاعب بالمعرفات الرقمية للحسابات (User ID Tampering)',
    description: 'Probes sequential user ID routes to ensure the backend verifies that the caller owns the requested resource.',
    descriptionAr: 'محاكاة تغيير رقم المستخدم بالرابط لفحص هل يتحقق الباك إند من ملكية الجلسة للبيانات قبل عرضها.',
    method: 'GET',
    targetPath: '/api/users/1',
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'GET /api/users/1 HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Accessing objects not owned by current session must return 401, 403, or 404.',
    canaryExpectedOutcomeAr: 'يجب رفض الوصول لأي سجل لا يملكه المستخدم الحالي برمز 401 أو 403.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'idor-02',
    category: 'idor',
    name: 'Cross-Tenant Resource Isolation Audit (/api/orders/1001)',
    nameAr: 'فحص عزل بيانات الطلبات بين المشتركين (Multi-Tenant Isolation)',
    description: 'Tests if order or invoice objects are isolated between accounts or queryable without tenant scoping.',
    descriptionAr: 'التأكد من أن سجلات الفواتير والطلبات معزولة بالكامل ولا يمكن استعراضها بتخمين أرقام المعرفات.',
    method: 'GET',
    targetPath: '/api/orders/1001',
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'GET /api/orders/1001 HTTP/1.1\nHost: target\n',
    canaryExpectedOutcome: 'Order objects must enforce tenant ownership checks.',
    canaryExpectedOutcomeAr: 'يجب عزل الطلبات حسب معرف المستخدم المصادق عليه.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 7. GRAPHQL INTROSPECTION & CSRF ---
  {
    id: 'graphql-01',
    category: 'graphql',
    name: 'GraphQL Production Schema Introspection Audit',
    nameAr: 'فحص كشف مخططات GraphQL للعامة (Introspection Probe)',
    description: 'Sends an introspection query to check if the complete database schema and mutations are exposed in production.',
    descriptionAr: 'إرسال استعلام استكشافي لمعرفة هل يكشف GraphQL تفاصيل كل الجداول البرمجية والحقول للعامة في بيئة الإنتاج.',
    method: 'POST',
    targetPath: '/api/graphql',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: JSON.stringify({ query: '{ __schema { types { name } } }' }),
    canaryExpectedOutcome: 'GraphQL schema introspection should be disabled in production environments.',
    canaryExpectedOutcomeAr: 'يجب إيقاف خاصية Introspection في بيئة الإنتاج لمنع استكشاف المخطط بالكامل.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'csrf-01',
    category: 'csrf',
    name: 'Cross-Site Request Forgery State Change Check',
    nameAr: 'فحص حماية طلبات تعديل البيانات من التزوير (CSRF Check)',
    description: 'Tests whether state-changing POST requests validate origin headers or require anti-CSRF tokens.',
    descriptionAr: 'فحص هل تتطلب طلبات POST الحساسة ترويسات مخصصة أو رموز حماية لمنع الهجمات الموجهة من مواقع أخرى.',
    method: 'POST',
    targetPath: '/api/user/update-status',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'SecuriPulse-Auditor/3.5',
    },
    payloadCode: 'action=status_update&canary=test',
    canaryExpectedOutcome: 'State mutations must validate origin/referrer or require a cryptographically signed anti-CSRF token.',
    canaryExpectedOutcomeAr: 'يجب التحقق من ترويسة Origin أو رمز الحماية في كل طلب تعديل.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 8. RATE LIMITING & DOS RESILIENCE ---
  {
    id: 'rate-01',
    category: 'rate_limiting',
    name: 'Burst Traffic Throttling & 429 Enforcement',
    nameAr: 'فحص الصمود أمام الفيضان البرمجي وتقييد المعدل (Rate Limiting 429)',
    description: 'Simulates rapid successive requests to sensitive routes to check if rate limiting is actively enforced.',
    descriptionAr: 'محاكاة إرسال طلبات متتالية سريعة لفحص هل يفعل الخادم رمز 429 Too Many Requests لحماية نفسه.',
    method: 'GET',
    targetPath: '/api/health',
    headers: { 'User-Agent': 'SecuriPulse-Burst-Canary/3.5' },
    payloadCode: 'Burst probe: 10 parallel requests dispatched within 100ms window',
    canaryExpectedOutcome: 'Excessive request bursts should trigger HTTP 429 or response latency throttling.',
    canaryExpectedOutcomeAr: 'يجب أن يقوم السيرفر بتهدئة الطلبات المتسارعة وتفعيل Rate Limiting.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'rate-02',
    category: 'rate_limiting',
    name: 'Authentication Brute-Force Rate Limiting Audit',
    nameAr: 'فحص حماية مسار تسجيل الدخول من محاولات التخمين (Brute-Force Limit)',
    description: 'Checks whether login and token endpoints throttle repeated failed authorization attempts.',
    descriptionAr: 'التأكد من أن واجهات الدخول تقيد المحاولات المتكررة وتمنع هجمات التخمين الآلي لكلمات المرور.',
    method: 'POST',
    targetPath: '/api/v1/auth/login',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Burst-Canary/3.5',
    },
    payloadCode: JSON.stringify({ email: 'probe@canary.local', password: 'test' }),
    canaryExpectedOutcome: 'Login endpoints must enforce lockout or velocity limiting per IP.',
    canaryExpectedOutcomeAr: 'يجب قفل الحساب مؤقتاً أو تفعيل رمز 429 عند تكرار المحاولات الفاشلة.',
    intensityLevel: 'standard',
    enabled: true,
  },

  // --- 9. SQL INJECTION (SQLI) CANARIES (RIGOROUS) ---
  {
    id: 'sqli-01',
    category: 'sqli',
    name: 'SQL Boolean Tautology Canary Probe',
    nameAr: 'اختبار الحشو المنطقي لقواعد البيانات (Tautology 1=1)',
    description: 'Sends a benign tautological condition to verify if query sanitization handles quotes cleanly.',
    descriptionAr: 'يرسل شرطاً منطقياً بديهياً لفحص ما إذا كان استعلام قاعدة البيانات يدمج النصوص دون عزل (Sanitization).',
    method: 'GET',
    targetPath: '/api/search?q=%27%20OR%201%3D1%20--',
    headers: {
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.5',
      'Accept': 'application/json, text/html',
    },
    payloadCode: "' OR 1=1 --",
    canaryExpectedOutcome: 'Server must treat input as literal text, never alter query logic or return unescaped database errors.',
    canaryExpectedOutcomeAr: 'يجب على الخادم معاملة النص ككلمة بحث عادية، وعدم تغيير هيكل الاستعلام أو إظهار خطأ SQL.',
    intensityLevel: 'rigorous',
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
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.5',
    },
    payloadCode: JSON.stringify({ email: "admin'\"", password: "test" }, null, 2),
    canaryExpectedOutcome: 'Server must return generic 400/401 response without disclosing PostgreSQL, MySQL, or SQLite syntax traces.',
    canaryExpectedOutcomeAr: 'يجب أن يعيد الخادم رسالة عامة "بيانات غير صالحة" دون ذكر أي تفاصيل برمجية داخلية.',
    intensityLevel: 'rigorous',
    enabled: true,
  },
  {
    id: 'sqli-03',
    category: 'sqli',
    name: 'SQL Clause & Order-By Injection Canary',
    nameAr: 'فحص حقن جمل الترتيب والفرز (Order-By Clause Injection)',
    description: 'Tests if sorting parameters (sort, order) are concatenated directly into raw database queries.',
    descriptionAr: 'فحص ما إذا كانت متغيرات الترتيب والفرز في الرابط تدمج مباشرة في استعلام قاعدة البيانات.',
    method: 'GET',
    targetPath: '/api/items?sort=id%20DESC%3B--',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'id DESC;--',
    canaryExpectedOutcome: 'Order by values must be validated against a strict whitelist of allowed column names.',
    canaryExpectedOutcomeAr: 'يجب التحقق من أسماء الأعمدة في مصفوفة بيضاء محددة مسبقاً.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- 10. CROSS-SITE SCRIPTING (XSS) CANARIES (RIGOROUS) ---
  {
    id: 'xss-01',
    category: 'xss',
    name: 'Reflected Script Tag Canary Probe',
    nameAr: 'فحص انعكاس وسوم الجافاسكريبت (Reflected Script Tag)',
    description: 'Tests if user inputs in URL parameters are reflected back raw into HTML without HTML entity escaping.',
    descriptionAr: 'فحص ما إذا كانت متغيرات الرابط تظهر كما هي في الصفحة بدون تشفير الكيانات (HTML Escaping).',
    method: 'GET',
    targetPath: '/?ref=%3Cscript%3Econsole.log(%22securipulse_canary%22)%3C%2Fscript%3E',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: '<script>console.log("securipulse_canary")</script>',
    canaryExpectedOutcome: 'Output must be safely entity-encoded (&lt;script&gt;) or blocked by Content-Security-Policy.',
    canaryExpectedOutcomeAr: 'يجب تحويل الأقواس لرموز نصية آمنة لمنع المتصفح من تشغيل الكود.',
    intensityLevel: 'rigorous',
    enabled: true,
  },
  {
    id: 'xss-02',
    category: 'xss',
    name: 'HTML Attribute Event-Handler Injection',
    nameAr: 'فحص حقن أحداث المتصفح في الوسوم (Attribute Event Injection)',
    description: 'Sends an image tag with an onerror handler to verify attribute context sanitization.',
    descriptionAr: 'محاكاة إرسال وسم صورة مع معالج خطأ لاختبار هل يتم تفريغ الأحداث التنفيذية في الحقول.',
    method: 'POST',
    targetPath: '/api/feedback',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.5',
    },
    payloadCode: JSON.stringify({ comment: '<img src=x onerror=void(0)>' }, null, 2),
    canaryExpectedOutcome: 'Attributes like onerror, onclick must be stripped by sanitization library (e.g. DOMPurify).',
    canaryExpectedOutcomeAr: 'يجب حذف الأحداث التنفيذية بواسطة مكتبة تنظيف موثوقة.',
    intensityLevel: 'rigorous',
    enabled: true,
  },
  {
    id: 'xss-03',
    category: 'xss',
    name: 'JavaScript Pseudo-Protocol URI Injection (javascript:)',
    nameAr: 'فحص بروتوكول جافاسكريبت في الروابط (javascript: URI Scheme)',
    description: 'Tests if redirect or link href parameters accept dangerous javascript: execution strings.',
    descriptionAr: 'فحص هل تقبل روابط التحويل أو وسوم <a> بادئة javascript: التي تتيح تشغيل كود خبيث عند الضغط.',
    method: 'GET',
    targetPath: '/?redirect=javascript%3Avoid(0)',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'javascript:void(0)',
    canaryExpectedOutcome: 'Protocols must be restricted strictly to http: and https:.',
    canaryExpectedOutcomeAr: 'يجب حصر البروتوكولات المقبولة في الروابط على https: فقط.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- 11. OS COMMAND INJECTION CANARIES (RIGOROUS) ---
  {
    id: 'cmd-01',
    category: 'cmd_injection',
    name: 'OS Command Separator & Semicolon Canary (;)',
    nameAr: 'فحص محارف تنفيذ أوامر النظام بالفاصلة المنقوطة (;)',
    description: 'Sends command separator characters into parameters to verify system shells are not invoked dynamically.',
    descriptionAr: 'إرسال محارف فصل الأوامر لفحص ما إذا كان الموقع يمرر المدخلات إلى طرفية السيرفر (Terminal).',
    method: 'GET',
    targetPath: '/api/ping?host=127.0.0.1%3B%20echo%20securipulse',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: '127.0.0.1; echo securipulse',
    canaryExpectedOutcome: 'Input must be strictly validated as an IP address; shell execution must never occur.',
    canaryExpectedOutcomeAr: 'يجب التحقق من صحة المدخلات كعنوان IP دون تشغيل طرفية النظام.',
    intensityLevel: 'rigorous',
    enabled: true,
  },
  {
    id: 'cmd-02',
    category: 'cmd_injection',
    name: 'OS Command Pipe Character Canary (|)',
    nameAr: 'فحص توجيه الأوامر التنفيذية عبر الأنبوب (| Pipe)',
    description: 'Checks if pipe characters in parameters trigger background shell pipelines or command execution.',
    descriptionAr: 'فحص هل تمرر المدخلات لأمر نظام عبر محرف الأنبوب (|) مما يتيح تشغيل برمجيات خبيثة.',
    method: 'GET',
    targetPath: '/api/dns?domain=example.com%7Cecho%20securipulse',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'example.com|echo securipulse',
    canaryExpectedOutcome: 'Input must be validated strictly against hostname regex without shell evaluation.',
    canaryExpectedOutcomeAr: 'يجب مطابقة النطاق مع نمط نصي آمن دون استدعاء طرفية النظام.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- 12. DIRECTORY & PATH TRAVERSAL (RIGOROUS) ---
  {
    id: 'traversal-01',
    category: 'directory_traversal',
    name: 'Linux System File Dot-Dot-Slash Canary (/etc/passwd)',
    nameAr: 'فحص القفز خارج مجلد الملفات (Path Traversal /etc/passwd)',
    description: 'Sends relative directory traversal sequences in download and asset paths to check boundary jail enforcement.',
    descriptionAr: 'محاكاة إرسال ../ في روابط عرض الملفات للتأكد من أن السيرفر يمنع الخروج من المجلد المصرح به.',
    method: 'GET',
    targetPath: '/api/download?file=..%2F..%2F..%2Fetc%2Fpasswd',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'GET /api/download?file=../../../etc/passwd HTTP/1.1\n',
    canaryExpectedOutcome: 'Server must normalize paths, prevent root escaping, and return HTTP 400 or 403.',
    canaryExpectedOutcomeAr: 'يجب تنظيف المسار ومنع الوصول للمجلدات العلوية من السيرفر.',
    intensityLevel: 'rigorous',
    enabled: true,
  },
  {
    id: 'traversal-02',
    category: 'directory_traversal',
    name: 'Windows System File Traversal Canary (win.ini)',
    nameAr: 'فحص تخطي المجلدات على بيئات ويندوز (win.ini Traversal)',
    description: 'Tests if asset handlers accept dot-dot-slash patterns targeting common Windows system files.',
    descriptionAr: 'فحص مسارات الملفات الثابتة للتأكد من عدم فتح ملفات التكوين لنظام التشغيل ويندوز.',
    method: 'GET',
    targetPath: '/static/%2e%2e/%2e%2e/windows/win.ini',
    headers: { 'User-Agent': 'SecuriPulse-Auditor/3.5' },
    payloadCode: 'GET /static/../../windows/win.ini HTTP/1.1\n',
    canaryExpectedOutcome: 'Web server must block relative dot-dot-slash navigation outside the static directory.',
    canaryExpectedOutcomeAr: 'يجب أن يحظر السيرفر مسارات النقطتين المائلتين .. خارج مجلد الملفات الثابتة.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- 13. MASS ASSIGNMENT & ROLE ESCALATION (RIGOROUS) ---
  {
    id: 'mass-01',
    category: 'mass_assignment',
    name: 'Parameter Tampering & Privilege Escalation (isAdmin: true)',
    nameAr: 'فحص التعيين الجماعي للبيانات وتصعيد الصلاحيات (isAdmin: true)',
    description: 'Injects unauthorized privilege fields (isAdmin, role) into payload to verify strict schema DTO validation.',
    descriptionAr: 'إرسال خصائص إدارية غير مصرح بها أثناء تحديث البيانات لمعرفة هل يفلتر السيرفر المدخلات بدقة.',
    method: 'POST',
    targetPath: '/api/user/profile',
    headers: {
      'Content-Type': 'application/json',
      'User-Agent': 'SecuriPulse-Canary-Auditor/3.5',
    },
    payloadCode: JSON.stringify({ name: 'Canary User', role: 'admin', isAdmin: true }, null, 2),
    canaryExpectedOutcome: 'Privilege properties must be stripped by strict validation schemas (e.g. Zod DTO).',
    canaryExpectedOutcomeAr: 'يجب على الخادم رفض أو تجاهل الحقول الإدارية واعتماد المدخلات المصرح بها فقط.',
    intensityLevel: 'rigorous',
    enabled: true,
  },

  // --- 14. OPEN PORTS & SUBDOMAIN (STANDARD) ---
  {
    id: 'ports-01',
    category: 'ports',
    name: 'Exposed PostgreSQL Database Port Audit (:5432)',
    nameAr: 'فحص منافذ قواعد البيانات المباشرة (Postgres 5432)',
    description: 'Simulates safe banner checking on port 5432 to verify database is not exposed to the public internet.',
    descriptionAr: 'فحص هل قاعدة بيانات بوستجرس مكشوفة برقم IP العام دون جدار ناري وعزل VPC.',
    method: 'HEAD',
    targetPath: ':5432',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'TCP SYN Canary Probe to Port 5432 (PostgreSQL)',
    canaryExpectedOutcome: 'Database ports should never be exposed to the public internet; only accessible via private VPC.',
    canaryExpectedOutcomeAr: 'يجب أن تكون منافذ قواعد البيانات مغلقة عن الإنترنت العام ومحصورة بالشبكة الداخلية.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'ports-02',
    category: 'ports',
    name: 'Exposed Redis In-Memory Cache Port Audit (:6379)',
    nameAr: 'فحص منفذ خادم الذاكرة السريعة (Redis 6379)',
    description: 'Checks whether port 6379 is accessible externally, which often lacks authentication and leads to RCE.',
    descriptionAr: 'فحص هل منفذ ريديس 6379 مفتوح للعامة مما قد يتيح قراءة الجلسات أو كتابة ملفات على السيرفر.',
    method: 'HEAD',
    targetPath: ':6379',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'TCP SYN Canary Probe to Port 6379 (Redis)',
    canaryExpectedOutcome: 'Redis port must be firewalled and restricted to private VPC localhost network.',
    canaryExpectedOutcomeAr: 'يجب إغلاق منفذ Redis عن الإنترنت العام وتأمينه بكلمة مرور معقدة.',
    intensityLevel: 'standard',
    enabled: true,
  },
  {
    id: 'subdomain-01',
    category: 'subdomain',
    name: 'Dangling CNAME & Orphaned Cloud Resource Audit',
    nameAr: 'فحص سجلات CNAME المعلقة ومضيفات السحابة المهجورة',
    description: 'Audits DNS canonical name mappings for orphaned targets on AWS S3, Vercel, GitHub Pages, or Heroku.',
    descriptionAr: 'التأكد من أن النطاقات الفرعية لا تشير إلى خدمات سحابية تم حذفها مما يتيح للغير حجزها باسمك.',
    method: 'GET',
    targetPath: '/dns-hygiene-audit',
    headers: { 'User-Agent': 'SecuriPulse-Canary-Auditor/3.5' },
    payloadCode: 'DNS Query: CNAME record verification & NXDOMAIN error check',
    canaryExpectedOutcome: 'No CNAME records pointing to unclaimed resources with NXDOMAIN status.',
    canaryExpectedOutcomeAr: 'عدم وجود سجلات توجه لمشاريع محذوفة تتيح للغرباء السيطرة على دومينك الفرعي.',
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
  response.headers.delete('x-powered-by');

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
