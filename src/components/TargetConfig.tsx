'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React from 'react';
import {
  GlobalOutlined,
  SlidersOutlined,
  ThunderboltOutlined,
  PlayCircleOutlined,
  StopOutlined,
  CodeOutlined,
  DatabaseOutlined,
  KeyOutlined,
  CloudServerOutlined,
  SafetyCertificateOutlined,
  ClusterOutlined,
  FieldTimeOutlined,
  ApiOutlined,
  LockOutlined,
  FileTextOutlined,
  DesktopOutlined,
  ShareAltOutlined,
  SafetyOutlined,
  FolderOpenOutlined,
  ControlOutlined,
  CheckOutlined,
  SettingOutlined,
  CheckSquareOutlined,
  BorderOutlined,
} from '@ant-design/icons';
import {
  AttackIntensity,
  DiscoveredEndpoint,
  VulnerabilityCategory,
} from '@/types/security';
import { INTENSITY_PROFILES, CATEGORY_METADATA } from '@/lib/constants';
import EndpointDiscoveryPanel from './EndpointDiscoveryPanel';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const PRESET_URLS = [
  { labelAr: 'أكاديمية فلسطين الدولية', labelEn: 'Palestine Academy', url: 'https://palestine-international-academy.netlify.app' },
  { labelAr: 'تطبيق تاسك فلو', labelEn: 'TaskFlow App', url: 'https://taskflow.apps.taqat.academy' },
  { labelAr: 'بوابة سيو الذكية', labelEn: 'SEO Opt Portal', url: 'https://seo-opt.apps.taqat.academy' },
];

const STYLES = {
  container: 'space-y-5',
  omnibar: 'rounded-xl border border-[#303030] bg-[#141414] p-4 sm:p-5 space-y-3.5',
  bentoCard: 'rounded-xl border border-[#303030] bg-[#141414] p-4 sm:p-5 space-y-4',
  input:
    'w-full rounded-lg border border-[#303030] bg-[#1f1f1f] px-4 py-2.5 text-sm text-white placeholder-[#595959] focus:border-[#1677ff] focus:outline-none font-mono transition-colors',
  primaryLaunchBtn:
    'w-full sm:w-auto px-6 py-2.5 rounded-lg font-bold text-sm text-white bg-[#1677ff] hover:bg-[#4096ff] transition-all flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 select-none shadow-sm',
  abortBtn:
    'w-full sm:w-auto px-6 py-2.5 rounded-lg font-bold text-sm text-white bg-[#ff4d4f] hover:bg-[#ff7875] transition-all flex items-center justify-center gap-2 cursor-pointer select-none shadow-sm',
  presetChip:
    'text-xs px-3 py-1.5 rounded-md bg-[#1f1f1f] text-[#d9d9d9] hover:bg-[#262626] hover:text-[#1677ff] border border-[#303030] transition-colors cursor-pointer select-none flex items-center gap-1.5',
  vectorItem:
    'p-3 rounded-lg border flex items-center justify-between cursor-pointer select-none transition-all gap-2 text-start',
  subSectionHeader:
    'text-xs font-semibold text-[#8c8c8c] flex items-center justify-between pt-1 pb-0.5',
};

const VECTOR_GROUPS: {
  id: string;
  titleAr: string;
  badgeEn: string;
  categories: VulnerabilityCategory[];
}[] = [
  {
    id: 'injection',
    titleAr: 'حقن الأكواد وقواعد البيانات',
    badgeEn: 'Injection Canaries',
    categories: ['sqli', 'xss', 'cmd_injection', 'directory_traversal'],
  },
  {
    id: 'auth_access',
    titleAr: 'المصادقة والتحكم بالوصول',
    badgeEn: 'Auth & Access Control',
    categories: ['auth', 'idor', 'mass_assignment'],
  },
  {
    id: 'perimeter_network',
    titleAr: 'الشبكة والجدران النارية والترويسات',
    badgeEn: 'Network & Perimeter',
    categories: ['ssrf', 'headers', 'ports', 'cors_leak', 'csrf'],
  },
  {
    id: 'recon_leaks',
    titleAr: 'تسريب البيانات الحساسة والبنية التحتية',
    badgeEn: 'Data Leaks & Recon',
    categories: ['sensitive_files', 'graphql', 'rate_limiting', 'subdomain'],
  },
];

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface TargetConfigProps {
  targetUrl: string;
  onTargetUrlChange: (url: string) => void;
  apiBaseUrl: string;
  onApiBaseUrlChange: (url: string) => void;
  endpoints: DiscoveredEndpoint[];
  onEndpointsChange: (updated: DiscoveredEndpoint[]) => void;
  intensity: AttackIntensity;
  onIntensityChange: (level: AttackIntensity) => void;
  concurrency: number;
  onConcurrencyChange: (threads: number) => void;
  delayMs: number;
  onDelayMsChange: (delay: number) => void;
  enabledCategories: Record<VulnerabilityCategory, boolean>;
  onToggleCategory: (cat: VulnerabilityCategory) => void;
  onOpenInspector: () => void;
  onStartAudit: () => void;
  onAbortAudit: () => void;
  isRunning: boolean;
  lang: 'ar' | 'en';
}

// ============================================================================
// 4. HELPER COMPONENTS (ZONE 4)
// ============================================================================
function getCategoryIcon(cat: VulnerabilityCategory) {
  switch (cat) {
    case 'sqli':
      return <DatabaseOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'xss':
      return <CodeOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'auth':
      return <KeyOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'ports':
      return <CloudServerOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'subdomain':
      return <GlobalOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'headers':
      return <SafetyCertificateOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'ssrf':
      return <ApiOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'idor':
      return <LockOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'sensitive_files':
      return <FileTextOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'rate_limiting':
      return <FieldTimeOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'cmd_injection':
      return <DesktopOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'cors_leak':
      return <ShareAltOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'csrf':
      return <SafetyOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'graphql':
      return <ClusterOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'directory_traversal':
      return <FolderOpenOutlined className="text-sm text-[#1677ff] shrink-0" />;
    case 'mass_assignment':
    default:
      return <ControlOutlined className="text-sm text-[#1677ff] shrink-0" />;
  }
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function TargetConfig({
  targetUrl,
  onTargetUrlChange,
  apiBaseUrl,
  onApiBaseUrlChange,
  endpoints,
  onEndpointsChange,
  intensity,
  onIntensityChange,
  concurrency,
  onConcurrencyChange,
  delayMs,
  onDelayMsChange,
  enabledCategories,
  onToggleCategory,
  onOpenInspector,
  onStartAudit,
  onAbortAudit,
  isRunning,
  lang,
}: TargetConfigProps) {
  const isArabic = lang === 'ar';

  const totalEnabled = Object.values(enabledCategories).filter(Boolean).length;
  const isAllEnabled = totalEnabled === 16;

  function handleToggleAll(enable: boolean) {
    const allCategories: VulnerabilityCategory[] = [
      'sqli', 'xss', 'auth', 'ports', 'subdomain', 'headers', 'ssrf', 'idor',
      'sensitive_files', 'rate_limiting', 'cmd_injection', 'cors_leak',
      'csrf', 'graphql', 'directory_traversal', 'mass_assignment',
    ];
    allCategories.forEach((cat) => {
      if (enabledCategories[cat] !== enable) {
        onToggleCategory(cat);
      }
    });
  }

  return (
    <div className={STYLES.container}>
      {/* ===================================================================== */}
      {/* 1. MASTER OMNIBAR                                                     */}
      {/* ===================================================================== */}
      <div className={STYLES.omnibar}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-[#1677ff]" />
            <span className="text-xs font-bold text-white tracking-wide">
              {isArabic ? 'رابط الموقع أو الواجهة المستهدفة للفحص' : 'Target Application URL'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#52c41a]" />
            <span className="text-xs font-mono text-[#52c41a]">
              {isArabic ? 'جاهز لمحاكاة الهجمات (42 فحص حقيقي)' : 'Telemetry Armed (42 Probes)'}
            </span>
          </div>
        </div>

        {/* Input Bar + Direct Launch Action */}
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <div className="absolute inset-y-0 start-0 flex items-center ps-3.5 pointer-events-none text-[#8c8c8c]">
              <GlobalOutlined className="text-sm" />
            </div>
            <input
              type="text"
              value={targetUrl}
              onChange={(e) => onTargetUrlChange(e.target.value)}
              placeholder="https://your-app.com"
              disabled={isRunning}
              className={`${STYLES.input} ps-10`}
              dir="ltr"
            />
          </div>

          {/* Action Trigger Button */}
          {isRunning ? (
            <button
              type="button"
              onClick={onAbortAudit}
              className={STYLES.abortBtn}
            >
              <StopOutlined className="text-base" />
              <span>{isArabic ? 'إيقاف الفحص المباشر' : 'Abort Attack Stream'}</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartAudit}
              disabled={!targetUrl.trim()}
              className={STYLES.primaryLaunchBtn}
            >
              <PlayCircleOutlined className="text-base" />
              <span>{isArabic ? 'شن الهجوم وفحص الأمان' : 'Launch Threat Audit'}</span>
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-[#111d2c] border border-[#153450] text-[#69b1ff]">
                42 Probes
              </span>
            </button>
          )}
        </div>

        {/* Preset suggestions */}
        <div className="flex items-center gap-2 flex-wrap pt-0.5">
          <span className="text-xs text-[#8c8c8c]">
            {isArabic ? 'أهداف سريعة للتجربة:' : 'Quick targets:'}
          </span>
          {PRESET_URLS.map((item) => (
            <button
              key={item.url}
              type="button"
              onClick={() => onTargetUrlChange(item.url)}
              disabled={isRunning}
              className={STYLES.presetChip}
            >
              <span className="text-white font-medium">
                {isArabic ? item.labelAr : item.labelEn}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* ===================================================================== */}
      {/* 2. BENTO WORKSPACE                                                    */}
      {/* ===================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* =================================================================== */}
        {/* RIGHT/MAIN COLUMN (7 COLS): SECURITY VECTORS MATRIX & API DISCOVERY */}
        {/* =================================================================== */}
        <div className="lg:col-span-7 space-y-5">
          {/* Attack Vectors Matrix Card */}
          <div className={STYLES.bentoCard}>
            <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-[#262626]">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff]">
                  <SlidersOutlined className="text-sm" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white flex items-center gap-2">
                    <span>{isArabic ? 'نطاقات الهجوم الأمنية' : 'Defensive Attack Vectors'}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#1f1f1f] text-[#d9d9d9] border border-[#303030]">
                      {totalEnabled} / 16 {isArabic ? 'مفعل' : 'Active'}
                    </span>
                  </h3>
                  <p className="text-[11px] text-[#8c8c8c]">
                    {isArabic
                      ? 'حدد النطاقات المستهدفة بالهجوم التلقائي والمحاكاة'
                      : 'Configure the active attack vector payloads to simulate'}
                  </p>
                </div>
              </div>

              {/* Quick Select All / Clear All */}
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => handleToggleAll(true)}
                  disabled={isRunning || isAllEnabled}
                  className="px-2.5 py-1 rounded text-xs bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] border border-[#303030] transition-colors cursor-pointer disabled:opacity-40"
                >
                  <CheckSquareOutlined className="me-1 text-xs text-[#52c41a]" />
                  <span>{isArabic ? 'تحديد الكل' : 'Select All'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleToggleAll(false)}
                  disabled={isRunning || totalEnabled === 0}
                  className="px-2.5 py-1 rounded text-xs bg-[#1f1f1f] hover:bg-[#262626] text-[#8c8c8c] hover:text-white border border-[#303030] transition-colors cursor-pointer disabled:opacity-40"
                >
                  <BorderOutlined className="me-1 text-xs" />
                  <span>{isArabic ? 'إلغاء التحديد' : 'Clear'}</span>
                </button>
              </div>
            </div>

            {/* Categorized Vector Groups */}
            <div className="space-y-4">
              {VECTOR_GROUPS.map((group) => (
                <div key={group.id} className="space-y-2">
                  <div className={STYLES.subSectionHeader}>
                    <span className="text-white font-medium">{group.titleAr}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#1f1f1f] text-[#8c8c8c] border border-[#303030]">
                      {group.badgeEn}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {group.categories.map((cat) => {
                      const meta = CATEGORY_METADATA[cat];
                      const isEnabled = enabledCategories[cat];

                      return (
                        <button
                          key={cat}
                          type="button"
                          onClick={() => onToggleCategory(cat)}
                          disabled={isRunning}
                          className={`${STYLES.vectorItem} ${
                            isEnabled
                              ? 'bg-[#1f1f1f] border-[#1677ff] text-white'
                              : 'bg-[#161616] border-[#262626] text-[#8c8c8c] hover:text-[#d9d9d9] hover:border-[#383838]'
                          }`}
                        >
                          <div className="flex items-center gap-2.5 min-w-0 flex-1">
                            {getCategoryIcon(cat)}
                            <div className="text-start leading-tight">
                              <span className="text-xs font-medium block text-white">
                                {isArabic ? meta.nameAr : meta.nameEn}
                              </span>
                            </div>
                          </div>

                          <div
                            className={`w-4 h-4 rounded border flex items-center justify-center shrink-0 transition-colors ${
                              isEnabled
                                ? 'bg-[#1677ff] border-[#1677ff] text-white'
                                : 'border-[#434343] bg-transparent'
                            }`}
                          >
                            {isEnabled && <CheckOutlined className="text-[10px]" />}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Embedded Real API & Endpoint Discovery Engine */}
          <EndpointDiscoveryPanel
            targetUrl={targetUrl}
            apiBaseUrl={apiBaseUrl}
            onApiBaseUrlChange={onApiBaseUrlChange}
            endpoints={endpoints}
            onEndpointsChange={onEndpointsChange}
            lang={lang}
            isRunning={isRunning}
          />
        </div>

        {/* =================================================================== */}
        {/* SIDEBAR COLUMN (5 COLS): ATTACK PROFILE, PACING & INSPECTOR         */}
        {/* =================================================================== */}
        <div className="lg:col-span-5 space-y-5">
          {/* Card 1: Attack Intensity Profile (Gentle, Standard, Rigorous) */}
          <div className={STYLES.bentoCard}>
            <div className="flex items-center justify-between pb-2 border-b border-[#262626]">
              <div className="flex items-center gap-2">
                <ThunderboltOutlined className="text-sm text-[#1677ff]" />
                <h3 className="text-xs font-bold text-white">
                  {isArabic ? 'مستوى شدة الهجوم' : 'Attack Intensity Profile'}
                </h3>
              </div>
              <span className="text-[11px] font-mono text-[#8c8c8c]">
                {INTENSITY_PROFILES[intensity].probesCount} Probes
              </span>
            </div>

            <div className="space-y-2.5">
              {(['gentle', 'standard', 'rigorous'] as AttackIntensity[]).map((level) => {
                const profile = INTENSITY_PROFILES[level];
                const isSelected = intensity === level;

                return (
                  <button
                    key={level}
                    type="button"
                    onClick={() => onIntensityChange(level)}
                    disabled={isRunning}
                    className={`w-full p-3 rounded-lg border text-start transition-all cursor-pointer flex flex-col gap-1 ${
                      isSelected
                        ? 'bg-[#111d2c] border-[#1677ff] text-white'
                        : 'bg-[#181818] border-[#262626] text-[#8c8c8c] hover:border-[#383838] hover:text-[#d9d9d9]'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="text-xs font-semibold text-white flex items-center gap-2">
                        <span>{isArabic ? profile.labelAr : profile.labelEn}</span>
                        {isSelected && (
                          <span className="w-1.5 h-1.5 rounded-full bg-[#1677ff]" />
                        )}
                      </span>
                      <span className="text-[10px] px-2 py-0.5 rounded font-mono bg-[#141414] border border-[#303030] text-[#d9d9d9]">
                        {profile.probesCount} {isArabic ? 'فحص' : 'probes'}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#8c8c8c] leading-relaxed">
                      {isArabic ? profile.descriptionAr : profile.descriptionEn}
                    </p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Card 2: Concurrency & Delay (Tactile Engine Controls) */}
          <div className={STYLES.bentoCard}>
            <div className="flex items-center justify-between pb-2 border-b border-[#262626]">
              <div className="flex items-center gap-2">
                <ClusterOutlined className="text-sm text-[#1677ff]" />
                <h3 className="text-xs font-bold text-white">
                  {isArabic ? 'المحاكاة والتزامن والسرعة' : 'Concurrency & Pacing'}
                </h3>
              </div>
              <span className="text-[11px] font-mono text-[#52c41a]">
                ● WAF Evasion
              </span>
            </div>

            {/* Concurrency Selector */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#8c8c8c]">
                  {isArabic ? 'الهجمات المتوازية (Threads):' : 'Parallel Threads:'}
                </span>
                <span className="font-mono text-xs font-semibold text-[#1677ff] bg-[#111d2c] px-2 py-0.5 rounded border border-[#153450]">
                  {concurrency}x Concurrency
                </span>
              </div>
              <div className="grid grid-cols-4 gap-1.5 bg-[#181818] p-1 rounded-lg border border-[#262626]">
                {[1, 2, 4, 8].map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => onConcurrencyChange(t)}
                    disabled={isRunning}
                    className={`py-1.5 rounded text-xs font-mono font-medium transition-all cursor-pointer ${
                      concurrency === t
                        ? 'bg-[#1677ff] text-white font-bold'
                        : 'text-[#8c8c8c] hover:text-white'
                    }`}
                  >
                    {t}x
                  </button>
                ))}
              </div>
            </div>

            {/* Pacing Delay Selector */}
            <div className="space-y-2 pt-1">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#8c8c8c]">
                  {isArabic ? 'فترة التهدئة بين الحزم (Delay):' : 'Packet Delay:'}
                </span>
                <span className="font-mono text-xs font-semibold text-[#faad14] bg-[#2b2111] px-2 py-0.5 rounded border border-[#594214]">
                  {delayMs} ms
                </span>
              </div>
              <div className="grid grid-cols-4 gap-1.5 bg-[#181818] p-1 rounded-lg border border-[#262626]">
                {[
                  { val: 0, label: '0ms' },
                  { val: 50, label: '50ms' },
                  { val: 150, label: '150ms' },
                  { val: 350, label: '350ms' },
                ].map((p) => (
                  <button
                    key={p.val}
                    type="button"
                    onClick={() => onDelayMsChange(p.val)}
                    disabled={isRunning}
                    className={`py-1.5 rounded text-xs font-mono font-medium transition-all cursor-pointer ${
                      delayMs === p.val
                        ? 'bg-[#1677ff] text-white font-bold'
                        : 'text-[#8c8c8c] hover:text-white'
                    }`}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Card 3: Custom Probes Inspector Trigger */}
          <div className="rounded-xl border border-[#303030] bg-[#141414] p-4 flex items-center justify-between">
            <div className="space-y-0.5">
              <span className="text-xs font-bold text-white block">
                {isArabic ? 'محرر الحمولات والـ Payloads' : 'Payloads & Canaries'}
              </span>
              <p className="text-[11px] text-[#8c8c8c]">
                {isArabic ? 'معاينة وتعديل الـ 42 فحص يدوي' : 'Inspect and edit custom probes'}
              </p>
            </div>
            <button
              type="button"
              onClick={onOpenInspector}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] hover:text-white border border-[#303030] transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <SettingOutlined className="text-xs text-[#1677ff]" />
              <span>{isArabic ? 'فتح المحرر' : 'Inspector'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
