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
  'https://taskflow.apps.taqat.academy',
  'https://palestine-international-academy.netlify.app',
  'https://seo-opt.apps.taqat.academy',
];

const STYLES = {
  card: 'rounded-[8px] border border-[#303030] bg-[#141414] p-5 space-y-5',
  input:
    'w-full rounded-[6px] border border-[#303030] bg-[#1f1f1f] px-3.5 py-2 text-sm text-white placeholder-[#595959] focus:border-[#1677ff] focus:outline-none font-mono transition-colors',
  intensityButton:
    'p-3 rounded-[6px] border text-start transition-all flex flex-col gap-1 cursor-pointer',
  vectorBadge:
    'p-2.5 rounded-[6px] border flex items-center justify-between cursor-pointer select-none transition-all',
  primaryLaunchBtn:
    'w-full py-2.5 px-5 rounded-[6px] font-medium text-sm text-white bg-[#1677ff] hover:bg-[#4096ff] transition-all flex items-center justify-center gap-2 disabled:opacity-50 cursor-pointer',
  abortBtn:
    'w-full py-2.5 px-5 rounded-[6px] font-medium text-sm text-white bg-[#ff4d4f] hover:bg-[#ff7875] transition-all flex items-center justify-center gap-2 cursor-pointer',
};

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

  const categoryList: VulnerabilityCategory[] = [
    'sqli',
    'xss',
    'auth',
    'ports',
    'subdomain',
    'headers',
  ];

  const getCategoryIcon = (cat: VulnerabilityCategory) => {
    switch (cat) {
      case 'sqli':
        return <DatabaseOutlined className="text-sm text-[#1677ff]" />;
      case 'xss':
        return <CodeOutlined className="text-sm text-[#1677ff]" />;
      case 'auth':
        return <KeyOutlined className="text-sm text-[#1677ff]" />;
      case 'ports':
        return <CloudServerOutlined className="text-sm text-[#1677ff]" />;
      case 'subdomain':
        return <GlobalOutlined className="text-sm text-[#1677ff]" />;
      case 'headers':
      default:
        return <SafetyCertificateOutlined className="text-sm text-[#1677ff]" />;
    }
  };

  return (
    <div className={STYLES.card}>
      {/* Section 1: Target Web URL */}
      <div className="space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <label className="text-xs font-semibold text-white flex items-center gap-2">
            <GlobalOutlined className="text-sm text-[#1677ff]" />
            <span>
              {isArabic
                ? 'رابط الموقع أو الواجهة المستهدفة (Target Web URL):'
                : 'Target Website or Web App URL:'}
            </span>
          </label>
          <span className="text-[11px] font-mono text-[#52c41a] flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-[#52c41a]" />
            <span>{isArabic ? 'جاهز للفحص الشبكي المباشر' : 'Live Network Ready'}</span>
          </span>
        </div>

        <div className="relative">
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => onTargetUrlChange(e.target.value)}
            placeholder="https://example.com"
            disabled={isRunning}
            className={STYLES.input}
            dir="ltr"
          />
        </div>

        {/* Preset suggestions */}
        <div className="flex items-center gap-2 flex-wrap pt-0.5">
          <span className="text-[11px] text-[#8c8c8c]">
            {isArabic ? 'أهداف سريعة للتجربة:' : 'Sample targets:'}
          </span>
          {PRESET_URLS.map((url) => (
            <button
              key={url}
              type="button"
              onClick={() => onTargetUrlChange(url)}
              disabled={isRunning}
              className="text-[11px] font-mono px-2.5 py-1 rounded bg-[#1f1f1f] text-[#d9d9d9] hover:bg-[#262626] hover:text-[#1677ff] border border-[#303030] transition-colors cursor-pointer"
            >
              {url.replace('https://', '')}
            </button>
          ))}
        </div>
      </div>

      {/* Section 1.5: Automated API & Endpoint Discovery Panel */}
      <EndpointDiscoveryPanel
        targetUrl={targetUrl}
        apiBaseUrl={apiBaseUrl}
        onApiBaseUrlChange={onApiBaseUrlChange}
        endpoints={endpoints}
        onEndpointsChange={onEndpointsChange}
        lang={lang}
        isRunning={isRunning}
      />

      {/* Section 2: Attack Intensity (ضعيف / وسط / صعب) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-white flex items-center gap-2">
            <ThunderboltOutlined className="text-sm text-[#1677ff]" />
            <span>
              {isArabic ? 'مستوى صعوبة وشدة الهجوم:' : 'Attack Intensity Profile:'}
            </span>
          </label>
          <span className="text-[11px] text-[#8c8c8c]">
            {isArabic ? 'حدد حسب بيئة موقعك' : 'Choose based on target environment'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(['gentle', 'standard', 'rigorous'] as AttackIntensity[]).map((level) => {
            const profile = INTENSITY_PROFILES[level];
            const isSelected = intensity === level;

            return (
              <button
                key={level}
                type="button"
                onClick={() => onIntensityChange(level)}
                disabled={isRunning}
                className={`${STYLES.intensityButton} ${
                  isSelected
                    ? 'bg-[#111d2c] border-[#1677ff] text-white'
                    : 'bg-[#1f1f1f] border-[#303030] text-[#8c8c8c] hover:border-[#434343] hover:text-[#d9d9d9]'
                }`}
              >
                <div className="flex items-center justify-between w-full">
                  <span className="text-xs font-semibold text-white">
                    {isArabic ? profile.labelAr : profile.labelEn}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded font-mono bg-[#141414] border border-[#303030] text-[#d9d9d9]">
                    {profile.probesCount} {isArabic ? 'فحص' : 'probes'}
                  </span>
                </div>
                <p className="text-[11px] text-[#8c8c8c] text-start leading-relaxed mt-1">
                  {isArabic ? profile.descriptionAr : profile.descriptionEn}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Section 3: Concurrency & Delay (Tactile Ant Design Segmented Controls) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Concurrency Segmented */}
        <div className="p-4 rounded-lg bg-[#1f1f1f] border border-[#303030] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#d9d9d9] flex items-center gap-1.5">
              <ClusterOutlined className="text-xs text-[#1677ff]" />
              <span>
                {isArabic ? 'الهجمات المتزامنة (Concurrency):' : 'Concurrent Workers:'}
              </span>
            </span>
            <span className="font-mono text-xs font-medium text-[#1677ff] bg-[#111d2c] px-2 py-0.5 rounded border border-[#153450]">
              {concurrency} {isArabic ? 'خيوط متوازية' : 'threads'}
            </span>
          </div>

          <div className="flex items-center gap-1.5 bg-[#141414] p-1 rounded-lg border border-[#303030]">
            {[1, 2, 4, 8].map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => onConcurrencyChange(t)}
                disabled={isRunning}
                className={`flex-1 py-1 rounded text-xs font-mono font-medium transition-all cursor-pointer ${
                  concurrency === t
                    ? 'bg-[#1677ff] text-white font-semibold'
                    : 'text-[#8c8c8c] hover:text-white'
                }`}
              >
                {t}x
              </button>
            ))}
          </div>
          <p className="text-[10.5px] text-[#8c8c8c]">
            {isArabic
              ? 'توزيع حزم الهجوم عبر عدة مسارات لتسريع الفحص واختبار صمود السيرفر.'
              : 'Parallelize probe requests across multiple asynchronous threads.'}
          </p>
        </div>

        {/* Pacing Delay Segmented */}
        <div className="p-4 rounded-lg bg-[#1f1f1f] border border-[#303030] space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-[#d9d9d9] flex items-center gap-1.5">
              <FieldTimeOutlined className="text-xs text-[#1677ff]" />
              <span>
                {isArabic ? 'فترة التهدئة (Pacing Delay):' : 'Request Delay:'}
              </span>
            </span>
            <span className="font-mono text-xs font-medium text-[#faad14] bg-[#2b2111] px-2 py-0.5 rounded border border-[#594214]">
              {delayMs} ms
            </span>
          </div>

          <div className="flex items-center gap-1.5 bg-[#141414] p-1 rounded-lg border border-[#303030]">
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
                className={`flex-1 py-1 rounded text-xs font-mono font-medium transition-all cursor-pointer ${
                  delayMs === p.val
                    ? 'bg-[#1677ff] text-white font-semibold'
                    : 'text-[#8c8c8c] hover:text-white'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
          <p className="text-[10.5px] text-[#8c8c8c]">
            {isArabic
              ? 'تحديد فترة زمنية بين الطلبات لتجنب حظر الـ Rate Limiting بجدار الحماية.'
              : 'Add interval spacing between packets to bypass sensitive rate limiters.'}
          </p>
        </div>
      </div>

      {/* Section 4: Vulnerability Modules Toggles */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold text-white flex items-center gap-2">
            <SlidersOutlined className="text-sm text-[#1677ff]" />
            <span>
              {isArabic ? 'النطاقات الأمنية المشمولة بالهجوم:' : 'Included Attack Vectors:'}
            </span>
          </label>
          <span className="text-[11px] font-mono text-[#8c8c8c]">
            {Object.values(enabledCategories).filter(Boolean).length} / 6{' '}
            {isArabic ? 'نطاقات مفعلة' : 'Active'}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2.5">
          {categoryList.map((cat) => {
            const meta = CATEGORY_METADATA[cat];
            const isEnabled = enabledCategories[cat];

            return (
              <button
                key={cat}
                type="button"
                onClick={() => onToggleCategory(cat)}
                disabled={isRunning}
                className={`${STYLES.vectorBadge} ${
                  isEnabled
                    ? 'bg-[#1f1f1f] border-[#1677ff] text-white'
                    : 'bg-[#181818] border-[#303030] text-[#8c8c8c] hover:text-[#d9d9d9]'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  {getCategoryIcon(cat)}
                  <span className="text-xs font-medium text-start">
                    {isArabic ? meta.nameAr : meta.nameEn}
                  </span>
                </div>
                <div
                  className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${
                    isEnabled
                      ? 'border-[#1677ff] bg-[#1677ff] text-white'
                      : 'border-[#434343] bg-transparent'
                  }`}
                >
                  {isEnabled && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Section 5: Pre-Attack Code Inspection & Launch Bar */}
      <div className="flex flex-col sm:flex-row items-center gap-3 pt-3 border-t border-[#303030]">
        <button
          type="button"
          onClick={onOpenInspector}
          disabled={isRunning}
          className="w-full sm:w-auto px-4 py-2.5 rounded-lg border border-[#303030] bg-[#1f1f1f] hover:bg-[#262626] text-[#d9d9d9] hover:text-white text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer shrink-0"
        >
          <CodeOutlined className="text-xs text-[#1677ff]" />
          <span>
            {isArabic
              ? 'معاينة وتعديل الأكواد المُرسلة قبل الهجوم'
              : 'Inspect & Edit Payloads Before Attack'}
          </span>
        </button>

        <div className="flex-1 w-full">
          {isRunning ? (
            <button
              type="button"
              onClick={onAbortAudit}
              className={STYLES.abortBtn}
            >
              <StopOutlined className="text-sm" />
              <span>{isArabic ? 'إيقاف الهجوم فوراً' : 'Abort Simulation'}</span>
            </button>
          ) : (
            <button
              type="button"
              onClick={onStartAudit}
              className={STYLES.primaryLaunchBtn}
            >
              <PlayCircleOutlined className="text-base" />
              <span>
                {isArabic
                  ? 'شن الهجوم وفحص أمان الموقع والنهايات المكتشفة'
                  : 'Launch Real Attack & Audit Discovered Endpoints'}
              </span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
