'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  ApiOutlined,
  SearchOutlined,
  LinkOutlined,
  PlusOutlined,
  DeleteOutlined,
  CheckCircleOutlined,
  InfoCircleOutlined,
  DownOutlined,
  UpOutlined,
  ThunderboltOutlined,
  DatabaseOutlined,
} from '@ant-design/icons';
import { DiscoveredEndpoint, EndpointDiscoveryResult, ApiArchitecture } from '@/types/security';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const STYLES = {
  card: 'rounded-[8px] border border-[#303030] bg-[#141414] p-4 sm:p-5 space-y-4',
  input:
    'w-full rounded-[6px] border border-[#303030] bg-[#1f1f1f] px-3.5 py-2 text-xs text-white placeholder-[#595959] focus:border-[#1677ff] focus:outline-none font-mono transition-colors',
  methodPill:
    'px-2 py-0.5 rounded-[4px] font-mono text-[10px] font-bold uppercase border',
  discoverBtn:
    'px-3.5 py-2 rounded-[6px] font-medium text-xs text-white bg-[#1677ff] hover:bg-[#4096ff] transition-all flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-50',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface EndpointDiscoveryPanelProps {
  targetUrl: string;
  apiBaseUrl: string;
  onApiBaseUrlChange: (url: string) => void;
  endpoints: DiscoveredEndpoint[];
  onEndpointsChange: (updated: DiscoveredEndpoint[]) => void;
  lang: 'ar' | 'en';
  isRunning: boolean;
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function EndpointDiscoveryPanel({
  targetUrl,
  apiBaseUrl,
  onApiBaseUrlChange,
  endpoints,
  onEndpointsChange,
  lang,
  isRunning,
}: EndpointDiscoveryPanelProps) {
  const isArabic = lang === 'ar';
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [newPath, setNewPath] = useState('');
  const [newMethod, setNewMethod] = useState<'GET' | 'POST'>('GET');
  const [discoveryStatus, setDiscoveryStatus] = useState<{
    architecture: ApiArchitecture;
    crawledScripts: number;
    discoveredCount: number;
    apiBaseUrl?: string;
    messageAr: string;
    messageEn: string;
  } | null>(null);

  async function handleAutoDiscover() {
    if (!targetUrl.trim()) return;
    setIsDiscovering(true);

    try {
      const response = await fetch('/api/discover', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetUrl }),
      });

      const data = await response.json();
      if (data.success && data.discovery) {
        const res: EndpointDiscoveryResult = data.discovery;

        if (res.apiArchitecture === 'supabase_baas' && res.detectedApiBaseUrl) {
          onApiBaseUrlChange(res.detectedApiBaseUrl);
          setDiscoveryStatus({
            architecture: 'supabase_baas',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            apiBaseUrl: res.detectedApiBaseUrl,
            messageAr: `تم كشف معمارية Supabase سحابية (BaaS) للموقع! تم رصد خادم قواعد البيانات (${res.detectedApiBaseUrl}) واستخراج جداول البيانات والمسارات الحقيقية (${res.endpoints.length}) لفحص أمان الجداول (RLS) وحماية البيانات الحساسة.`,
            messageEn: `Detected Supabase Backend-as-a-Service (BaaS) architecture! Connected to database (${res.detectedApiBaseUrl}) and extracted ${res.endpoints.length} data tables and routes for Row-Level Security auditing.`,
          });
        } else if (res.apiArchitecture === 'co_located_serverless') {
          const resolvedApi = res.detectedApiBaseUrl || targetUrl;
          onApiBaseUrlChange(resolvedApi);
          setDiscoveryStatus({
            architecture: 'co_located_serverless',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            apiBaseUrl: resolvedApi,
            messageAr: `تم اكتشاف معمارية مدمجة عند الطلب (Next.js / On-Demand Serverless Routes) على نفس الموقع! تم رصد (${res.endpoints.length}) مساراً برمجياً جاهزاً للاختبار ومحاكاة الطلبات.`,
            messageEn: `Detected Co-located Serverless Architecture (Next.js / On-Demand Routes) on same host. Staged ${res.endpoints.length} endpoints for testing.`,
          });
        } else if (res.apiArchitecture === 'external_backend' && res.detectedApiBaseUrl) {
          onApiBaseUrlChange(res.detectedApiBaseUrl);
          setDiscoveryStatus({
            architecture: 'external_backend',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            apiBaseUrl: res.detectedApiBaseUrl,
            messageAr: `تم التحقق بنجاح! تم رصد خادم API خارجي مستقل (${res.detectedApiBaseUrl}) واكتشاف (${res.endpoints.length}) مسار.`,
            messageEn: `Verified! Active external API server detected (${res.detectedApiBaseUrl}) with ${res.endpoints.length} endpoints.`,
          });
        } else {
          // Frontend only
          onApiBaseUrlChange('');
          setDiscoveryStatus({
            architecture: 'frontend_only',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            messageAr: `الموقع يعمل كواجهة أمامية مباشرة (بدون مسارات API مكتشفة). سيتم تركيز الفحص على ترويسات الأمان وملفات التكوين الحساسة وسياسات CORS وعزل النطاق.`,
            messageEn: `Pure frontend without detected API endpoints. Audit will focus on security headers, .env files, and CORS isolation.`,
          });
        }

        onEndpointsChange(res.endpoints);
        setIsExpanded(true);
      }
    } catch {
      alert(
        isArabic
          ? 'تعذر استكشاف المسارات تلقائياً، يرجى التأكد من أن الرابط متاح على الإنترنت.'
          : 'Could not auto-discover endpoints. Ensure host is reachable.'
      );
    } finally {
      setIsDiscovering(false);
    }
  }

  function handleToggleEndpoint(id: string) {
    onEndpointsChange(
      endpoints.map((ep) => (ep.id === id ? { ...ep, selected: !ep.selected } : ep))
    );
  }

  function handleAddCustomEndpoint(e: React.FormEvent) {
    e.preventDefault();
    if (!newPath.trim()) return;

    const formattedPath = newPath.startsWith('/') ? newPath.trim() : `/${newPath.trim()}`;
    const newEp: DiscoveredEndpoint = {
      id: `custom-${Date.now()}`,
      path: formattedPath,
      method: newMethod,
      source: 'user_defined',
      tested: false,
      selected: true,
      description: 'Custom developer endpoint',
    };

    onEndpointsChange([newEp, ...endpoints]);
    setNewPath('');
  }

  function handleDeleteEndpoint(id: string) {
    onEndpointsChange(endpoints.filter((ep) => ep.id !== id));
  }

  function handleSelectAll(selected: boolean) {
    onEndpointsChange(endpoints.map((ep) => ({ ...ep, selected })));
  }

  const selectedCount = endpoints.filter((e) => e.selected).length;

  return (
    <div className={STYLES.card}>
      {/* Top Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff]">
            <ApiOutlined className="text-sm" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-white flex items-center gap-2">
              <span>
                {isArabic
                  ? 'مُستكشف مسارات الـ API والنهايات الحقيقية'
                  : 'Automated API & Endpoint Discovery Engine'}
              </span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#1f1f1f] text-[#8c8c8c] border border-[#303030]">
                {endpoints.length} {isArabic ? 'مسار' : 'routes'}
              </span>
            </h3>
            <p className="text-[11px] text-[#8c8c8c]">
              {isArabic
                ? 'يفحص كود الجافاسكريبت الفعلي ويتحقق هل يوجد خادم API حقيقي يعمل على النطاق'
                : 'Scans real JavaScript bundles and verifies if an active backend API exists on target'}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleAutoDiscover}
            disabled={isDiscovering || isRunning || !targetUrl.trim()}
            className={STYLES.discoverBtn}
          >
            <SearchOutlined className={`text-xs ${isDiscovering ? 'animate-spin' : ''}`} />
            <span>
              {isDiscovering
                ? isArabic
                  ? 'جاري فحص ملفات الـ JS...'
                  : 'Scanning Bundles...'
                : isArabic
                ? 'استكشاف الـ API تلقائياً'
                : 'Auto-Discover Endpoints'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1.5 rounded-lg bg-[#1f1f1f] hover:bg-[#262626] text-[#8c8c8c] hover:text-white border border-[#303030] transition-colors cursor-pointer"
          >
            {isExpanded ? <UpOutlined className="text-xs" /> : <DownOutlined className="text-xs" />}
          </button>
        </div>
      </div>

      {/* Discovery Status Notice */}
      {discoveryStatus && (
        <div
          className={`p-3 rounded-lg border text-xs flex flex-col gap-2 ${
            discoveryStatus.architecture === 'supabase_baas'
              ? 'bg-[#162312] border-[#274916] text-[#b7eb8f]'
              : discoveryStatus.architecture === 'co_located_serverless'
              ? 'bg-[#111d2c] border-[#153450] text-[#91caff]'
              : discoveryStatus.architecture === 'external_backend'
              ? 'bg-[#111d2c] border-[#153450] text-[#91caff]'
              : 'bg-[#1f1f1f] border-[#303030] text-[#d9d9d9]'
          }`}
        >
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              {discoveryStatus.architecture === 'supabase_baas' ? (
                <DatabaseOutlined className="text-[#52c41a]" />
              ) : (
                <ThunderboltOutlined className="text-[#1677ff]" />
              )}
              <span className="font-semibold text-[11px] px-2 py-0.5 rounded border bg-black/40 border-current">
                {discoveryStatus.architecture === 'supabase_baas'
                  ? isArabic
                    ? 'قواعد بيانات سحابية (Supabase BaaS)'
                    : 'Supabase Cloud BaaS'
                  : discoveryStatus.architecture === 'co_located_serverless'
                  ? isArabic
                    ? 'مسارات API مدمجة عند الطلب (Serverless / Next.js)'
                    : 'On-Demand Serverless / Next.js API'
                  : discoveryStatus.architecture === 'external_backend'
                  ? isArabic
                    ? 'خادم API مستقل ومخصص'
                    : 'Dedicated External API Server'
                  : isArabic
                  ? 'واجهة أمامية مباشرة'
                  : 'Pure Frontend'}
              </span>
            </div>
            <span className="text-[10px] font-mono opacity-80">
              {isArabic
                ? `تم فحص (${discoveryStatus.crawledScripts}) ملف جافاسكريبت`
                : `Analyzed ${discoveryStatus.crawledScripts} JS bundles`}
            </span>
          </div>

          <p className="leading-relaxed text-[11.5px] opacity-90">
            {isArabic ? discoveryStatus.messageAr : discoveryStatus.messageEn}
          </p>
        </div>
      )}

      {/* API Base URL Setting Field */}
      <div className="space-y-1.5 pt-1">
        <div className="flex items-center justify-between">
          <label className="text-xs font-medium text-[#d9d9d9] flex items-center gap-1.5">
            <LinkOutlined className="text-xs text-[#1677ff]" />
            <span>
              {isArabic
                ? 'رابط خادم الـ API (اتركه فارغاً إذا كان موقعك واجهة بدون API):'
                : 'API Base URL (leave empty if site is a static/pure frontend):'}
            </span>
          </label>
          <span className="text-[10px] text-[#8c8c8c] font-mono">
            {isArabic ? 'مثال: https://api.mysite.com' : 'Optional custom backend'}
          </span>
        </div>
        <input
          type="text"
          value={apiBaseUrl}
          onChange={(e) => onApiBaseUrlChange(e.target.value)}
          placeholder="https://api.yourdomain.com"
          disabled={isRunning}
          className={STYLES.input}
          dir="ltr"
        />
      </div>

      {/* Expanded Endpoints List & Custom Endpoint Input */}
      {isExpanded && (
        <div className="space-y-3 pt-2 border-t border-[#303030]">
          {/* Add Custom Endpoint Form */}
          <form onSubmit={handleAddCustomEndpoint} className="flex items-center gap-2">
            <select
              value={newMethod}
              onChange={(e) => setNewMethod(e.target.value as 'GET' | 'POST')}
              disabled={isRunning}
              className="px-2.5 py-2 rounded-[6px] bg-[#1f1f1f] border border-[#303030] text-xs text-white font-mono focus:border-[#1677ff] focus:outline-none cursor-pointer"
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
            <input
              type="text"
              value={newPath}
              onChange={(e) => setNewPath(e.target.value)}
              placeholder="/api/v1/resource"
              disabled={isRunning}
              className={`${STYLES.input} flex-1`}
              dir="ltr"
            />
            <button
              type="submit"
              disabled={isRunning || !newPath.trim()}
              className="px-3.5 py-2 rounded-[6px] bg-[#1f1f1f] hover:bg-[#262626] text-xs font-medium text-white border border-[#303030] flex items-center gap-1 transition-colors cursor-pointer shrink-0 disabled:opacity-40"
            >
              <PlusOutlined className="text-xs" />
              <span>{isArabic ? 'إضافة مسار' : 'Add Path'}</span>
            </button>
          </form>

          {/* Endpoints Table Actions */}
          {endpoints.length > 0 && (
            <div className="flex items-center justify-between text-[11px] text-[#8c8c8c] px-1">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleSelectAll(true)}
                  className="hover:text-[#1677ff] transition-colors cursor-pointer"
                >
                  {isArabic ? 'تحديد الكل' : 'Select All'}
                </button>
                <span>•</span>
                <button
                  type="button"
                  onClick={() => handleSelectAll(false)}
                  className="hover:text-white transition-colors cursor-pointer"
                >
                  {isArabic ? 'إلغاء التحديد' : 'Deselect All'}
                </button>
              </div>
              <span className="font-mono">
                {selectedCount} / {endpoints.length} {isArabic ? 'مشمول بالفحص' : 'selected'}
              </span>
            </div>
          )}

          {/* Endpoints Scroll List */}
          <div className="max-h-56 overflow-y-auto space-y-1.5 pr-1 divide-y divide-[#222]">
            {endpoints.length === 0 ? (
              <div className="p-4 text-center text-xs text-[#8c8c8c] font-mono">
                {isArabic
                  ? 'لا توجد نهايات API مسجلة حالياً. إذا كان لديك مسارات تريد اختبارها، يمكنك إضافتها يدوياً أعلاه.'
                  : 'No custom API endpoints queued. Add custom paths above if you have private APIs to test.'}
              </div>
            ) : (
              endpoints.map((ep) => {
                const methodColor =
                  ep.method === 'POST'
                    ? 'bg-[#111d2c] text-[#1677ff] border-[#153450]'
                    : 'bg-[#162312] text-[#52c41a] border-[#274916]';

                return (
                  <div
                    key={ep.id}
                    className="p-2 rounded-lg bg-[#181818] hover:bg-[#202020] border border-[#2a2a2a] flex items-center justify-between gap-2 text-xs font-mono transition-colors"
                  >
                    <div className="flex items-center gap-2.5 truncate">
                      <input
                        type="checkbox"
                        checked={ep.selected}
                        onChange={() => handleToggleEndpoint(ep.id)}
                        disabled={isRunning}
                        className="w-3.5 h-3.5 rounded border-[#303030] bg-[#141414] text-[#1677ff] focus:ring-0 cursor-pointer"
                      />
                      <span className={`${STYLES.methodPill} ${methodColor}`}>
                        {ep.method}
                      </span>
                      <span className="text-[#ededed] truncate" dir="ltr">
                        {ep.path}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${
                          ep.source === 'supabase_table'
                            ? 'bg-[#162312] text-[#52c41a] border-[#274916]'
                            : 'bg-[#1f1f1f] text-[#8c8c8c] border-[#303030]'
                        }`}
                      >
                        {ep.source === 'supabase_table'
                          ? isArabic
                            ? 'قاعدة Supabase'
                            : 'Supabase DB'
                          : ep.source === 'js_bundle'
                          ? isArabic
                            ? 'كود JS'
                            : 'JS Code'
                          : isArabic
                          ? 'مسار مخصص'
                          : 'Custom'}
                      </span>
                      <button
                        type="button"
                        onClick={() => handleDeleteEndpoint(ep.id)}
                        className="text-[#8c8c8c] hover:text-[#ff4d4f] p-1 cursor-pointer transition-colors"
                      >
                        <DeleteOutlined className="text-xs" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      )}
    </div>
  );
}
