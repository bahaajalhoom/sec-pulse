'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  SearchOutlined,
  LinkOutlined,
  PlusOutlined,
  DeleteOutlined,
  DownOutlined,
  UpOutlined,
  CheckOutlined,
} from '@ant-design/icons';
import { DiscoveredEndpoint, EndpointDiscoveryResult, ApiArchitecture } from '@/types/security';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const STYLES = {
  card: 'space-y-3.5',
  input:
    'w-full rounded-lg border border-white/[0.08] bg-black px-3.5 py-2 text-xs text-white placeholder-zinc-600 focus:border-white/30 focus:outline-none font-mono transition-colors',
  discoverBtn:
    'px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-white/[0.08] hover:bg-white/[0.14] border border-white/[0.12] transition-colors flex items-center gap-1.5 cursor-pointer disabled:opacity-40',
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
            messageAr: `تم كشف معمارية Supabase BaaS (${res.detectedApiBaseUrl}) واستخراج ${res.endpoints.length} مسار لفحص أمان الجداول والصلاحيات.`,
            messageEn: `Detected Supabase BaaS architecture (${res.detectedApiBaseUrl}) with ${res.endpoints.length} tables staged.`,
          });
        } else if (res.apiArchitecture === 'co_located_serverless') {
          const resolvedApi = res.detectedApiBaseUrl || targetUrl;
          onApiBaseUrlChange(resolvedApi);
          setDiscoveryStatus({
            architecture: 'co_located_serverless',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            apiBaseUrl: resolvedApi,
            messageAr: `تم رصد مسارات API مدمجة على نفس النطاق (${res.endpoints.length} مسار).`,
            messageEn: `Detected serverless/co-located endpoints (${res.endpoints.length} routes).`,
          });
        } else if (res.apiArchitecture === 'external_backend' && res.detectedApiBaseUrl) {
          onApiBaseUrlChange(res.detectedApiBaseUrl);
          setDiscoveryStatus({
            architecture: 'external_backend',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            apiBaseUrl: res.detectedApiBaseUrl,
            messageAr: `تم رصد خادم API مستقل (${res.detectedApiBaseUrl}) واكتشاف ${res.endpoints.length} مسار.`,
            messageEn: `External API host detected (${res.detectedApiBaseUrl}) with ${res.endpoints.length} routes.`,
          });
        } else {
          onApiBaseUrlChange('');
          setDiscoveryStatus({
            architecture: 'frontend_only',
            crawledScripts: res.crawledScriptsCount,
            discoveredCount: res.endpoints.length,
            messageAr: `واجهة أمامية مباشرة بدون مسارات API واضحة في الكود المصدري.`,
            messageEn: `Static frontend detected without explicit public endpoints.`,
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
      description: 'Custom endpoint',
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
      {/* Top Action Header */}
      <div className="flex items-center justify-between flex-wrap gap-2 pt-1">
        <span className="text-xs text-zinc-400">
          {isArabic ? 'فحص ملفات الـ JS لاكتشاف نهايات الـ API' : 'Scan JS bundles for API routes'}
        </span>

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
                  ? 'جاري الفحص...'
                  : 'Scanning...'
                : isArabic
                ? 'استكشاف المسارات'
                : 'Discover Routes'}
            </span>
          </button>

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="p-1 rounded text-zinc-400 hover:text-white transition-colors cursor-pointer"
          >
            {isExpanded ? <UpOutlined className="text-xs" /> : <DownOutlined className="text-xs" />}
          </button>
        </div>
      </div>

      {/* Discovery Status Notice */}
      {discoveryStatus && (
        <div className="p-3 rounded-lg bg-black border border-white/[0.08] text-xs flex flex-col gap-1.5 font-mono">
          <div className="flex items-center justify-between">
            <span className="text-emerald-400 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>{discoveryStatus.architecture}</span>
            </span>
            <span className="text-zinc-500 text-[10px]">
              {discoveryStatus.crawledScripts} bundles
            </span>
          </div>
          <p className="text-zinc-300 text-[11px] font-sans">
            {isArabic ? discoveryStatus.messageAr : discoveryStatus.messageEn}
          </p>
        </div>
      )}

      {/* API Base URL Setting Field */}
      <div className="space-y-1">
        <label className="text-[11px] text-zinc-400 flex items-center gap-1.5">
          <LinkOutlined className="text-xs text-zinc-500" />
          <span>
            {isArabic
              ? 'خادم الـ API المخصص (اختياري):'
              : 'Custom API Base Host (Optional):'}
          </span>
        </label>
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
        <div className="space-y-3 pt-2 border-t border-white/[0.06]">
          {/* Add Custom Endpoint Form */}
          <form onSubmit={handleAddCustomEndpoint} className="flex items-center gap-1.5">
            <select
              value={newMethod}
              onChange={(e) => setNewMethod(e.target.value as 'GET' | 'POST')}
              disabled={isRunning}
              className="px-2 py-2 rounded-lg bg-black border border-white/[0.08] text-xs text-white font-mono focus:outline-none cursor-pointer"
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
              className="px-3 py-2 rounded-lg bg-white/[0.08] hover:bg-white/[0.14] text-xs font-medium text-white border border-white/[0.1] transition-colors cursor-pointer shrink-0 disabled:opacity-30"
            >
              <PlusOutlined className="text-xs" />
            </button>
          </form>

          {/* Endpoints Table Actions */}
          {endpoints.length > 0 && (
            <div className="flex items-center justify-between text-[11px] text-zinc-500">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => handleSelectAll(true)}
                  className="hover:text-white transition-colors cursor-pointer"
                >
                  {isArabic ? 'تحديد الكل' : 'Select all'}
                </button>
                <span>·</span>
                <button
                  type="button"
                  onClick={() => handleSelectAll(false)}
                  className="hover:text-white transition-colors cursor-pointer"
                >
                  {isArabic ? 'إلغاء' : 'Clear'}
                </button>
              </div>
              <span className="font-mono">
                {selectedCount} / {endpoints.length}
              </span>
            </div>
          )}

          {/* Endpoints Scroll List */}
          <div className="max-h-56 overflow-y-auto space-y-1 pr-1 font-mono text-xs">
            {endpoints.length === 0 ? (
              <div className="p-3 text-center text-zinc-600 font-mono text-xs">
                {isArabic ? 'لا توجد مسارات مضافة بعد' : 'No endpoints registered yet'}
              </div>
            ) : (
              endpoints.map((ep) => (
                <div
                  key={ep.id}
                  className="flex items-center justify-between p-2 rounded bg-black border border-white/[0.04] hover:border-white/[0.08] transition-colors"
                >
                  <button
                    type="button"
                    onClick={() => handleToggleEndpoint(ep.id)}
                    className="flex items-center gap-2 text-start flex-1 min-w-0 cursor-pointer"
                  >
                    <div
                      className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center shrink-0 ${
                        ep.selected
                          ? 'bg-white border-white text-black'
                          : 'border-zinc-700 bg-transparent'
                      }`}
                    >
                      {ep.selected && <CheckOutlined className="text-[8px] font-bold" />}
                    </div>
                    <span
                      className={`text-[10px] font-bold ${
                        ep.method === 'POST' ? 'text-blue-400' : 'text-emerald-400'
                      }`}
                    >
                      {ep.method}
                    </span>
                    <span className="truncate text-zinc-300" dir="ltr">
                      {ep.path}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleDeleteEndpoint(ep.id)}
                    className="text-zinc-600 hover:text-red-400 p-1 transition-colors cursor-pointer"
                    title="Delete endpoint"
                  >
                    <DeleteOutlined className="text-xs" />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
