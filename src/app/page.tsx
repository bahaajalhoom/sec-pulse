'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useRef, useCallback } from 'react';
import Header from '@/components/Header';
import TargetConfig from '@/components/TargetConfig';
import PayloadInspectorModal from '@/components/PayloadInspectorModal';
import LiveTelemetryConsole from '@/components/LiveTelemetryConsole';
import FindingsSummary from '@/components/FindingsSummary';
import DefenseRecipesModal from '@/components/DefenseRecipesModal';
import {
  AttackIntensity,
  AuditReport,
  DiscoveredEndpoint,
  LiveTelemetryEvent,
  SecurityProbePayload,
  VulnerabilityCategory,
} from '@/types/security';
import { INITIAL_PROBES } from '@/lib/constants';
import { normalizeTargetUrl } from '@/lib/security-engine';

// ============================================================================
// 2. CONFIGURATION & CONSTANTS (EASY EDIT ZONE)
// ============================================================================
const DEFAULT_CONFIG = {
  initialTargetUrl: 'https://taskflow.apps.taqat.academy',
  defaultIntensity: 'standard' as AttackIntensity,
  defaultConcurrency: 4,
  defaultDelayMs: 40,
};

const DEFAULT_CATEGORIES: Record<VulnerabilityCategory, boolean> = {
  sqli: true,
  xss: true,
  auth: true,
  ports: true,
  subdomain: true,
  headers: true,
  ssrf: true,
  idor: true,
  sensitive_files: true,
  rate_limiting: true,
  cmd_injection: true,
  cors_leak: true,
  csrf: true,
  graphql: true,
  directory_traversal: true,
  mass_assignment: true,
};

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function HomePage() {
  // --- UI & Language State ---
  const [lang, setLang] = useState<'ar' | 'en'>('ar');
  const isArabic = lang === 'ar';

  // --- Configuration State ---
  const [targetUrl, setTargetUrl] = useState(DEFAULT_CONFIG.initialTargetUrl);
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [endpoints, setEndpoints] = useState<DiscoveredEndpoint[]>([]);
  const [intensity, setIntensity] = useState<AttackIntensity>(DEFAULT_CONFIG.defaultIntensity);
  const [concurrency, setConcurrency] = useState(DEFAULT_CONFIG.defaultConcurrency);
  const [delayMs, setDelayMs] = useState(DEFAULT_CONFIG.defaultDelayMs);
  const [enabledCategories, setEnabledCategories] = useState(DEFAULT_CATEGORIES);

  // --- Probes Catalog (Editable in Inspector) ---
  const [probes, setProbes] = useState<SecurityProbePayload[]>(INITIAL_PROBES);

  // --- Modals State ---
  const [isInspectorOpen, setIsInspectorOpen] = useState(false);
  const [isRecipesOpen, setIsRecipesOpen] = useState(false);

  // --- Execution & Telemetry State ---
  const [isRunning, setIsRunning] = useState(false);
  const [telemetryEvents, setTelemetryEvents] = useState<LiveTelemetryEvent[]>([]);
  const [auditReport, setAuditReport] = useState<AuditReport | null>(null);

  // Abort controller ref
  const abortControllerRef = useRef<AbortController | null>(null);

  // --- Handlers: Category & Probes Management ---
  function handleToggleCategory(cat: VulnerabilityCategory) {
    setEnabledCategories((prev) => ({ ...prev, [cat]: !prev[cat] }));
  }

  function handleSaveProbes(updated: SecurityProbePayload[]) {
    setProbes(updated);
  }

  function handleResetDefaultProbes() {
    setProbes(INITIAL_PROBES);
  }

  function handleToggleLang() {
    setLang((prev) => (prev === 'ar' ? 'en' : 'ar'));
  }

  // --- Handlers: REAL Live Network Audit Execution ---
  const handleStartAudit = useCallback(async () => {
    const cleanUrl = normalizeTargetUrl(targetUrl);
    setTargetUrl(cleanUrl);

    const hasCategory = Object.values(enabledCategories).some(Boolean);
    if (!hasCategory) {
      alert(
        isArabic
          ? 'يرجى تفعيل نطاق أمني واحد على الأقل قبل بدء الفحص!'
          : 'Please enable at least one security module before launching!'
      );
      return;
    }

    setIsRunning(true);
    setTelemetryEvents([]);
    setAuditReport(null);

    const abortController = new AbortController();
    abortControllerRef.current = abortController;

    try {
      // Connect to the REAL backend audit route with live streaming enabled
      const response = await fetch('/api/audit?stream=true', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: cleanUrl,
          apiBaseUrl: apiBaseUrl.trim() || undefined,
          intensity,
          concurrency,
          delayMs,
          enabledCategories,
          customPayloads: probes,
          endpointsToTest: endpoints.filter((e) => e.selected),
        }),
        signal: abortController.signal,
      });

      if (!response.ok || !response.body) {
        throw new Error(`Server returned ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data: ')) {
            try {
              const payload = JSON.parse(trimmed.slice(6));
              if (payload.type === 'event' && payload.event) {
                setTelemetryEvents((prev) => [...prev, payload.event]);
              } else if (payload.type === 'report' && payload.report) {
                setAuditReport(payload.report);
              }
            } catch {
              // Ignore malformed chunks
            }
          }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== 'AbortError') {
        alert(
          isArabic
            ? `حدث خطأ أثناء الاتصال بالخادم: ${err.message}`
            : `Audit error: ${err.message}`
        );
      }
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
    }
  }, [
    targetUrl,
    apiBaseUrl,
    endpoints,
    probes,
    enabledCategories,
    concurrency,
    delayMs,
    intensity,
    isArabic,
  ]);

  function handleAbortAudit() {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    setIsRunning(false);
  }

  function handleClearLogs() {
    setTelemetryEvents([]);
  }

  return (
    <div
      className={`min-h-screen bg-[#000000] text-[#d9d9d9] flex flex-col font-sans selection:bg-[#1677ff] selection:text-white ${
        isArabic ? 'rtl' : 'ltr'
      }`}
      dir={isArabic ? 'rtl' : 'ltr'}
    >
      {/* 1. Header Bar */}
      <Header
        lang={lang}
        onToggleLang={handleToggleLang}
        onOpenRecipes={() => setIsRecipesOpen(true)}
        isRunning={isRunning}
        score={auditReport ? auditReport.score : null}
      />

      {/* 2. Main Work Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Hero Section */}
        <div className="space-y-2">
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-[4px] bg-[#111d2c] border border-[#153450] text-[#1677ff] text-xs font-normal">
            <span className="w-1.5 h-1.5 rounded-full bg-[#1677ff]" />
            <span>
              {isArabic
                ? 'فاحص الأمان الشبكي التفاعلي مع استكشاف الـ API الحقيقي'
                : 'Real Network Threat Auditor with Automated API Discovery'}
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            {isArabic
              ? 'فحص أمان موقعك ونهايات الـ API الحقيقية'
              : 'Audit Real Web & API Endpoints Under Live Threat Probing'}
          </h1>
          <p className="text-xs sm:text-sm text-[#8c8c8c] max-w-3xl leading-relaxed">
            {isArabic
              ? 'المنصة لا تخمن مسارات وهمية! تكتشف نهايات الـ API تلقائياً من كود موقعك (أو تتيح لك كتابة مسار API منفصل)، ثم تنفذ اختبارات حقيقية على تلك النهايات للتأكد من حمايتها وترويساتها.'
              : 'No fake static paths! Auto-discovers real API routes from your app bundle or accepts custom API hosts, then audits live endpoints for SQLi, XSS, Auth barriers, CORS, and exposed assets.'}
          </p>
        </div>

        {/* 3. Configuration Cockpit with API Discovery Panel */}
        <TargetConfig
          targetUrl={targetUrl}
          onTargetUrlChange={setTargetUrl}
          apiBaseUrl={apiBaseUrl}
          onApiBaseUrlChange={setApiBaseUrl}
          endpoints={endpoints}
          onEndpointsChange={setEndpoints}
          intensity={intensity}
          onIntensityChange={setIntensity}
          concurrency={concurrency}
          onConcurrencyChange={setConcurrency}
          delayMs={delayMs}
          onDelayMsChange={setDelayMs}
          enabledCategories={enabledCategories}
          onToggleCategory={handleToggleCategory}
          onOpenInspector={() => setIsInspectorOpen(true)}
          onStartAudit={handleStartAudit}
          onAbortAudit={handleAbortAudit}
          isRunning={isRunning}
          lang={lang}
        />

        {/* 4. Live Telemetry Console */}
        <LiveTelemetryConsole
          events={telemetryEvents}
          isRunning={isRunning}
          onClear={handleClearLogs}
          lang={lang}
        />

        {/* 5. Executive Findings & Code Fixes Report */}
        <FindingsSummary report={auditReport} lang={lang} />
      </main>

      {/* Footer */}
      <footer className="border-t border-[#303030] bg-[#141414] py-5 text-center text-xs text-[#8c8c8c] font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>SecuriPulse DevSec Platform • Ant Design Dark Enterprise Architecture</span>
          <span>Next.js 16.4.3 • Node.js 24 • Real Network Testing</span>
        </div>
      </footer>

      {/* Modal 1: Pre-Attack Payload & Code Inspector */}
      <PayloadInspectorModal
        isOpen={isInspectorOpen}
        onClose={() => setIsInspectorOpen(false)}
        probes={probes}
        onSaveProbes={handleSaveProbes}
        onResetDefaultProbes={handleResetDefaultProbes}
        lang={lang}
      />

      {/* Modal 2: Defense Blueprints & Recipes */}
      <DefenseRecipesModal
        isOpen={isRecipesOpen}
        onClose={() => setIsRecipesOpen(false)}
        lang={lang}
      />
    </div>
  );
}
