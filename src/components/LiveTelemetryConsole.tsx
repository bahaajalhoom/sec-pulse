'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useRef, useEffect } from 'react';
import {
  CodeOutlined,
  DeleteOutlined,
  VerticalAlignBottomOutlined,
  DownOutlined,
  UpOutlined,
  SyncOutlined,
} from '@ant-design/icons';
import { LiveTelemetryEvent, ProbeStatus } from '@/types/security';

// ============================================================================
// 2. CONFIGURATION & STYLES (ZONE 2)
// ============================================================================
const STATUS_META: Record<
  ProbeStatus,
  { labelAr: string; labelEn: string; colorClass: string; dotClass: string }
> = {
  passed: {
    labelAr: 'تم الصد (آمن)',
    labelEn: 'DEFENDED',
    colorClass: 'text-emerald-400',
    dotClass: 'bg-emerald-400',
  },
  warning: {
    labelAr: 'تنبيه أمني',
    labelEn: 'WARNING',
    colorClass: 'text-amber-400',
    dotClass: 'bg-amber-400',
  },
  failed: {
    labelAr: 'ثغرة مؤكدة',
    labelEn: 'VULNERABLE',
    colorClass: 'text-red-400',
    dotClass: 'bg-red-400',
  },
  blocked: {
    labelAr: 'محظور من جدار الحماية',
    labelEn: 'BLOCKED',
    colorClass: 'text-zinc-400',
    dotClass: 'bg-zinc-400',
  },
  running: {
    labelAr: 'جاري الإرسال...',
    labelEn: 'PROBING...',
    colorClass: 'text-white',
    dotClass: 'bg-white',
  },
  pending: {
    labelAr: 'في الانتظار',
    labelEn: 'QUEUED',
    colorClass: 'text-zinc-600',
    dotClass: 'bg-zinc-600',
  },
};

const STYLES = {
  consoleCard:
    'rounded-xl border border-white/[0.08] bg-[#0c0c0e] overflow-hidden flex flex-col',
  headerBar:
    'flex items-center justify-between p-3 border-b border-white/[0.08] bg-black',
  filterBtn:
    'px-2.5 py-1 rounded text-xs transition-colors cursor-pointer select-none font-mono',
  row: 'p-2.5 text-xs font-mono transition-colors border-b border-white/[0.04] hover:bg-white/[0.02] flex flex-col gap-1.5 w-full text-start cursor-pointer select-none',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface LiveTelemetryConsoleProps {
  events: LiveTelemetryEvent[];
  isRunning: boolean;
  onClear: () => void;
  lang: 'ar' | 'en';
}

type FilterType = 'all' | 'failed' | 'warning' | 'passed';

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function LiveTelemetryConsole({
  events,
  isRunning,
  onClear,
  lang,
}: LiveTelemetryConsoleProps) {
  const isArabic = lang === 'ar';
  const [filter, setFilter] = useState<FilterType>('all');
  const [autoScroll, setAutoScroll] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [events, autoScroll]);

  const filteredEvents = events.filter((ev) => {
    if (filter === 'all') return true;
    return ev.status === filter;
  });

  const passedCount = events.filter((e) => e.status === 'passed').length;
  const warningCount = events.filter((e) => e.status === 'warning').length;
  const failedCount = events.filter((e) => e.status === 'failed').length;

  return (
    <div className={STYLES.consoleCard}>
      {/* Console Top Toolbar */}
      <div className={STYLES.headerBar}>
        <div className="flex items-center gap-2">
          <CodeOutlined className="text-xs text-zinc-400" />
          <span className="text-xs font-medium text-white">
            {isArabic ? 'سجل الرصد الحي للحزم' : 'Live Packet Telemetry'}
          </span>
          {isRunning && (
            <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1 ms-2">
              <SyncOutlined spin className="text-[9px]" />
              <span>STREAMING</span>
            </span>
          )}
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-2">
          {/* Filters */}
          <div className="flex items-center gap-1 text-xs">
            <button
              type="button"
              onClick={() => setFilter('all')}
              className={`${STYLES.filterBtn} ${
                filter === 'all'
                  ? 'bg-white/[0.1] text-white'
                  : 'text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {isArabic ? 'الكل' : 'All'} ({events.length})
            </button>
            <button
              type="button"
              onClick={() => setFilter('failed')}
              className={`${STYLES.filterBtn} ${
                filter === 'failed'
                  ? 'bg-white/[0.1] text-red-400'
                  : 'text-zinc-500 hover:text-red-400'
              }`}
            >
              {isArabic ? 'ثغرات' : 'Vulns'} ({failedCount})
            </button>
            <button
              type="button"
              onClick={() => setFilter('warning')}
              className={`${STYLES.filterBtn} ${
                filter === 'warning'
                  ? 'bg-white/[0.1] text-amber-400'
                  : 'text-zinc-500 hover:text-amber-400'
              }`}
            >
              {isArabic ? 'تنبيهات' : 'Warn'} ({warningCount})
            </button>
          </div>

          <div className="h-3.5 w-[1px] bg-white/[0.08] mx-1" />

          {/* Autoscroll */}
          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1 rounded text-xs transition-colors cursor-pointer ${
              autoScroll ? 'text-white' : 'text-zinc-600'
            }`}
            title="Auto-scroll"
          >
            <VerticalAlignBottomOutlined />
          </button>

          {/* Clear */}
          <button
            type="button"
            onClick={onClear}
            disabled={events.length === 0 || isRunning}
            className="p-1 rounded text-xs text-zinc-500 hover:text-white disabled:opacity-30 transition-colors cursor-pointer"
            title="Clear logs"
          >
            <DeleteOutlined />
          </button>
        </div>
      </div>

      {/* Terminal Output Area */}
      <div className="max-h-[520px] min-h-[360px] overflow-y-auto select-text font-mono">
        {filteredEvents.length === 0 ? (
          <div className="h-[360px] flex flex-col items-center justify-center text-center p-8 text-zinc-600 font-mono text-xs">
            <span className="text-zinc-700 text-sm mb-1">$ securipulse --listen</span>
            <p className="text-zinc-400">
              {isArabic
                ? 'محرك الرصد بانتظار بدء الفحص'
                : 'Telemetry stream waiting for scan trigger...'}
            </p>
            <p className="text-[11px] text-zinc-600 mt-1 max-w-xs">
              {isArabic
                ? 'اضغط "بدء فحص الأمان الشامل" لبدء إرسال الحزم ورؤية النتائج اللحظية هنا.'
                : 'Click "Start Security Audit" to stream live packets, status codes, and latency.'}
            </p>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const meta = STATUS_META[ev.status] || STATUS_META.pending;
            const isExpanded = expandedId === ev.id;

            return (
              <button
                type="button"
                key={ev.id}
                onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                className={STYLES.row}
              >
                {/* Event Summary Line */}
                <div className="flex items-center justify-between gap-2 flex-wrap w-full text-zinc-400">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-zinc-600 text-[10px]">{ev.timestamp}</span>
                    <span className="text-zinc-500 text-[10px]">T{ev.threadId}</span>
                    <span className="text-white text-[11px] font-semibold">{ev.method}</span>
                    <span className="text-zinc-200 truncate max-w-[260px] sm:max-w-md">
                      {ev.url}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-zinc-500 text-[10px]">{ev.latencyMs}ms</span>
                    <span className="text-zinc-300 text-[11px]">{ev.statusCode}</span>
                    <div className="flex items-center gap-1.5 ms-1">
                      <span className={`w-1.5 h-1.5 rounded-full ${meta.dotClass}`} />
                      <span className={`text-[10px] uppercase font-mono ${meta.colorClass}`}>
                        {isArabic ? meta.labelAr : meta.labelEn}
                      </span>
                    </div>
                    {isExpanded ? (
                      <UpOutlined className="text-[9px] text-zinc-600" />
                    ) : (
                      <DownOutlined className="text-[9px] text-zinc-600" />
                    )}
                  </div>
                </div>

                {/* Sent Payload Snippet */}
                <div className="text-[11px] text-zinc-500 flex items-center gap-2 overflow-hidden text-ellipsis whitespace-nowrap">
                  <span className="text-zinc-700">→</span>
                  <code className="text-zinc-300 bg-white/[0.04] px-1.5 py-0.2 rounded font-mono">
                    {ev.sentPayloadSnippet}
                  </code>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="mt-2 p-3 rounded-lg bg-black border border-white/[0.06] text-xs space-y-2 w-full text-start font-sans">
                    <div className="flex items-center justify-between">
                      <span className="font-medium text-white">
                        {isArabic ? ev.probeNameAr : ev.probeName}
                      </span>
                      <span className="text-[10px] uppercase font-mono text-zinc-500">
                        {ev.category}
                      </span>
                    </div>

                    <p className="text-zinc-400 text-[11px] leading-relaxed">
                      {isArabic ? ev.explanationAr : ev.explanation}
                    </p>

                    <div className="bg-[#0c0c0e] p-2.5 rounded border border-white/[0.06] space-y-1 font-mono text-[11px]">
                      <span className="text-zinc-500 block text-[10px]">
                        {isArabic ? '// الدليل والاستجابة:' : '// Response Evidence:'}
                      </span>
                      <code className="text-emerald-400 block whitespace-pre-wrap">
                        {ev.evidence}
                      </code>
                    </div>
                  </div>
                )}
              </button>
            );
          })
        )}
        <div ref={terminalEndRef} />
      </div>

      {/* Terminal Footer */}
      <div className="px-4 py-2 bg-black border-t border-white/[0.08] flex items-center justify-between text-[11px] font-mono text-zinc-500">
        <span>
          {isArabic ? 'إجمالي الطلبات:' : 'Probes:'}{' '}
          <strong className="text-white">{events.length}</strong>
        </span>
        <div className="flex items-center gap-3">
          <span className="text-emerald-400">
            {passedCount} {isArabic ? 'سليم' : 'passed'}
          </span>
          <span className="text-amber-400">
            {warningCount} {isArabic ? 'تنبيه' : 'warnings'}
          </span>
          <span className="text-red-400">
            {failedCount} {isArabic ? 'ثغرة' : 'vulns'}
          </span>
        </div>
      </div>
    </div>
  );
}
