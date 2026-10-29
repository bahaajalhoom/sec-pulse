'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState, useRef, useEffect } from 'react';
import {
  CodeOutlined,
  CheckCircleOutlined,
  WarningOutlined,
  CloseCircleOutlined,
  ClockCircleOutlined,
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
const STATUS_BADGES: Record<
  ProbeStatus,
  { labelAr: string; labelEn: string; badgeClass: string; icon: React.ReactNode }
> = {
  passed: {
    labelAr: 'تم الصد (آمن)',
    labelEn: 'DEFENDED',
    badgeClass: 'bg-[#162312] text-[#52c41a] border border-[#274916]',
    icon: <CheckCircleOutlined className="text-xs text-[#52c41a]" />,
  },
  warning: {
    labelAr: 'تنبيه أمني',
    labelEn: 'WARNING',
    badgeClass: 'bg-[#2b2111] text-[#faad14] border border-[#594214]',
    icon: <WarningOutlined className="text-xs text-[#faad14]" />,
  },
  failed: {
    labelAr: 'ثغرة مؤكدة',
    labelEn: 'VULNERABLE',
    badgeClass: 'bg-[#2a1215] text-[#ff4d4f] border border-[#58181c]',
    icon: <CloseCircleOutlined className="text-xs text-[#ff4d4f]" />,
  },
  blocked: {
    labelAr: 'محظور من جدار الحماية',
    labelEn: 'BLOCKED BY WAF',
    badgeClass: 'bg-[#111d2c] text-[#1677ff] border border-[#153450]',
    icon: <CheckCircleOutlined className="text-xs text-[#1677ff]" />,
  },
  running: {
    labelAr: 'جاري الإرسال...',
    labelEn: 'PROBING...',
    badgeClass: 'bg-[#1f1f1f] text-[#d9d9d9] border border-[#303030]',
    icon: <SyncOutlined spin className="text-xs text-[#1677ff]" />,
  },
  pending: {
    labelAr: 'في الانتظار',
    labelEn: 'QUEUED',
    badgeClass: 'bg-[#141414] text-[#595959] border border-[#303030]',
    icon: <ClockCircleOutlined className="text-xs text-[#595959]" />,
  },
};

const STYLES = {
  consoleCard: 'rounded-[8px] border border-[#303030] bg-[#141414] flex flex-col overflow-hidden',
  headerBar: 'px-4 py-2.5 bg-[#1f1f1f] border-b border-[#303030] flex items-center justify-between flex-wrap gap-2',
  filterPill: 'px-2 py-0.5 rounded-[4px] text-[11px] font-mono transition-colors flex items-center gap-1 cursor-pointer border',
  row: 'w-full text-start p-3 hover:bg-[#1f1f1f] transition-colors border-b border-[#262626] font-mono text-xs flex flex-col gap-1 cursor-pointer focus:outline-none focus-visible:bg-[#1f1f1f]',
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

  // Auto-scroll when new events arrive
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
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-[#ff4d4f]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#faad14]" />
            <span className="w-2.5 h-2.5 rounded-full bg-[#52c41a]" />
          </div>
          <div className="h-4 w-[1px] bg-[#303030] mx-1" />
          <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
            <CodeOutlined className="text-xs text-[#1677ff]" />
            <span>
              {isArabic
                ? 'شاشة المراقبة الحية للهجوم والأكواد المُرسلة'
                : 'Live Threat Execution & Telemetry Terminal'}
            </span>
          </div>
          {isRunning && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#111d2c] text-[#1677ff] border border-[#153450]">
              LIVE
            </span>
          )}
        </div>

        {/* Toolbar Controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Status Filter Badges */}
          <div className="flex items-center bg-[#141414] p-0.5 rounded-lg border border-[#303030] text-[11px]">
            <button
              type="button"
              onClick={() => setFilter('all')}
              className={`${STYLES.filterPill} ${
                filter === 'all'
                  ? 'bg-[#1f1f1f] text-white border-[#303030]'
                  : 'border-transparent text-[#8c8c8c] hover:text-white'
              }`}
            >
              <span>{isArabic ? 'الكل' : 'All'}</span>
              <span className="text-[10px] opacity-70 font-mono">({events.length})</span>
            </button>
            <button
              type="button"
              onClick={() => setFilter('failed')}
              className={`${STYLES.filterPill} ${
                filter === 'failed'
                  ? 'bg-[#2a1215] text-[#ff4d4f] border-[#58181c]'
                  : 'border-transparent text-[#8c8c8c] hover:text-[#ff4d4f]'
              }`}
            >
              <span>{isArabic ? 'ثغرات' : 'Vulns'}</span>
              <span className="text-[10px] opacity-70 font-mono">({failedCount})</span>
            </button>
            <button
              type="button"
              onClick={() => setFilter('warning')}
              className={`${STYLES.filterPill} ${
                filter === 'warning'
                  ? 'bg-[#2b2111] text-[#faad14] border-[#594214]'
                  : 'border-transparent text-[#8c8c8c] hover:text-[#faad14]'
              }`}
            >
              <span>{isArabic ? 'تنبيهات' : 'Warn'}</span>
              <span className="text-[10px] opacity-70 font-mono">({warningCount})</span>
            </button>
            <button
              type="button"
              onClick={() => setFilter('passed')}
              className={`${STYLES.filterPill} ${
                filter === 'passed'
                  ? 'bg-[#162312] text-[#52c41a] border-[#274916]'
                  : 'border-transparent text-[#8c8c8c] hover:text-[#52c41a]'
              }`}
            >
              <span>{isArabic ? 'سليم' : 'Safe'}</span>
              <span className="text-[10px] opacity-70 font-mono">({passedCount})</span>
            </button>
          </div>

          {/* Auto-scroll toggle */}
          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded-lg border text-xs transition-colors cursor-pointer ${
              autoScroll
                ? 'bg-[#111d2c] border-[#153450] text-[#1677ff]'
                : 'bg-[#1f1f1f] border-[#303030] text-[#8c8c8c]'
            }`}
            title={autoScroll ? 'Auto-scroll ON' : 'Auto-scroll OFF'}
          >
            <VerticalAlignBottomOutlined className="text-xs" />
          </button>

          {/* Clear Log */}
          <button
            type="button"
            onClick={onClear}
            disabled={events.length === 0 || isRunning}
            className="p-1.5 rounded-lg bg-[#1f1f1f] border border-[#303030] text-[#8c8c8c] hover:text-white disabled:opacity-40 transition-colors cursor-pointer"
            title={isArabic ? 'مسح السجل' : 'Clear Logs'}
          >
            <DeleteOutlined className="text-xs" />
          </button>
        </div>
      </div>

      {/* Terminal Output Area */}
      <div className="max-h-[380px] min-h-[220px] overflow-y-auto divide-y divide-[#222] select-text">
        {filteredEvents.length === 0 ? (
          <div className="h-[220px] flex flex-col items-center justify-center text-center p-6 text-[#8c8c8c] font-mono text-xs">
            <CodeOutlined className="text-2xl mb-2 opacity-30 text-[#1677ff]" />
            <p>
              {isArabic
                ? 'لا توجد هجمات مُسجلة حالياً. اضغط "شن الهجوم وفحص الأمان" للبدء.'
                : 'No telemetry logged. Launch the simulated audit to view live traffic.'}
            </p>
            <span className="text-[11px] text-[#595959] mt-1">
              {isArabic
                ? 'ستظهر هنا كل استجابة، الكود المُرسل، والزمن المستغرق بالملي ثانية.'
                : 'Live requests, sent payloads, and HTTP status codes will stream here.'}
            </span>
          </div>
        ) : (
          filteredEvents.map((ev) => {
            const badge = STATUS_BADGES[ev.status] || STATUS_BADGES.pending;
            const isExpanded = expandedId === ev.id;

            return (
              <button
                type="button"
                key={ev.id}
                onClick={() => setExpandedId(isExpanded ? null : ev.id)}
                className={STYLES.row}
              >
                {/* Single Event Summary Line */}
                <div className="flex items-center justify-between gap-2 flex-wrap w-full">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[#8c8c8c] text-[10px]">[{ev.timestamp}]</span>
                    <span className="text-[10px] font-bold text-[#1677ff] bg-[#111d2c] px-1.5 py-0.2 rounded border border-[#153450]">
                      T-{ev.threadId}
                    </span>
                    <span className="text-[10px] font-bold text-[#faad14] bg-[#2b2111] px-1.5 py-0.2 rounded border border-[#594214]">
                      {ev.method}
                    </span>
                    <span className="text-[#d9d9d9] font-medium truncate max-w-[260px] sm:max-w-md">
                      {ev.url}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-[#8c8c8c] font-mono">
                      {ev.latencyMs}ms
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#1f1f1f] text-[#d9d9d9] border border-[#303030]">
                      {ev.statusCode}
                    </span>
                    <span
                      className={`text-[10px] font-mono font-medium px-2 py-0.5 rounded flex items-center gap-1 ${badge.badgeClass}`}
                    >
                      {badge.icon}
                      <span>{isArabic ? badge.labelAr : badge.labelEn}</span>
                    </span>
                    {isExpanded ? (
                      <UpOutlined className="text-[10px] text-[#8c8c8c]" />
                    ) : (
                      <DownOutlined className="text-[10px] text-[#8c8c8c]" />
                    )}
                  </div>
                </div>

                {/* Sent Payload Snippet */}
                <div className="text-[11px] text-[#8c8c8c] flex items-center gap-2 overflow-hidden text-ellipsis whitespace-nowrap pl-1">
                  <span className="text-[#1677ff] select-none">→</span>
                  <span className="text-[#8c8c8c]">
                    {isArabic ? 'الكود المُرسل:' : 'Payload:'}
                  </span>
                  <code className="text-[#91caff] bg-[#111d2c] px-1 rounded border border-[#153450]">
                    {ev.sentPayloadSnippet}
                  </code>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="mt-2.5 p-3 rounded-lg bg-[#141414] border border-[#303030] text-xs space-y-2 w-full text-start">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-white">
                        {isArabic ? ev.probeNameAr : ev.probeName}
                      </span>
                      <span className="text-[10px] uppercase font-mono text-[#8c8c8c]">
                        {ev.category}
                      </span>
                    </div>

                    <p className="text-[#d9d9d9] text-[11px] leading-relaxed">
                      {isArabic ? ev.explanationAr : ev.explanation}
                    </p>

                    <div className="bg-[#0c0c0c] p-2.5 rounded border border-[#262626] space-y-1">
                      <span className="text-[10px] text-[#8c8c8c] block">
                        {isArabic ? '// الدليل والرد المستلم:' : '// Evidence & Result:'}
                      </span>
                      <code className="text-[#52c41a] text-[11px] block whitespace-pre-wrap">
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

      {/* Terminal Footer Bar */}
      <div className="px-4 py-2 bg-[#1f1f1f] border-t border-[#303030] flex items-center justify-between text-[11px] font-mono text-[#8c8c8c]">
        <span>
          {isArabic ? 'إجمالي الطلبات المُنفذة:' : 'Probes Telemetry:'}{' '}
          <strong className="text-white">{events.length}</strong>
        </span>
        <div className="flex items-center gap-3">
          <span className="text-[#52c41a]">
            {passedCount} {isArabic ? 'تم الصد' : 'Defended'}
          </span>
          <span className="text-[#faad14]">
            {warningCount} {isArabic ? 'تنبيه' : 'Warnings'}
          </span>
          <span className="text-[#ff4d4f]">
            {failedCount} {isArabic ? 'ثغرات' : 'Vulnerable'}
          </span>
        </div>
      </div>
    </div>
  );
}
