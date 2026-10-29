'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  CloseOutlined,
  CodeOutlined,
  CheckOutlined,
  UndoOutlined,
  SaveOutlined,
} from '@ant-design/icons';
import { SecurityProbePayload, VulnerabilityCategory } from '@/types/security';
import { CATEGORY_METADATA } from '@/lib/constants';

// ============================================================================
// 2. CONFIGURATION & STYLES (ANT DESIGN DARK THEME)
// ============================================================================
const STYLES = {
  dialogBackdrop:
    'fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-3 sm:p-5 overflow-y-auto animate-in fade-in duration-150',
  modalCard:
    'bg-[#1f1f1f] border border-[#303030] rounded-[8px] w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden',
  categoryTab:
    'px-2.5 py-1 rounded-[4px] text-xs font-medium transition-all whitespace-nowrap flex items-center gap-1.5 cursor-pointer border',
  codeBlock:
    'font-mono text-xs p-3 rounded-[6px] bg-[#141414] border border-[#303030] text-[#d9d9d9] w-full resize-y min-h-[85px] focus:outline-none focus:border-[#1677ff] transition-colors',
  methodTag: 'px-1.5 py-0.5 rounded-[4px] font-mono text-[10px] font-bold uppercase border',
};

const METHOD_TAGS: Record<string, string> = {
  GET: 'bg-[#162312] text-[#52c41a] border-[#274916]',
  POST: 'bg-[#111d2c] text-[#1677ff] border-[#153450]',
  PUT: 'bg-[#2b2111] text-[#faad14] border-[#594214]',
  DELETE: 'bg-[#2a1215] text-[#ff4d4f] border-[#58181c]',
  OPTIONS: 'bg-[#141414] text-[#8c8c8c] border-[#303030]',
  HEAD: 'bg-[#141414] text-[#8c8c8c] border-[#303030]',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface PayloadInspectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  probes: SecurityProbePayload[];
  onSaveProbes: (updated: SecurityProbePayload[]) => void;
  onResetDefaultProbes: () => void;
  lang: 'ar' | 'en';
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function PayloadInspectorModal({
  isOpen,
  onClose,
  probes,
  onSaveProbes,
  onResetDefaultProbes,
  lang,
}: PayloadInspectorModalProps) {
  const isArabic = lang === 'ar';
  const [activeCategory, setActiveCategory] = useState<VulnerabilityCategory>('sqli');
  const [localProbes, setLocalProbes] = useState<SecurityProbePayload[]>(probes);
  const [hasChanges, setHasChanges] = useState(false);

  // Sync when reopened
  React.useEffect(() => {
    setLocalProbes(probes);
    setHasChanges(false);
  }, [probes, isOpen]);

  if (!isOpen) return null;

  const categories: VulnerabilityCategory[] = [
    'sqli',
    'xss',
    'auth',
    'ports',
    'subdomain',
    'headers',
    'ssrf',
    'idor',
    'sensitive_files',
    'rate_limiting',
    'cmd_injection',
    'cors_leak',
    'csrf',
    'graphql',
    'directory_traversal',
    'mass_assignment',
  ];

  const filteredProbes = localProbes.filter((p) => p.category === activeCategory);

  function handleUpdatePayload(id: string, newCode: string) {
    setLocalProbes((prev) =>
      prev.map((p) => (p.id === id ? { ...p, payloadCode: newCode } : p))
    );
    setHasChanges(true);
  }

  function handleToggleProbe(id: string) {
    setLocalProbes((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: !p.enabled } : p))
    );
    setHasChanges(true);
  }

  function handleSave() {
    onSaveProbes(localProbes);
    onClose();
  }

  function handleReset() {
    onResetDefaultProbes();
    setHasChanges(false);
  }

  return (
    <div className={STYLES.dialogBackdrop} role="dialog" aria-modal="true">
      <div className={STYLES.modalCard}>
        {/* Header Bar */}
        <div className="p-4 border-b border-[#303030] flex items-center justify-between bg-[#1f1f1f]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[6px] bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff]">
              <CodeOutlined className="text-sm" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">
                {isArabic
                  ? 'مُعاين الأكواد المُرسلة ومصفوفة الهجوم التجريبي'
                  : 'Pre-Attack Payload & Code Inspector'}
              </h2>
              <p className="text-xs text-[#8c8c8c]">
                {isArabic
                  ? 'يمكنك فحص الأكواد والرؤوس التي ستُرسل وتعديلها يدوياً قبل شن الهجوم'
                  : 'Inspect and customize payloads and headers sent during simulated audits'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-[4px] text-[#8c8c8c] hover:text-white hover:bg-[#262626] transition-colors cursor-pointer"
            aria-label="Close"
          >
            <CloseOutlined className="text-sm" />
          </button>
        </div>

        {/* Category Tabs */}
        <div className="px-4 py-2 border-b border-[#303030] bg-[#141414] flex gap-2 overflow-x-auto">
          {categories.map((cat) => {
            const meta = CATEGORY_METADATA[cat];
            const isActive = activeCategory === cat;
            const count = localProbes.filter((p) => p.category === cat && p.enabled).length;

            return (
              <button
                key={cat}
                type="button"
                onClick={() => setActiveCategory(cat)}
                className={`${STYLES.categoryTab} ${
                  isActive
                    ? 'bg-[#111d2c] text-[#1677ff] border-[#1677ff]'
                    : 'bg-[#1f1f1f] text-[#8c8c8c] border-[#303030] hover:text-white'
                }`}
              >
                <span>{isArabic ? meta.nameAr : meta.nameEn}</span>
                <span className="text-[10px] opacity-75 font-mono">({count})</span>
              </button>
            );
          })}
        </div>

        {/* Probes List */}
        <div className="p-4 overflow-y-auto space-y-3.5 flex-1 max-h-[60vh] bg-[#141414]">
          {filteredProbes.map((probe) => {
            const tagStyle = METHOD_TAGS[probe.method] || METHOD_TAGS.GET;

            return (
              <div
                key={probe.id}
                className="p-3.5 rounded-[6px] bg-[#1f1f1f] border border-[#303030] space-y-2.5 transition-all"
              >
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`${STYLES.methodTag} ${tagStyle}`}>
                      {probe.method}
                    </span>
                    <span className="font-mono text-xs font-semibold text-white">
                      {probe.name}
                    </span>
                    <span className="text-[11px] font-mono text-[#8c8c8c]">
                      {probe.targetPath}
                    </span>
                  </div>

                  <label className="flex items-center gap-1.5 cursor-pointer text-xs text-[#8c8c8c]">
                    <input
                      type="checkbox"
                      checked={probe.enabled}
                      onChange={() => handleToggleProbe(probe.id)}
                      className="rounded border-[#434343] text-[#1677ff] focus:ring-0"
                    />
                    <span>{isArabic ? 'تفعيل في الفحص' : 'Active'}</span>
                  </label>
                </div>

                <p className="text-xs text-[#8c8c8c]">
                  {isArabic ? probe.descriptionAr : probe.description}
                </p>

                {/* Editable payload input */}
                <div>
                  <textarea
                    value={probe.payloadCode}
                    onChange={(e) => handleUpdatePayload(probe.id, e.target.value)}
                    dir="ltr"
                    className={STYLES.codeBlock}
                    rows={2}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {/* Modal Bottom Actions */}
        <div className="p-3 sm:px-4 border-t border-[#303030] bg-[#1f1f1f] flex items-center justify-between">
          <button
            type="button"
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] text-xs font-medium text-[#8c8c8c] hover:text-white hover:bg-[#262626] border border-[#303030] transition-colors cursor-pointer"
          >
            <UndoOutlined className="text-xs" />
            <span>{isArabic ? 'استعادة الافتراضيات' : 'Reset Defaults'}</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded-[6px] text-xs font-medium text-[#8c8c8c] hover:text-white hover:bg-[#262626] border border-[#303030] transition-colors cursor-pointer"
            >
              {isArabic ? 'إلغاء' : 'Cancel'}
            </button>
            <button
              type="button"
              onClick={handleSave}
              className="flex items-center gap-1.5 px-4 py-1.5 rounded-[6px] text-xs font-medium bg-[#1677ff] hover:bg-[#4096ff] text-white border border-[#1677ff] transition-colors cursor-pointer"
            >
              <SaveOutlined className="text-xs" />
              <span>{isArabic ? 'حفظ الأكواد وإغلاق' : 'Save Changes'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
