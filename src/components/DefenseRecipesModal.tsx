'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React, { useState } from 'react';
import {
  BookOutlined,
  CloseOutlined,
  CopyOutlined,
  CheckOutlined,
  CodeOutlined,
} from '@ant-design/icons';
import { REMEDIATION_RECIPES } from '@/lib/constants';

// ============================================================================
// 2. CONFIGURATION & STYLES (ANT DESIGN DARK THEME)
// ============================================================================
const STYLES = {
  backdrop:
    'fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-3 sm:p-5 overflow-y-auto animate-in fade-in duration-150',
  modal:
    'bg-[#1f1f1f] border border-[#303030] rounded-[8px] w-full max-w-3xl max-h-[85vh] flex flex-col shadow-2xl overflow-hidden',
  recipeBtn:
    'px-3 py-2 rounded-[4px] text-xs font-medium text-start transition-all cursor-pointer border',
  codeBlock:
    'font-mono text-xs p-4 rounded-[6px] bg-[#141414] border border-[#303030] text-[#d9d9d9] overflow-x-auto select-all',
};

// ============================================================================
// 3. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface DefenseRecipesModalProps {
  isOpen: boolean;
  onClose: () => void;
  lang: 'ar' | 'en';
}

type RecipeKey = keyof typeof REMEDIATION_RECIPES;

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function DefenseRecipesModal({
  isOpen,
  onClose,
  lang,
}: DefenseRecipesModalProps) {
  const isArabic = lang === 'ar';
  const [activeRecipe, setActiveRecipe] = useState<RecipeKey>('headers');
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const current = REMEDIATION_RECIPES[activeRecipe];

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(current.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  }

  const recipeKeys: RecipeKey[] = [
    'headers',
    'sqli',
    'cors',
    'xss',
    'ssrf',
    'rate_limiting',
    'mass_assignment',
    'idor',
  ];

  return (
    <div className={STYLES.backdrop} role="dialog" aria-modal="true">
      <div className={STYLES.modal}>
        {/* Header */}
        <div className="p-4 border-b border-[#303030] flex items-center justify-between bg-[#1f1f1f]">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-[6px] bg-[#111d2c] border border-[#153450] flex items-center justify-center text-[#1677ff]">
              <BookOutlined className="text-sm" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">
                {isArabic
                  ? 'كتيب الأكواد الدفاعية الجاهزة للمواقع'
                  : 'Instant Security Defense Blueprints'}
              </h2>
              <p className="text-xs text-[#8c8c8c]">
                {isArabic
                  ? 'حلول برمجية جاهزة للنسخ تحمي موقعك من ثغرات الحقن والترويسات'
                  : 'Production-ready code snippets to fortify your Next.js and Node.js applications'}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-[4px] text-[#8c8c8c] hover:text-white hover:bg-[#262626] transition-colors cursor-pointer"
          >
            <CloseOutlined className="text-sm" />
          </button>
        </div>

        {/* Recipe Selection Tabs */}
        <div className="p-3 border-b border-[#303030] bg-[#141414] grid grid-cols-2 sm:grid-cols-4 gap-2">
          {recipeKeys.map((key) => {
            const r = REMEDIATION_RECIPES[key];
            const isSelected = activeRecipe === key;

            return (
              <button
                key={key}
                type="button"
                onClick={() => setActiveRecipe(key)}
                className={`${STYLES.recipeBtn} ${
                  isSelected
                    ? 'bg-[#111d2c] border-[#1677ff] text-[#1677ff]'
                    : 'bg-[#1f1f1f] border-[#303030] text-[#8c8c8c] hover:text-white'
                }`}
              >
                <span>{isArabic ? r.titleAr : r.titleEn}</span>
              </button>
            );
          })}
        </div>

        {/* Recipe Body */}
        <div className="p-4 overflow-y-auto space-y-3.5 flex-1 bg-[#141414]">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <div className="flex items-center gap-2">
              <CodeOutlined className="text-xs text-[#1677ff]" />
              <span className="text-xs font-semibold text-white">
                {isArabic ? current.titleAr : current.titleEn}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-[4px] bg-[#1f1f1f] text-[#8c8c8c] border border-[#303030]">
                {current.fileName}
              </span>
            </div>

            <button
              type="button"
              onClick={handleCopy}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-[6px] text-xs font-medium bg-[#1677ff] hover:bg-[#4096ff] text-white border border-[#1677ff] transition-colors cursor-pointer"
            >
              {copied ? (
                <>
                  <CheckOutlined className="text-xs" />
                  <span>{isArabic ? 'تم النسخ!' : 'Copied!'}</span>
                </>
              ) : (
                <>
                  <CopyOutlined className="text-xs" />
                  <span>{isArabic ? 'نسخ الكود' : 'Copy Code'}</span>
                </>
              )}
            </button>
          </div>

          <pre className={STYLES.codeBlock} dir="ltr">
            {current.code}
          </pre>
        </div>

        {/* Footer */}
        <div className="p-3 border-t border-[#303030] bg-[#1f1f1f] flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-[6px] text-xs font-medium bg-[#141414] hover:bg-[#262626] text-[#d9d9d9] hover:text-white border border-[#303030] transition-colors cursor-pointer"
          >
            {isArabic ? 'إغلاق' : 'Close'}
          </button>
        </div>
      </div>
    </div>
  );
}
