'use client';

// ============================================================================
// 1. IMPORTS
// ============================================================================
import React from 'react';
import BrandLogo from './BrandLogo';
import {
  BookOutlined,
  GlobalOutlined,
  SyncOutlined,
} from '@ant-design/icons';

// ============================================================================
// 2. TYPES & INTERFACES (ZONE 3)
// ============================================================================
interface HeaderProps {
  lang: 'ar' | 'en';
  onToggleLang: () => void;
  onOpenRecipes: () => void;
  isRunning: boolean;
  score: number | null;
}

// ============================================================================
// 6. MAIN COMPONENT (ZONE 6)
// ============================================================================
export default function Header({
  lang,
  onToggleLang,
  onOpenRecipes,
  isRunning,
  score,
}: HeaderProps) {
  const isArabic = lang === 'ar';

  return (
    <header className="border-b border-white/[0.08] bg-black sticky top-0 z-40">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 h-13 flex items-center justify-between">
        {/* Brand Identity */}
        <BrandLogo lang={lang} size="sm" />

        {/* Action Tools */}
        <div className="flex items-center gap-2">
          {/* Running Status Indicator */}
          {isRunning && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs font-mono">
              <SyncOutlined spin className="text-[11px]" />
              <span>{isArabic ? 'جاري الفحص المباشر...' : 'Auditing...'}</span>
            </div>
          )}

          {/* Overall Score if completed */}
          {score !== null && !isRunning && (
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-white/[0.04] border border-white/[0.08] text-xs font-mono">
              <span className="text-zinc-500">{isArabic ? 'التقييم:' : 'Score:'}</span>
              <span
                className={`font-bold ${
                  score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-red-400'
                }`}
              >
                {score}/100
              </span>
            </div>
          )}

          {/* Defense Quick Recipes Button */}
          <button
            type="button"
            onClick={onOpenRecipes}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs text-zinc-300 hover:text-white bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.08] transition-colors cursor-pointer"
          >
            <BookOutlined className="text-xs" />
            <span className="hidden sm:inline">
              {isArabic ? 'أكواد الحماية' : 'Defense Recipes'}
            </span>
          </button>

          {/* Language Switcher */}
          <button
            type="button"
            onClick={onToggleLang}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded text-xs text-zinc-400 hover:text-white bg-transparent hover:bg-white/[0.04] transition-colors cursor-pointer"
            title={isArabic ? 'Switch to English' : 'التحويل للعربية'}
          >
            <GlobalOutlined className="text-xs" />
            <span className="font-mono uppercase">{lang}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
