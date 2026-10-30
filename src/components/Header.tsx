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
    <header className="border-b border-white/[0.1] bg-[#0c0c0e] sticky top-0 z-40">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
        {/* Brand Identity */}
        <BrandLogo lang={lang} size="sm" />

        {/* Action Tools */}
        <div className="flex items-center gap-2.5">
          {/* Running Status Pill */}
          {isRunning && (
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono">
              <SyncOutlined spin className="text-[11px]" />
              <span>{isArabic ? 'جاري الفحص المباشر...' : 'Auditing...'}</span>
            </div>
          )}

          {/* Overall Score Badge */}
          {score !== null && !isRunning && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/[0.06] border border-white/[0.12] text-xs font-mono">
              <span className="text-zinc-400">{isArabic ? 'التقييم:' : 'Score:'}</span>
              <span
                className={`font-bold text-sm ${
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
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium text-zinc-200 hover:text-white bg-white/[0.06] hover:bg-white/[0.12] border border-white/[0.15] transition-all cursor-pointer shadow-sm active:scale-95"
          >
            <BookOutlined className="text-xs text-zinc-400" />
            <span>{isArabic ? 'أكواد الحماية' : 'Defense Blueprints'}</span>
          </button>

          {/* Language Switcher Button */}
          <button
            type="button"
            onClick={onToggleLang}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-white/[0.08] hover:bg-white/[0.15] border border-white/[0.18] transition-all cursor-pointer shadow-sm active:scale-95"
          >
            <GlobalOutlined className="text-xs text-zinc-300" />
            <span className="font-semibold">{isArabic ? 'English' : 'العربية'}</span>
          </button>
        </div>
      </div>
    </header>
  );
}
