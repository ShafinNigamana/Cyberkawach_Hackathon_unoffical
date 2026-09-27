import React from 'react';
import { 
  Zap, 
  Building2, 
  PackageCheck, 
  QrCode, 
  Briefcase, 
  Scale, 
  ShieldCheck,
  FlaskConical
} from 'lucide-react';
import { PRESET_SCENARIOS } from '../data/presets';
import { TRANSLATIONS } from '../i18n/translations';

const ICON_MAP = {
  Zap: Zap,
  Building2: Building2,
  PackageCheck: PackageCheck,
  QrCode: QrCode,
  Briefcase: Briefcase,
  Scale: Scale,
  ShieldCheck: ShieldCheck,
};

export default function PresetChips({ onSelectPreset, activePresetId, lang }) {
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  return (
    <section className="w-full mb-3" aria-label="Indian Cyber Fraud Presets">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
        <div className="flex items-center space-x-1.5 text-xs font-bold text-slate-800 dark:text-slate-200">
          <FlaskConical className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
          <span>{t.presetsTitle}:</span>
        </div>
        <span className="text-[11px] text-slate-500 dark:text-slate-400">
          {t.presetsSubtext}
        </span>
      </div>

      <div className="flex flex-wrap gap-1.5">
        {PRESET_SCENARIOS.map((preset) => {
          const IconComponent = ICON_MAP[preset.iconName] || Zap;
          const isSelected = activePresetId === preset.id;

          const baseClass = "inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs font-medium border transition-all duration-150 cursor-pointer shadow-xs focus:outline-none";
          
          let colorClass = "bg-white text-slate-800 border-slate-300 hover:bg-slate-50 hover:border-slate-400 dark:bg-slate-900/90 dark:text-slate-200 dark:border-slate-700 dark:hover:bg-slate-800";
          
          if (preset.isSafe) {
            colorClass = isSelected
              ? "bg-emerald-100 text-emerald-950 border-emerald-600 ring-2 ring-emerald-500/40 font-bold dark:bg-emerald-950 dark:text-emerald-200 dark:border-emerald-500"
              : "bg-emerald-50/70 text-emerald-900 border-emerald-300 hover:bg-emerald-100/70 dark:bg-emerald-950/40 dark:text-emerald-300 dark:border-emerald-800";
          } else if (isSelected) {
            colorClass = "bg-amber-100 text-amber-950 border-amber-600 ring-2 ring-amber-500/40 font-bold dark:bg-amber-950/90 dark:text-amber-200 dark:border-amber-500";
          }

          return (
            <button
              key={preset.id}
              type="button"
              onClick={() => onSelectPreset(preset)}
              className={`${baseClass} ${colorClass}`}
              title={`Load test scenario: ${preset.title}`}
            >
              <IconComponent 
                className={`w-3.5 h-3.5 ${preset.isSafe ? 'text-emerald-600 dark:text-emerald-400' : 'text-amber-600 dark:text-amber-400'}`} 
                strokeWidth={2} 
              />
              <span>{preset.title}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
