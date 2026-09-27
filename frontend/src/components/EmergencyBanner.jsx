import React from 'react';
import { AlertTriangle, PhoneCall, ExternalLink } from 'lucide-react';
import { TRANSLATIONS } from '../i18n/translations';

export default function EmergencyBanner({ lang }) {
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  return (
    <aside 
      className="bg-red-50 border-y border-red-200 text-red-900 dark:bg-red-950/60 dark:border-red-900/60 dark:text-red-200 px-4 py-2 transition-colors" 
      role="alert" 
      aria-label="Golden Hour Emergency Financial Fraud Alert"
    >
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-2.5">
        <div className="flex items-center space-x-2.5">
          <div className="p-1 bg-red-100 dark:bg-red-900/60 rounded text-red-700 dark:text-red-400 flex-shrink-0">
            <AlertTriangle className="w-4 h-4 text-red-700 dark:text-red-400" />
          </div>
          <div className="text-xs">
            <strong className="text-red-950 dark:text-red-200 font-bold mr-1.5 uppercase tracking-wide">
              {t.goldenHourTitle}:
            </strong>
            <span className="text-red-900 dark:text-red-300 font-medium">
              {t.goldenHourText}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-2 self-end md:self-auto flex-shrink-0">
          <a
            href="tel:1930"
            className="inline-flex items-center space-x-1 px-3 py-1 bg-red-600 hover:bg-red-700 text-white font-bold rounded text-xs shadow-xs transition-all active:scale-95"
            title="Immediately call National Cyber Crime Helpline 1930"
          >
            <PhoneCall className="w-3.5 h-3.5" />
            <span>{t.call1930}</span>
          </a>
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center space-x-1 px-2.5 py-1 bg-white hover:bg-slate-100 text-slate-800 border border-slate-300 dark:bg-slate-900 dark:hover:bg-slate-800 dark:text-slate-300 dark:hover:text-white dark:border-slate-700 rounded text-xs font-medium transition-colors"
            title="Open cybercrime.gov.in"
          >
            <span>cybercrime.gov.in</span>
            <ExternalLink className="w-3 h-3 text-slate-500 dark:text-slate-400" />
          </a>
        </div>
      </div>
    </aside>
  );
}
