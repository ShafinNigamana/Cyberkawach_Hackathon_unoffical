import React from 'react';
import { AlertTriangle, PhoneCall, ExternalLink, ShieldAlert } from 'lucide-react';
import { TRANSLATIONS } from '../i18n/translations';

export default function EmergencyBanner({ lang }) {
  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  return (
    <aside 
      className="bg-rose-50/90 dark:bg-rose-950/40 border-b border-rose-200/90 dark:border-rose-900/60 text-rose-950 dark:text-rose-200 px-4 py-2.5 transition-colors select-none" 
      role="alert" 
      aria-label="Golden Hour Emergency Financial Fraud Alert"
    >
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3 min-w-0">
          <div className="w-7 h-7 rounded-lg bg-rose-600 text-white flex items-center justify-center flex-shrink-0 shadow-xs">
            <ShieldAlert className="w-4 h-4 animate-pulse" />
          </div>
          <div className="text-xs leading-snug">
            <span className="font-extrabold text-rose-900 dark:text-rose-100 uppercase tracking-wide mr-2 text-[11px] bg-rose-100 dark:bg-rose-900/60 px-1.5 py-0.5 rounded border border-rose-300 dark:border-rose-800">
              {t.goldenHourTitle || 'Golden Hour Advisory'}
            </span>
            <span className="text-rose-800 dark:text-rose-200 font-medium">
              {t.goldenHourText || 'If financial fraud occurred within the last 2 hours, immediately dial 1930 to freeze transaction routes.'}
            </span>
          </div>
        </div>

        <div className="flex items-center space-x-2 self-end md:self-auto flex-shrink-0">
          <a
            href="tel:1930"
            className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 bg-rose-600 hover:bg-rose-700 text-white font-bold rounded-lg text-xs shadow-xs transition-all duration-150 active:scale-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-rose-500"
            title="Immediately call National Cyber Crime Helpline 1930"
          >
            <PhoneCall className="w-3.5 h-3.5" />
            <span>{t.call1930 || 'Call 1930'}</span>
          </a>
          <a
            href="https://cybercrime.gov.in"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-300/80 dark:bg-night-850 dark:hover:bg-night-800 dark:text-slate-200 dark:border-night-border rounded-lg text-xs font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 shadow-2xs"
            title="Open cybercrime.gov.in"
          >
            <span>cybercrime.gov.in</span>
            <ExternalLink className="w-3 h-3 text-slate-400" />
          </a>
        </div>
      </div>
    </aside>
  );
}
