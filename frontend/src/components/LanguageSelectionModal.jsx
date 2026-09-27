import React, { useState } from 'react';
import { Globe, Shield, Check, ArrowRight, X } from 'lucide-react';
import { TRANSLATIONS } from '../i18n/translations';

const LANGUAGES = [
  {
    code: 'en',
    name: 'English',
    nativeName: 'English',
    region: 'National Standard (All India)',
    sample: 'Evidence-Driven AI Fraud Protection',
  },
  {
    code: 'hi',
    name: 'Hindi',
    nativeName: 'हिन्दी',
    region: 'भारत सरकार आधिकारिक भाषा',
    sample: 'साक्ष्य-आधारित साइबर सुरक्षा एवं नागरिक रक्षा',
  },
  {
    code: 'gu',
    name: 'Gujarati',
    nativeName: 'ગુજરાતી',
    region: 'ગુજરાત રાજ્ય (BSides Ahmedabad)',
    sample: 'પુરાવા-આધારિત સાયબર સુરક્ષા વ્યવસ્થા',
  },
  {
    code: 'ta',
    name: 'Tamil',
    nativeName: 'தமிழ்',
    region: 'தமிழ்நாடு & புதுச்சேரி',
    sample: 'சான்று அடிப்படையிலான சைபர் பாதுகாப்பு அமைப்பு',
  },
  {
    code: 'te',
    name: 'Telugu',
    nativeName: 'తెలుగు',
    region: 'ఆంధ్రప్రదేశ్ & తెలంగాణ',
    sample: 'సాక్ష్య ఆధారిత సైబర్ పౌర రక్షణ వ్యవస్థ',
  },
  {
    code: 'bn',
    name: 'Bengali',
    nativeName: 'বাংলা',
    region: 'পশ্চিমবঙ্গ & ত্রিপুরা',
    sample: 'প্রমাণ-ভিত্তিক সাইবার নিরাপত্তা ও নাগরিক সুরক্ষা',
  },
];

export default function LanguageSelectionModal({ isOpen, currentLang, onSelectLanguage, onClose, canClose = true }) {
  const [selected, setSelected] = useState(currentLang || 'en');

  if (!isOpen) return null;

  const t = (key) => {
    const langObj = TRANSLATIONS[selected] || TRANSLATIONS.en;
    return langObj[key] || TRANSLATIONS.en[key] || key;
  };

  const handleConfirm = () => {
    onSelectLanguage(selected);
    if (onClose) onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
      <div className="bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header with Shield Motif */}
        <div className="bg-gradient-to-r from-blue-950/80 via-slate-900 to-indigo-950/80 p-6 border-b border-slate-800 flex items-start justify-between">
          <div className="flex items-center gap-3.5">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
              <Globe className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] font-bold uppercase tracking-wider text-cyan-400 bg-cyan-950/80 border border-cyan-800/60 px-2 py-0.5 rounded">
                  IRCTC-Style Citizen Gateway
                </span>
              </div>
              <h2 className="text-xl font-bold text-white mt-1">
                {t('langSelectTitle')}
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                {t('langSelectSub')}
              </p>
            </div>
          </div>

          {canClose && (
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Language Selection Grid */}
        <div className="p-6 overflow-y-auto grid grid-cols-1 sm:grid-cols-2 gap-3.5">
          {LANGUAGES.map((lang) => {
            const isChosen = selected === lang.code;
            return (
              <button
                key={lang.code}
                type="button"
                onClick={() => setSelected(lang.code)}
                className={`relative flex flex-col text-left p-4 rounded-xl border transition-all duration-150 ${
                  isChosen
                    ? 'bg-gradient-to-br from-cyan-950/60 to-blue-950/40 border-cyan-500 shadow-md shadow-cyan-500/10'
                    : 'bg-slate-800/50 hover:bg-slate-800 border-slate-700/60 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <span className="text-lg font-bold text-white tracking-wide">
                      {lang.nativeName}
                    </span>
                    <span className="text-xs text-slate-400 font-medium">
                      ({lang.name})
                    </span>
                  </div>
                  <div
                    className={`w-5 h-5 rounded-full flex items-center justify-center text-xs transition-colors ${
                      isChosen
                        ? 'bg-cyan-500 text-slate-950 font-bold'
                        : 'border border-slate-600 text-transparent'
                    }`}
                  >
                    <Check className="w-3.5 h-3.5" />
                  </div>
                </div>

                <span className="text-[11px] text-cyan-300/80 font-medium mb-1">
                  {lang.region}
                </span>

                <span className="text-xs text-slate-400 line-clamp-1 italic mt-auto">
                  "{lang.sample}"
                </span>
              </button>
            );
          })}
        </div>

        {/* Modal Footer */}
        <div className="bg-slate-950/80 p-5 border-t border-slate-800 flex items-center justify-between flex-wrap gap-3">
          <span className="text-xs text-slate-400">
            {t('changeLangAnytime')}
          </span>

          <button
            type="button"
            onClick={handleConfirm}
            className="flex items-center gap-2 px-6 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl shadow-lg shadow-cyan-500/20 transition-all hover:scale-[1.02] active:scale-[0.98]"
          >
            <span>{t('continueInLang')}</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
