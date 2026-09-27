import React, { useState, useRef } from 'react';
import { 
  FileText, 
  ImageUp, 
  ClipboardPaste, 
  Eraser, 
  ShieldCheck, 
  Search, 
  ChevronDown, 
  ChevronUp,
  Loader2,
  AlertCircle,
  Link as LinkIcon
} from 'lucide-react';
import { uploadScreenshot } from '../services/api';
import { TRANSLATIONS } from '../i18n/translations';

export default function InputForm({ 
  formData, 
  onFormChange, 
  onSubmit, 
  isAnalyzing, 
  lang 
}) {
  const [isUploadingOcr, setIsUploadingOcr] = useState(false);
  const [ocrStatus, setOcrStatus] = useState(null);
  const [showUrlField, setShowUrlField] = useState(Boolean(formData.urls));
  const [validationError, setValidationError] = useState(null);
  const fileInputRef = useRef(null);

  const t = TRANSLATIONS[lang] || TRANSLATIONS.en;

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onFormChange({ ...formData, message: (formData.message ? formData.message + '\n' : '') + text });
        setValidationError(null);
      }
    } catch {
      // Fallback
    }
  };

  const handleClear = () => {
    onFormChange({
      ...formData,
      message: '',
      urls: '',
    });
    setOcrStatus(null);
    setValidationError(null);
  };

  const handleScreenshotUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > 10 * 1024 * 1024) {
      setOcrStatus({ error: 'Image exceeds maximum 10MB limit.' });
      return;
    }

    setIsUploadingOcr(true);
    setOcrStatus({ loading: 'Scanning screenshot via Optical Character Recognition (OCR)...' });

    try {
      const res = await uploadScreenshot(file);
      if (res.extracted_text && res.extracted_text.trim()) {
        onFormChange({
          ...formData,
          message: res.extracted_text.trim(),
        });
        setValidationError(null);
        setOcrStatus({ success: `Successfully extracted text from "${res.filename}" (${res.extracted_text.length} chars)` });
      } else {
        setOcrStatus({ error: 'No legible text could be extracted from image. Please paste manually.' });
      }
    } catch (err) {
      setOcrStatus({ error: err.message || 'OCR processing failed. Please paste text directly.' });
    } finally {
      setIsUploadingOcr(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const handleFormSubmit = (e) => {
    if (e) e.preventDefault();
    if (!formData.message || !formData.message.trim()) {
      setValidationError('Please enter or paste a suspicious message to analyze, or select a preset scenario above.');
      return;
    }
    setValidationError(null);
    onSubmit(e);
  };

  const charCount = (formData.message || '').length;

  return (
    <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-4 sm:p-5 shadow-xs dark:shadow-card-elevated mb-4 transition-colors">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-2.5 mb-3 border-b border-slate-200 dark:border-slate-800 gap-2">
        <div className="flex items-center space-x-2">
          <span className="px-2 py-0.5 rounded bg-blue-100 text-blue-900 dark:bg-blue-900/80 dark:text-blue-300 font-mono text-[10px] font-bold border border-blue-200 dark:border-blue-700/60 uppercase">
            {t.analyzeStep}
          </span>
          <h2 className="text-sm sm:text-base font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
            <FileText className="w-4 h-4 text-amber-600 dark:text-amber-400" />
            <span>{t.analyzeTitle}</span>
          </h2>
        </div>

        {/* Action Tools */}
        <div className="flex items-center space-x-1.5 self-end sm:self-auto">
          {/* OCR Upload Button */}
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleScreenshotUpload} 
            accept="image/png,image/jpeg,image/webp" 
            className="hidden" 
            id="ocr-file-input"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={isUploadingOcr || isAnalyzing}
            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200 dark:border-slate-700 text-xs font-medium transition-colors disabled:opacity-50 cursor-pointer shadow-xs"
            title="Upload image or screenshot to extract text using OCR"
          >
            {isUploadingOcr ? <Loader2 className="w-3.5 h-3.5 animate-spin text-amber-500" /> : <ImageUp className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />}
            <span>{t.ocrBtn}</span>
          </button>

          {/* Paste from Clipboard */}
          <button
            type="button"
            onClick={handlePaste}
            disabled={isAnalyzing}
            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-200 dark:border-slate-700 text-xs font-medium transition-colors cursor-pointer shadow-xs"
            title="Paste text from clipboard"
          >
            <ClipboardPaste className="w-3.5 h-3.5 text-slate-600 dark:text-slate-400" />
            <span>{t.pasteBtn}</span>
          </button>

          {/* Clear Form */}
          <button
            type="button"
            onClick={handleClear}
            disabled={isAnalyzing}
            className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 text-slate-600 border border-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 dark:text-slate-300 dark:border-slate-700 text-xs font-medium transition-colors cursor-pointer shadow-xs"
            title="Clear all fields"
          >
            <Eraser className="w-3.5 h-3.5 text-slate-500" />
            <span>{t.clearBtn}</span>
          </button>
        </div>
      </div>

      {/* OCR Status Banner */}
      {ocrStatus && (
        <div className={`mb-2.5 p-2 rounded text-xs flex items-center space-x-2 border ${
          ocrStatus.error ? 'bg-red-50 text-red-800 border-red-200 dark:bg-red-950/50 dark:border-red-800 dark:text-red-300' :
          ocrStatus.loading ? 'bg-blue-50 text-blue-800 border-blue-200 dark:bg-blue-950/50 dark:border-blue-800 dark:text-blue-300' :
          'bg-emerald-50 text-emerald-800 border-emerald-200 dark:bg-emerald-950/50 dark:border-emerald-800 dark:text-emerald-300'
        }`}>
          {ocrStatus.error && <AlertCircle className="w-4 h-4 flex-shrink-0" />}
          {ocrStatus.loading && <Loader2 className="w-4 h-4 flex-shrink-0 animate-spin" />}
          {ocrStatus.success && <ShieldCheck className="w-4 h-4 flex-shrink-0 text-emerald-600 dark:text-emerald-400" />}
          <span>{ocrStatus.error || ocrStatus.loading || ocrStatus.success}</span>
        </div>
      )}

      {/* Main Analysis Form */}
      <form id="analyze-form" onSubmit={handleFormSubmit} noValidate className="space-y-3">
        {/* Message Input Textarea */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <label htmlFor="message-input" className="text-xs font-bold text-slate-900 dark:text-slate-200">
              {t.messageLabel} <span className="text-red-600 dark:text-red-400 font-bold">*</span>
              <span className="text-slate-500 dark:text-slate-400 font-normal ml-1 hidden sm:inline">{t.messageHint}</span>
            </label>
            <span className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
              {charCount} characters
            </span>
          </div>

          <textarea
            id="message-input"
            rows={3}
            value={formData.message}
            onChange={(e) => {
              onFormChange({ ...formData, message: e.target.value });
              if (validationError) setValidationError(null);
            }}
            placeholder="Paste suspicious SMS, WhatsApp message, email, or select a scenario above..."
            className={`w-full bg-slate-50 text-slate-900 placeholder-slate-400 border rounded-lg p-3 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/50 focus:border-amber-500 dark:bg-slate-950 dark:text-slate-100 dark:placeholder-slate-500 transition-all font-sans leading-relaxed resize-y ${
              validationError ? 'border-red-500 ring-1 ring-red-500' : 'border-slate-300 dark:border-slate-700'
            }`}
          />

          {validationError && (
            <p className="mt-1 text-xs text-red-600 dark:text-red-400 font-semibold flex items-center space-x-1">
              <AlertCircle className="w-3.5 h-3.5 inline mr-1 flex-shrink-0" />
              <span>{validationError}</span>
            </p>
          )}
        </div>

        {/* Responsive Grid: Channel Select & Citizen State Select */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
          {/* Channel Selector */}
          <div>
            <label htmlFor="input-type" className="block text-xs font-bold text-slate-900 dark:text-slate-300 mb-1">
              {t.channelLabel}
            </label>
            <select
              id="input-type"
              value={formData.input_type}
              onChange={(e) => onFormChange({ ...formData, input_type: e.target.value })}
              className="w-full bg-slate-50 text-slate-900 border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/50 dark:bg-slate-950 dark:text-slate-200 dark:border-slate-700 cursor-pointer"
            >
              <option value="sms">SMS / Text Message</option>
              <option value="chat">WhatsApp / Telegram / Chat</option>
              <option value="email">Email Message</option>
              <option value="text">General Document / Text</option>
            </select>
          </div>

          {/* Citizen Situation State Selector */}
          <div>
            <label htmlFor="user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-300 mb-1">
              {t.situationLabel} <span className="text-red-600 dark:text-red-400 font-bold">*</span>
            </label>
            <select
              id="user-state"
              value={formData.user_state}
              onChange={(e) => onFormChange({ ...formData, user_state: e.target.value })}
              className={`w-full border rounded-lg px-2.5 py-1.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-amber-500/50 cursor-pointer font-medium ${
                formData.user_state === 'paid' 
                  ? 'border-red-500 text-red-900 bg-red-50 dark:border-red-600 dark:text-red-300 dark:bg-red-950/20' 
                  : formData.user_state === 'entered_credentials'
                  ? 'border-amber-500 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/20'
                  : 'bg-slate-50 text-slate-900 border-slate-300 dark:bg-slate-950 dark:text-slate-200 dark:border-slate-700'
              }`}
            >
              <option value="received">{t.sitReceived}</option>
              <option value="clicked">{t.sitClicked}</option>
              <option value="entered_credentials">{t.sitEntered}</option>
              <option value="paid">{t.sitPaid}</option>
            </select>
          </div>
        </div>

        {/* Collapsible Secondary URLs Input */}
        <div>
          <button
            type="button"
            onClick={() => setShowUrlField(!showUrlField)}
            className="flex items-center space-x-1.5 text-xs text-slate-600 hover:text-blue-700 dark:text-slate-400 dark:hover:text-amber-400 transition-colors focus:outline-none cursor-pointer"
          >
            <LinkIcon className="w-3.5 h-3.5" />
            <span className="font-semibold">{t.additionalUrls}</span>
            <span className="text-slate-500">{t.additionalUrlsHint}</span>
            {showUrlField ? <ChevronUp className="w-3 h-3 ml-1" /> : <ChevronDown className="w-3 h-3 ml-1" />}
          </button>

          {showUrlField && (
            <div className="mt-1.5">
              <textarea
                id="urls-input"
                rows={2}
                value={formData.urls}
                onChange={(e) => onFormChange({ ...formData, urls: e.target.value })}
                placeholder="https://sbi-kyc-verify-urgent.com/login&#10;https://power-bill-payment.top"
                className="w-full bg-slate-50 text-slate-900 placeholder-slate-400 border border-slate-300 rounded-lg p-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-amber-500/50 dark:bg-slate-950 dark:text-slate-100 dark:placeholder-slate-600 dark:border-slate-700"
              />
            </div>
          )}
        </div>

        {/* Action Row: Primary Submit Button + Inline Privacy Guarantee */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 border-t border-slate-200 dark:border-slate-800">
          <button
            type="submit"
            id="analyze-btn"
            disabled={isAnalyzing}
            className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-8 py-2.5 bg-gradient-to-r from-amber-500 to-amber-400 hover:from-amber-400 hover:to-amber-300 active:from-amber-600 active:to-amber-500 text-slate-950 font-bold rounded-lg text-sm shadow-sm hover:shadow-md transition-all duration-150 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
                <span>{t.analyzingBtn}</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4 text-slate-950" strokeWidth={2.4} />
                <span>{t.analyzeBtn}</span>
              </>
            )}
          </button>

          <div className="flex items-center space-x-2 text-[11px] text-slate-500 dark:text-slate-400">
            <ShieldCheck className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
            <span><strong className="text-slate-700 dark:text-slate-300">Zero Retention:</strong> Ephemeral analysis only. Aadhaar & OTP numbers masked in-memory.</span>
          </div>
        </div>
      </form>
    </section>
  );
}
