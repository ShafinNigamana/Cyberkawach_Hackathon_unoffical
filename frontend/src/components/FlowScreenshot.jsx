import React, { useState, useRef } from 'react';
import { 
  ArrowLeft, 
  Camera, 
  UploadCloud, 
  Image as ImageIcon, 
  X, 
  FileText, 
  Globe, 
  Search, 
  Loader2, 
  AlertCircle, 
  ShieldCheck, 
  CheckCircle2,
  ScanText
} from 'lucide-react';
import { uploadScreenshot } from '../services/api';
import { t } from '../i18n/translations';

export default function FlowScreenshot({ onBack, onSubmit, isAnalyzing, lang = 'en' }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [isOcrProcessing, setIsOcrProcessing] = useState(false);
  const [ocrResult, setOcrResult] = useState(null);
  const [extractedText, setExtractedText] = useState('');
  const [extractedUrls, setExtractedUrls] = useState('');
  const [userState, setUserState] = useState('received');
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileSelect = (file) => {
    if (!file) return;

    if (!file.type.startsWith('image/')) {
      setError('Please upload a valid image file (PNG, JPG, JPEG, WEBP).');
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setError('Image exceeds maximum 10MB file limit.');
      return;
    }

    setError(null);
    setSelectedFile(file);
    const objectUrl = URL.createObjectURL(file);
    setPreviewUrl(objectUrl);
    setOcrResult(null);
    setExtractedText('');
    setExtractedUrls('');

    // Automatically trigger OCR for seamless citizen experience
    runOcr(file);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (file) handleFileSelect(file);
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleClear = () => {
    if (previewUrl) URL.revokeObjectURL(previewUrl);
    setSelectedFile(null);
    setPreviewUrl(null);
    setOcrResult(null);
    setExtractedText('');
    setExtractedUrls('');
    setError(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const runOcr = async (fileToScan) => {
    const file = fileToScan || selectedFile;
    if (!file) return;

    setIsOcrProcessing(true);
    setError(null);

    try {
      const res = await uploadScreenshot(file);
      setOcrResult(res);

      const rawText = res.extracted_text || '';
      setExtractedText(rawText);

      // Extract URLs from the OCR text
      const urlRegex = /(https?:\/\/[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi;
      const detected = rawText.match(urlRegex) || [];
      if (detected.length > 0) {
        setExtractedUrls(detected.join('\n'));
      }
    } catch (err) {
      setError(err.message || 'Optical Character Recognition (OCR) scan failed.');
    } finally {
      setIsOcrProcessing(false);
    }
  };

  const handleContinueAnalysis = (e) => {
    if (e) e.preventDefault();
    if (!extractedText.trim()) {
      setError('Please scan an image with legible text, or type the observed message content manually.');
      return;
    }

    setError(null);
    onSubmit({
      message: extractedText.trim(),
      urls: extractedUrls,
      input_type: 'screenshot',
      user_state: userState,
    });
  };

  return (
    <div className="w-full max-w-3xl mx-auto space-y-5">
      {/* ─── Breadcrumb & Navigation Header ─── */}
      <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
        <button
          type="button"
          onClick={onBack}
          className="inline-flex items-center space-x-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 dark:text-slate-400 dark:hover:text-white transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>{t(lang, 'backToSelection', 'Back to Task Selection')}</span>
        </button>

        <span className="text-xs font-mono font-medium text-slate-500 dark:text-slate-400">
          {t(lang, 'flowScreenshotBreadcrumb', 'Flow: Check Screenshot / Photo')}
        </span>
      </div>

      {/* ─── Flow Title ─── */}
      <div className="space-y-1">
        <div className="flex items-center space-x-2">
          <div className="w-8 h-8 rounded-lg bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900 flex items-center justify-center flex-shrink-0">
            <Camera className="w-4 h-4" />
          </div>
          <h2 className="text-xl font-extrabold text-slate-900 dark:text-white">
            {t(lang, 'flowScreenshotTitle', 'Inspect Screenshot or Photo')}
          </h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400 pl-10">
          {t(lang, 'flowScreenshotDesc', 'Upload or drag-and-drop a screenshot of a suspicious message, payment request, or chat notification.')}
        </p>
      </div>

      {/* ─── Error Notification ─── */}
      {error && (
        <div className="p-3 bg-red-50 border border-red-200 text-red-800 dark:bg-red-950/60 dark:border-red-800 dark:text-red-300 rounded-lg text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0 text-red-600 dark:text-red-400" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-800 font-bold hover:underline ml-2">
            Dismiss
          </button>
        </div>
      )}

      {/* ─── Step 1: Upload / Drop Zone ─── */}
      {!selectedFile ? (
        <div
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onClick={() => fileInputRef.current?.click()}
          className="luxury-card border-2 border-dashed border-indigo-400/40 dark:border-violet-500/30 hover:border-violet-500 dark:hover:border-violet-400 rounded-2xl p-10 text-center transition-all cursor-pointer space-y-4"
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => handleFileSelect(e.target.files?.[0])}
            accept="image/png,image/jpeg,image/webp"
            className="hidden"
            id="screenshot-input"
          />

          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-purple-500/20 to-indigo-500/20 text-purple-600 dark:text-violet-400 flex items-center justify-center mx-auto border border-purple-500/30 shadow-luxury-glow">
            <UploadCloud className="w-7 h-7" />
          </div>

          <div className="space-y-1.5">
            <p className="text-base font-bold text-slate-900 dark:text-white">
              {t(lang, 'dropzoneTitle', 'Click to select image or drag & drop screenshot here')}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 max-w-md mx-auto">
              {t(lang, 'dropzoneSubtitle', 'Supports PNG, JPG, JPEG, WEBP up to 10MB. Works on mobile camera & gallery.')}
            </p>
          </div>

          <button
            type="button"
            className="inline-flex items-center space-x-2 px-5 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white dark:bg-gradient-to-r dark:from-purple-600 dark:to-indigo-600 dark:hover:from-purple-500 dark:hover:to-indigo-500 text-xs font-bold shadow-luxury-glow cursor-pointer transition-all active:scale-95"
          >
            <Camera className="w-4 h-4" />
            <span>{t(lang, 'browseImage', 'Browse Image File')}</span>
          </button>
        </div>
      ) : (
        /* Image Preview & OCR State Box */
        <div className="luxury-card p-6 space-y-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-night-border">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-slate-100 dark:bg-night-800 rounded-xl text-purple-500">
                <ImageIcon className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-xs font-bold text-slate-900 dark:text-white truncate max-w-xs sm:max-w-md">
                  {selectedFile.name}
                </h4>
                <span className="text-[11px] text-slate-500 font-mono">
                  {(selectedFile.size / 1024).toFixed(1)} KB
                </span>
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <button
                type="button"
                onClick={() => runOcr()}
                disabled={isOcrProcessing}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 dark:bg-night-800 dark:hover:bg-night-750 text-slate-700 dark:text-slate-300 text-xs font-semibold transition-colors cursor-pointer border border-slate-200 dark:border-night-border"
              >
                <ScanText className="w-3.5 h-3.5 text-purple-500" />
                <span>{t(lang, 'reScanOcr', 'Re-Scan OCR')}</span>
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="p-1.5 rounded-lg text-slate-400 hover:text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition-colors cursor-pointer"
                title="Remove image"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Thumbnail & OCR Output Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-5 items-start">
            {/* Thumbnail Preview */}
            <div className="md:col-span-1 border border-slate-200 dark:border-night-border rounded-xl p-2 bg-slate-50 dark:bg-night-950 flex flex-col items-center">
              <img
                src={previewUrl}
                alt="Uploaded Screenshot Preview"
                className="max-h-48 object-contain rounded-lg"
              />
              <span className="text-[10px] text-slate-400 mt-1.5 font-medium">{t(lang, 'uploadedPreview', 'Uploaded preview')}</span>
            </div>

            {/* Extracted Text & URLs */}
            <div className="md:col-span-2 space-y-3.5">
              {isOcrProcessing ? (
                <div className="h-44 border border-dashed border-indigo-400/30 dark:border-violet-500/30 rounded-xl flex flex-col items-center justify-center p-4 text-center space-y-2 bg-slate-50/50 dark:bg-night-950/40">
                  <Loader2 className="w-7 h-7 text-purple-500 animate-spin" />
                  <p className="text-xs font-bold text-slate-900 dark:text-white">
                    {t(lang, 'scanningOcr', 'Scanning image via Optical Character Recognition (OCR)...')}
                  </p>
                  <p className="text-[11px] text-slate-500">
                    {t(lang, 'scanningOcrSub', 'Extracting Hindi, English, and regional script content')}
                  </p>
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
                      {t(lang, 'extractedMsgContent', 'Extracted Message Content (Editable):')}
                    </label>
                    <textarea
                      rows={3}
                      value={extractedText}
                      onChange={(e) => setExtractedText(e.target.value)}
                      placeholder={t(lang, 'extractedMsgPlaceholder', 'OCR extracted text will appear here. You can refine or add text...')}
                      className="w-full bg-slate-50 text-slate-900 border border-slate-300 dark:border-night-border rounded-xl p-3 text-xs font-sans focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-night-950 dark:text-slate-100 leading-relaxed"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
                      {t(lang, 'extractedUrls', 'Extracted Web Addresses / Links:')}
                    </label>
                    <input
                      type="text"
                      value={extractedUrls}
                      onChange={(e) => setExtractedUrls(e.target.value)}
                      placeholder="e.g. http://sbi-kyc-verify-urgent.com/login"
                      className="w-full bg-slate-50 text-slate-900 border border-slate-300 dark:border-night-border rounded-xl px-3 py-2 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-violet-500 dark:bg-night-950 dark:text-slate-100"
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Citizen Situation Selection */}
          <div className="pt-3 border-t border-slate-200 dark:border-night-border">
            <label htmlFor="screenshot-user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1.5">
              {t(lang, 'currentStateQuestion', 'What is your current interaction state?')} <span className="text-rose-500 font-bold">*</span>
            </label>
            <select
              id="screenshot-user-state"
              value={userState}
              onChange={(e) => setUserState(e.target.value)}
              className={`w-full border rounded-xl px-3.5 py-2.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-violet-500 cursor-pointer font-medium ${
                userState === 'paid' 
                  ? 'border-rose-500 text-rose-900 bg-rose-50 dark:border-rose-600 dark:text-rose-300 dark:bg-rose-950/30' 
                  : userState === 'entered_credentials'
                  ? 'border-amber-500 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/30'
                  : 'bg-slate-50 text-slate-900 border-slate-300 dark:bg-night-950 dark:text-slate-200 dark:border-night-border'
              }`}
            >
              <option value="received">{t(lang, 'scrSitReceived', '1. I only have this screenshot (No further action taken)')}</option>
              <option value="clicked">{t(lang, 'scrSitClicked', '2. I clicked a link shown in the screenshot')}</option>
              <option value="entered_credentials">{t(lang, 'scrSitEntered', '3. I submitted passwords or OTP')}</option>
              <option value="paid">{t(lang, 'scrSitPaid', '4. I transferred money / authorized payment (EMERGENCY)')}</option>
            </select>
          </div>

          {/* Continue Action Button */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-slate-200 dark:border-night-border">
            <button
              type="button"
              onClick={handleContinueAnalysis}
              disabled={isAnalyzing || isOcrProcessing || !extractedText.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-8 py-3 bg-slate-900 hover:bg-slate-800 text-white dark:bg-gradient-to-r dark:from-purple-600 dark:to-indigo-600 dark:hover:from-purple-500 dark:hover:to-indigo-500 font-bold rounded-xl text-sm shadow-luxury-glow transition-all duration-150 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white" />
                  <span>{t(lang, 'processingForensic', 'Processing Forensic Analysis...')}</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-white" strokeWidth={2.4} />
                  <span>{t(lang, 'analyzeExtracted', 'Analyze Extracted Content')}</span>
                </>
              )}
            </button>

            <span className="text-[11px] text-slate-500 dark:text-slate-400">
              {t(lang, 'scrZeroRetention', 'Zero Retention: Uploaded screenshot is held ephemerally in RAM and purged after OCR.')}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
