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
          className="clean-card border-2 border-dashed border-slate-300/80 dark:border-slate-700/80 hover:border-slate-400 dark:hover:border-slate-500 rounded-2xl p-8 text-center transition-all cursor-pointer space-y-3"
        >
          <input
            type="file"
            ref={fileInputRef}
            onChange={(e) => handleFileSelect(e.target.files?.[0])}
            accept="image/png,image/jpeg,image/webp"
            className="hidden"
            id="screenshot-input"
          />

          <div className="w-12 h-12 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 flex items-center justify-center mx-auto">
            <UploadCloud className="w-6 h-6" />
          </div>

          <div className="space-y-1">
            <p className="text-sm font-bold text-slate-900 dark:text-white">
              {t(lang, 'dropzoneTitle', 'Click to select image or drag & drop screenshot here')}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {t(lang, 'dropzoneSubtitle', 'Supports PNG, JPG, JPEG, WEBP up to 10MB. Works on mobile camera & gallery.')}
            </p>
          </div>

          <button
            type="button"
            className="inline-flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-white dark:bg-white dark:hover:bg-slate-100 dark:text-slate-950 text-xs font-semibold shadow-xs"
          >
            <Camera className="w-3.5 h-3.5" />
            <span>{t(lang, 'browseImage', 'Browse Image File')}</span>
          </button>
        </div>
      ) : (
        /* Image Preview & OCR State Box */
        <div className="clean-card rounded-2xl p-5 space-y-4 shadow-xs">
          <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 bg-slate-100 dark:bg-slate-800 rounded-lg">
                <ImageIcon className="w-4 h-4 text-slate-700 dark:text-slate-300" />
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
                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium transition-colors cursor-pointer"
              >
                <ScanText className="w-3.5 h-3.5" />
                <span>{t(lang, 'reScanOcr', 'Re-Scan OCR')}</span>
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="p-1 rounded text-slate-400 hover:text-red-600 transition-colors"
                title="Remove image"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Thumbnail & OCR Output Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-start">
            {/* Thumbnail Preview */}
            <div className="md:col-span-1 border border-slate-200 dark:border-slate-800 rounded-lg p-1.5 bg-slate-50 dark:bg-slate-950 flex flex-col items-center">
              <img
                src={previewUrl}
                alt="Uploaded Screenshot Preview"
                className="max-h-48 object-contain rounded"
              />
              <span className="text-[10px] text-slate-400 mt-1">{t(lang, 'uploadedPreview', 'Uploaded preview')}</span>
            </div>

            {/* Extracted Text & URLs */}
            <div className="md:col-span-2 space-y-3">
              {isOcrProcessing ? (
                <div className="h-44 border border-dashed border-slate-300 dark:border-slate-700 rounded-lg flex flex-col items-center justify-center p-4 text-center space-y-2 bg-slate-50 dark:bg-slate-950/40">
                  <Loader2 className="w-6 h-6 text-slate-900 dark:text-slate-100 animate-spin" />
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
                    <label className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1">
                      {t(lang, 'extractedMsgContent', 'Extracted Message Content (Editable):')}
                    </label>
                    <textarea
                      rows={3}
                      value={extractedText}
                      onChange={(e) => setExtractedText(e.target.value)}
                      placeholder={t(lang, 'extractedMsgPlaceholder', 'OCR extracted text will appear here. You can refine or add text...')}
                      className="w-full bg-slate-50 text-slate-900 border border-slate-300 rounded-lg p-2.5 text-xs font-sans focus:outline-none focus:ring-2 focus:ring-slate-900 dark:bg-slate-950 dark:text-slate-100 dark:border-slate-700 leading-relaxed"
                    />
                  </div>

                  <div>
                    <label className="block text-xs font-bold text-slate-900 dark:text-slate-200 mb-1">
                      {t(lang, 'extractedUrls', 'Extracted Web Addresses / Links:')}
                    </label>
                    <input
                      type="text"
                      value={extractedUrls}
                      onChange={(e) => setExtractedUrls(e.target.value)}
                      placeholder="e.g. http://sbi-kyc-verify-urgent.com/login"
                      className="w-full bg-slate-50 text-slate-900 border border-slate-300 rounded-lg px-2.5 py-1.5 text-xs font-mono focus:outline-none focus:ring-2 focus:ring-slate-900 dark:bg-slate-950 dark:text-slate-100 dark:border-slate-700"
                    />
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Citizen Situation Selection */}
          <div className="pt-2 border-t border-slate-200 dark:border-slate-800">
            <label htmlFor="screenshot-user-state" className="block text-xs font-bold text-slate-900 dark:text-slate-300 mb-1">
              {t(lang, 'currentStateQuestion', 'What is your current interaction state?')} <span className="text-red-600 font-bold">*</span>
            </label>
            <select
              id="screenshot-user-state"
              value={userState}
              onChange={(e) => setUserState(e.target.value)}
              className={`w-full border rounded-lg px-2.5 py-1.5 text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-slate-900 cursor-pointer font-medium ${
                userState === 'paid' 
                  ? 'border-red-600 text-red-900 bg-red-50 dark:border-red-600 dark:text-red-300 dark:bg-red-950/20' 
                  : userState === 'entered_credentials'
                  ? 'border-amber-600 text-amber-950 bg-amber-50 dark:border-amber-600 dark:text-amber-300 dark:bg-amber-950/20'
                  : 'bg-slate-50 text-slate-900 border-slate-300 dark:bg-slate-950 dark:text-slate-200 dark:border-slate-700'
              }`}
            >
              <option value="received">{t(lang, 'scrSitReceived', '1. I only have this screenshot (No further action taken)')}</option>
              <option value="clicked">{t(lang, 'scrSitClicked', '2. I clicked a link shown in the screenshot')}</option>
              <option value="entered_credentials">{t(lang, 'scrSitEntered', '3. I submitted passwords or OTP')}</option>
              <option value="paid">{t(lang, 'scrSitPaid', '4. I transferred money / authorized payment (EMERGENCY)')}</option>
            </select>
          </div>

          {/* Continue Action Button */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-200 dark:border-slate-800">
            <button
              type="button"
              onClick={handleContinueAnalysis}
              disabled={isAnalyzing || isOcrProcessing || !extractedText.trim()}
              className="w-full sm:w-auto inline-flex items-center justify-center space-x-2 px-7 py-2.5 bg-slate-900 hover:bg-slate-800 text-white dark:bg-slate-100 dark:hover:bg-white dark:text-slate-900 font-bold rounded-lg text-sm shadow-sm transition-all duration-150 active:scale-[0.99] disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin text-white dark:text-slate-900" />
                  <span>{t(lang, 'processingForensic', 'Processing Forensic Analysis...')}</span>
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 text-white dark:text-slate-900" strokeWidth={2.4} />
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
