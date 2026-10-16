import React, { useState, useRef } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Upload,
  Link,
  FileCheck,
  AlertTriangle,
  Download,
  Copy,
  Check,
  Loader2,
  X,
  FileText,
  Lock,
  ExternalLink,
  Bug,
  Archive,
  Terminal,
  Folder,
  FolderOpen,
  Layers,
  Sparkles,
  Gauge
} from 'lucide-react';
import { 
  scanFileForThreats, 
  scanRemoteDownloadUrl, 
  getSafeDownloadUrl,
  scanFolderBatch 
} from '../services/api';

export default function FileScanModal({ isOpen, onClose }) {
  const [scanTab, setScanTab] = useState('upload'); // 'upload' | 'folder' | 'url'
  const [downloadUrl, setDownloadUrl] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [selectedFolderFiles, setSelectedFolderFiles] = useState([]);
  const [detectedFolderName, setDetectedFolderName] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [scanState, setScanState] = useState('INITIATED');
  const [scanResult, setScanResult] = useState(null);
  const [folderResult, setFolderResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);
  
  const fileInputRef = useRef(null);
  const folderInputRef = useRef(null);

  if (!isOpen) return null;

  const handleFileSelect = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setScanResult(null);
      setFolderResult(null);
      setErrorMsg(null);
    }
  };

  const handleFolderSelect = (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      setSelectedFolderFiles(files);
      const rootFolder = files[0].webkitRelativePath?.split('/')[0] || 'Selected_Folder';
      setDetectedFolderName(rootFolder);
      setScanResult(null);
      setFolderResult(null);
      setErrorMsg(null);
    }
  };

  const executeFileScan = async () => {
    if (!selectedFile) return;
    setIsScanning(true);
    setScanState('RECEIVING');
    setErrorMsg(null);
    setScanResult(null);
    setFolderResult(null);

    try {
      setScanState('SCANNING');
      const result = await scanFileForThreats(selectedFile);
      setScanResult(result);
      setScanState(result.state);
    } catch (err) {
      setErrorMsg(err.message || 'File inspection failed');
      setScanState('ERROR');
    } finally {
      setIsScanning(false);
    }
  };

  const executeFolderScan = async () => {
    if (selectedFolderFiles.length === 0) return;
    setIsScanning(true);
    setScanState('SCANNING');
    setErrorMsg(null);
    setScanResult(null);
    setFolderResult(null);

    try {
      const result = await scanFolderBatch(selectedFolderFiles, detectedFolderName);
      setFolderResult(result);
      setScanState(result.overall_state);
    } catch (err) {
      setErrorMsg(err.message || 'Folder batch inspection failed');
      setScanState('ERROR');
    } finally {
      setIsScanning(false);
    }
  };

  const executeUrlScan = async () => {
    if (!downloadUrl.trim()) return;
    setIsScanning(true);
    setScanState('RECEIVING');
    setErrorMsg(null);
    setScanResult(null);
    setFolderResult(null);

    try {
      setScanState('SCANNING');
      const result = await scanRemoteDownloadUrl(downloadUrl.trim());
      setScanResult(result);
      setScanState(result.state);
    } catch (err) {
      setErrorMsg(err.message || 'Remote download inspection failed');
      setScanState('ERROR');
    } finally {
      setIsScanning(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const getVerdictBadge = (state, policy) => {
    if (state === 'CLEAN' && policy === 'ALLOWED') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-emerald-500/10 text-emerald-500 border border-emerald-500/30">
          <ShieldCheck className="w-4 h-4" />
          VERIFIED CLEAN (SAFE TO RELEASE)
        </span>
      );
    }
    if (state === 'MALICIOUS') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-rose-500/10 text-rose-500 border border-rose-500/30">
          <ShieldAlert className="w-4 h-4" />
          MALICIOUS THREAT DETECTED (QUARANTINED)
        </span>
      );
    }
    if (state === 'SUSPICIOUS') {
      return (
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-amber-500/10 text-amber-500 border border-amber-500/30">
          <AlertTriangle className="w-4 h-4" />
          SUSPICIOUS (DISGUISED OR EXECUTABLE)
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold bg-red-500/10 text-red-500 border border-red-500/30">
        <AlertTriangle className="w-4 h-4" />
        SCAN FAILED / BLOCKED
      </span>
    );
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-3xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[92vh]">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between p-5 border-b border-slate-800 bg-slate-900/95">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                Automatic Deep Threat Scanner & Quarantine
              </h3>
              <p className="text-xs text-slate-400">
                Single Files, ZIP Archives, and Whole Folder Tree Deep Malware Analysis
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="flex border-b border-slate-800 bg-slate-950/60 px-6 pt-3 gap-2">
          <button
            onClick={() => { setScanTab('upload'); setScanResult(null); setFolderResult(null); setErrorMsg(null); }}
            className={`pb-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center gap-2 ${
              scanTab === 'upload'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="w-4 h-4" />
            File / ZIP Archive
          </button>
          <button
            onClick={() => { setScanTab('folder'); setScanResult(null); setFolderResult(null); setErrorMsg(null); }}
            className={`pb-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center gap-2 ${
              scanTab === 'folder'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Folder className="w-4 h-4" />
            Whole Folder Tree
          </button>
          <button
            onClick={() => { setScanTab('url'); setScanResult(null); setFolderResult(null); setErrorMsg(null); }}
            className={`pb-3 px-4 text-xs font-bold transition-all border-b-2 flex items-center gap-2 ${
              scanTab === 'url'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Link className="w-4 h-4" />
            Remote URL Stream
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-5">
          
          {/* TAB 1: Single File / ZIP Upload */}
          {scanTab === 'upload' && (
            <div className="space-y-4">
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileSelect}
                className="hidden"
              />
              <div
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-blue-500/50 rounded-xl p-6 text-center cursor-pointer transition-all bg-slate-950/40 hover:bg-slate-900/40"
              >
                <div className="mx-auto w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-400 mb-2">
                  <Upload className="w-5 h-5" />
                </div>
                <p className="text-sm font-semibold text-slate-200">
                  {selectedFile ? selectedFile.name : 'Click or drop file / archive to inspect'}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Supports binaries, ZIP archives (.zip/.apk), documents, and scripts (Max 50 MB)
                </p>
              </div>

              <button
                disabled={!selectedFile || isScanning}
                onClick={executeFileScan}
                className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Deep Scanning ({scanState})...
                  </>
                ) : (
                  <>
                    <FileCheck className="w-4 h-4" />
                    Initiate Deep Malware Scan
                  </>
                )}
              </button>
            </div>
          )}

          {/* TAB 2: Whole Folder Tree Upload */}
          {scanTab === 'folder' && (
            <div className="space-y-4">
              <input
                type="file"
                ref={folderInputRef}
                webkitdirectory=""
                directory=""
                multiple
                onChange={handleFolderSelect}
                className="hidden"
              />
              <div
                onClick={() => folderInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-blue-500/50 rounded-xl p-6 text-center cursor-pointer transition-all bg-slate-950/40 hover:bg-slate-900/40"
              >
                <div className="mx-auto w-10 h-10 rounded-full bg-blue-500/10 flex items-center justify-center text-blue-400 mb-2">
                  <FolderOpen className="w-5 h-5" />
                </div>
                <p className="text-sm font-semibold text-slate-200">
                  {selectedFolderFiles.length > 0
                    ? `Folder Selected: ${detectedFolderName} (${selectedFolderFiles.length} files)`
                    : 'Click to select an entire folder directory'}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  Recursively uploads and deep-scans every file, nested folder, script, and archive (up to 200 files)
                </p>
              </div>

              <button
                disabled={selectedFolderFiles.length === 0 || isScanning}
                onClick={executeFolderScan}
                className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Deep Scanning Folder ({selectedFolderFiles.length} files)...
                  </>
                ) : (
                  <>
                    <Layers className="w-4 h-4" />
                    Initiate Recursive Folder Deep Analysis ({selectedFolderFiles.length} files)
                  </>
                )}
              </button>
            </div>
          )}

          {/* TAB 3: Remote Download URL */}
          {scanTab === 'url' && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1.5">
                  Remote Download Target URL:
                </label>
                <input
                  type="url"
                  placeholder="https://example.com/downloads/setup.exe"
                  value={downloadUrl}
                  onChange={(e) => setDownloadUrl(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3.5 py-2.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-blue-500"
                />
              </div>

              <button
                disabled={!downloadUrl.trim() || isScanning}
                onClick={executeUrlScan}
                className="w-full py-2.5 px-4 rounded-xl font-bold text-sm bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue-500/20"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Streaming & Analyzing ({scanState})...
                  </>
                ) : (
                  <>
                    <ShieldAlert className="w-4 h-4" />
                    Stream & Quarantine Remote Download
                  </>
                )}
              </button>
            </div>
          )}

          {errorMsg && (
            <div className="p-3.5 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {/* RESULTS DISPLAY: Single File Result */}
          {scanResult && (
            <div className="mt-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 className="text-sm font-bold text-white">{scanResult.original_filename}</h4>
                  <p className="text-[11px] text-slate-400">
                    Sanitized Name: <span className="font-mono text-slate-300">{scanResult.safe_filename}</span> • {(scanResult.size_bytes / 1024).toFixed(1)} KB
                  </p>
                </div>
                {getVerdictBadge(scanResult.state, scanResult.release_policy)}
              </div>

              {/* Shannon Entropy & Deep Analysis Meter */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px] flex items-center gap-1">
                    <Gauge className="w-3 h-3 text-cyan-400" /> Shannon Entropy
                  </span>
                  <span className={`font-mono font-bold text-sm ${scanResult.entropy > 7.2 ? 'text-amber-400' : 'text-slate-200'}`}>
                    {scanResult.entropy} / 8.0
                  </span>
                  <span className="text-[10px] text-slate-500 block">
                    {scanResult.entropy > 7.2 ? 'Packed/Encrypted' : 'Normal Structure'}
                  </span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">Verified True MIME</span>
                  <span className="font-semibold text-slate-200">{scanResult.magic_mime}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                  <span className="text-slate-500 block text-[10px]">File Signature</span>
                  <span className="font-semibold text-slate-200">{scanResult.file_type_description}</span>
                </div>
              </div>

              {/* SHA-256 Hash Card */}
              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800/80 space-y-1">
                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-blue-400" />
                    SHA-256 Fingerprint:
                  </span>
                  <button
                    onClick={() => copyToClipboard(scanResult.sha256)}
                    className="hover:text-white flex items-center gap-1 text-[10px]"
                  >
                    {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedHash ? 'Copied' : 'Copy'}
                  </button>
                </div>
                <p className="font-mono text-[11px] text-blue-300 break-all select-all">
                  {scanResult.sha256}
                </p>
              </div>

              {/* Deep Heuristics & Threat Findings */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-400 block">Deep Analysis Findings:</span>
                <ul className="space-y-1 text-xs">
                  {scanResult.findings.map((f, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-slate-300">
                      <span className="text-blue-400 mt-0.5">•</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Release Gate Action Button */}
              <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between">
                <span className="text-xs text-slate-400">
                  Release Policy: <strong className={scanResult.release_policy === 'ALLOWED' ? 'text-emerald-400' : 'text-rose-400'}>{scanResult.release_policy}</strong>
                </span>

                {scanResult.release_policy === 'ALLOWED' ? (
                  <a
                    href={getSafeDownloadUrl(scanResult.scan_id)}
                    download={scanResult.safe_filename}
                    className="py-1.5 px-3.5 rounded-lg font-bold text-xs bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 transition-colors shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5" />
                    Download Clean File
                  </a>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-rose-400 font-semibold bg-rose-500/10 px-3 py-1.5 rounded-lg border border-rose-500/20">
                    <Lock className="w-3.5 h-3.5" />
                    File Quarantined (Release Forbidden)
                  </span>
                )}
              </div>
            </div>
          )}

          {/* RESULTS DISPLAY: Whole Folder Batch Result */}
          {folderResult && (
            <div className="mt-4 p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <h4 className="text-sm font-bold text-white flex items-center gap-2">
                    <Folder className="w-4 h-4 text-blue-400" />
                    Folder Audit: {folderResult.folder_name}
                  </h4>
                  <p className="text-[11px] text-slate-400">
                    Total Files: {folderResult.total_files} • Scanned in {folderResult.processing_time_ms} ms
                  </p>
                </div>
                {getVerdictBadge(folderResult.overall_state, folderResult.overall_release_policy)}
              </div>

              {/* Folder Stat Chips */}
              <div className="grid grid-cols-3 gap-2 text-center text-xs">
                <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                  <span className="text-[10px] block text-emerald-400/80 uppercase font-semibold">Clean Files</span>
                  <span className="font-bold text-base">{folderResult.clean_count}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400">
                  <span className="text-[10px] block text-amber-400/80 uppercase font-semibold">Suspicious</span>
                  <span className="font-bold text-base">{folderResult.suspicious_count}</span>
                </div>
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                  <span className="text-[10px] block text-rose-400/80 uppercase font-semibold">Malicious</span>
                  <span className="font-bold text-base">{folderResult.malicious_count}</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300">
                <strong>Folder Audit Summary:</strong> {folderResult.summary}
              </div>

              {/* File Breakdown Table */}
              <div className="space-y-1.5">
                <span className="text-[11px] font-semibold text-slate-400 block">Folder File Tree Analysis:</span>
                <div className="max-h-56 overflow-y-auto rounded-lg border border-slate-800 divide-y divide-slate-800/80 text-xs">
                  {folderResult.file_records.map((f, idx) => (
                    <div key={idx} className="p-2.5 flex items-center justify-between hover:bg-slate-900/60 transition-colors">
                      <div className="truncate max-w-[65%]">
                        <span className="font-mono text-slate-200 block truncate">{f.original_filename}</span>
                        <span className="text-[10px] text-slate-500">
                          {f.magic_mime} • Entropy: {f.entropy} • {(f.size_bytes / 1024).toFixed(1)} KB
                        </span>
                      </div>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        f.state === 'CLEAN'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                          : f.state === 'MALICIOUS'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                      }`}>
                        {f.state}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

        </div>
      </div>
    </div>
  );
}
