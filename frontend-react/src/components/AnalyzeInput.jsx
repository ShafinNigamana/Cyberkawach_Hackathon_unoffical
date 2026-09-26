import { useState, useRef } from 'react';
import './AnalyzeInput.css';

const INPUT_TABS = [
  { key: 'text', label: 'MESSAGE' },
  { key: 'url', label: 'URL' },
  { key: 'screenshot', label: 'SCREENSHOT' },
];

/**
 * Analysis input workspace.
 * Tabbed interface: Message | URL | Screenshot.
 */
export default function AnalyzeInput({ onAnalyze, loading }) {
  const [activeTab, setActiveTab] = useState('text');
  const [message, setMessage] = useState('');
  const [url, setUrl] = useState('');
  const [file, setFile] = useState(null);
  const [filePreview, setFilePreview] = useState(null);
  const fileInputRef = useRef(null);
  const [dragOver, setDragOver] = useState(false);

  const handleSubmit = () => {
    if (loading) return;

    if (activeTab === 'text' && message.trim()) {
      onAnalyze({ message: message.trim(), inputType: 'text' });
    } else if (activeTab === 'url' && url.trim()) {
      onAnalyze({ message: url.trim(), inputType: 'url', urls: [url.trim()] });
    } else if (activeTab === 'screenshot' && file) {
      // Screenshot upload validates only — no OCR available in backend
      onAnalyze({ message: `[Screenshot uploaded: ${file.name}]`, inputType: 'screenshot' });
    }
  };

  const handleClear = () => {
    setMessage('');
    setUrl('');
    setFile(null);
    setFilePreview(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleFileSelect = (selectedFile) => {
    if (!selectedFile) return;
    const validTypes = ['image/png', 'image/jpeg', 'image/webp'];
    if (!validTypes.includes(selectedFile.type)) {
      return;
    }
    if (selectedFile.size > 10 * 1024 * 1024) {
      return;
    }
    setFile(selectedFile);
    const reader = new FileReader();
    reader.onload = (e) => setFilePreview(e.target.result);
    reader.readAsDataURL(selectedFile);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) handleFileSelect(droppedFile);
  };

  const canSubmit =
    !loading &&
    ((activeTab === 'text' && message.trim().length > 0) ||
     (activeTab === 'url' && url.trim().length > 0) ||
     (activeTab === 'screenshot' && file !== null));

  return (
    <div className="analyze-input">
      {/* Tab bar */}
      <div className="input-tabs" role="tablist" aria-label="Input type">
        {INPUT_TABS.map((tab) => (
          <button
            key={tab.key}
            id={`tab-${tab.key}`}
            role="tab"
            aria-selected={activeTab === tab.key}
            aria-controls={`panel-${tab.key}`}
            className={`input-tab ${activeTab === tab.key ? 'input-tab--active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Panels */}
      <div className="input-panel">
        {/* MESSAGE */}
        {activeTab === 'text' && (
          <div id="panel-text" role="tabpanel" aria-labelledby="tab-text">
            <label htmlFor="message-input" className="input-label">
              Paste the suspicious message
            </label>
            <textarea
              id="message-input"
              className="input-textarea"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Paste the message here…"
              rows={6}
              maxLength={10000}
              disabled={loading}
            />
            <p className="input-note">Your message is analyzed securely and not stored permanently.</p>
          </div>
        )}

        {/* URL */}
        {activeTab === 'url' && (
          <div id="panel-url" role="tabpanel" aria-labelledby="tab-url">
            <label htmlFor="url-input" className="input-label">
              Enter the suspicious URL
            </label>
            <input
              id="url-input"
              type="url"
              className="input-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/..."
              disabled={loading}
            />
            <p className="input-note">Only submit URLs you are authorized to inspect.</p>
          </div>
        )}

        {/* SCREENSHOT */}
        {activeTab === 'screenshot' && (
          <div id="panel-screenshot" role="tabpanel" aria-labelledby="tab-screenshot">
            <label className="input-label">Upload a screenshot</label>
            {!file ? (
              <div
                className={`upload-zone ${dragOver ? 'upload-zone--drag' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                role="button"
                tabIndex={0}
                aria-label="Upload screenshot"
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click(); }}
              >
                <div className="upload-zone-icon">↑</div>
                <p className="upload-zone-text">Drop an image here or click to select</p>
                <p className="upload-zone-hint">PNG, JPG, or WebP — max 10 MB</p>
              </div>
            ) : (
              <div className="upload-preview">
                <img src={filePreview} alt="Screenshot preview" className="upload-preview-img" />
                <div className="upload-preview-info">
                  <span className="upload-preview-name">{file.name}</span>
                  <button
                    className="upload-preview-remove"
                    onClick={() => { setFile(null); setFilePreview(null); }}
                    aria-label="Remove screenshot"
                  >
                    Remove
                  </button>
                </div>
              </div>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/jpeg,image/webp"
              className="visually-hidden"
              onChange={(e) => handleFileSelect(e.target.files[0])}
              aria-hidden="true"
            />
            <p className="input-note">Screenshot analysis validates the file. OCR text extraction is not yet available.</p>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="input-actions">
        <button
          className="btn btn--ghost"
          onClick={handleClear}
          disabled={loading}
          type="button"
        >
          Clear
        </button>
        <button
          className="btn btn--primary"
          onClick={handleSubmit}
          disabled={!canSubmit}
          type="button"
          id="analyze-button"
        >
          {loading ? 'Analyzing…' : 'Analyze'}
        </button>
      </div>
    </div>
  );
}
