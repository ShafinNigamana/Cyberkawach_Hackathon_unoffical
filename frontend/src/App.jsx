import React, { useState, useEffect } from 'react';
import Header from './components/Header';
import HomeChoice from './components/HomeChoice';
import FlowMessage from './components/FlowMessage';
import FlowUrl from './components/FlowUrl';
import FlowScreenshot from './components/FlowScreenshot';
import LoadingPipeline from './components/LoadingPipeline';
import ResultsDashboard from './components/ResultsDashboard';
import MethodologyModal from './components/MethodologyModal';
import LanguageSelectionModal from './components/LanguageSelectionModal';
import AuthModal from './components/AuthModal';
import Footer from './components/Footer';
import { analyzeMessage, updateUserState, fetchHealth, fetchCurrentUser } from './services/api';
import { TRANSLATIONS } from './i18n/translations';

export default function App() {
  const [lang, setLang] = useState(() => localStorage.getItem('cf_lang') || 'en');
  const [languageModalOpen, setLanguageModalOpen] = useState(false);
  const [fontSize, setFontSize] = useState(() => localStorage.getItem('cf_fontsize') || 'normal');
  const [isDark, setIsDark] = useState(() => localStorage.getItem('cf_theme') === 'dark');
  const [methodologyOpen, setMethodologyOpen] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [authModalPrompt, setAuthModalPrompt] = useState(null);
  const [authModalTab, setAuthModalTab] = useState('login');
  const [pendingFlow, setPendingFlow] = useState(null);
  const [pendingPreset, setPendingPreset] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [healthData, setHealthData] = useState(null);

  // Current task flow: 'home' | 'message' | 'url' | 'screenshot' | 'result'
  const [currentFlow, setCurrentFlow] = useState('home');

  // Active form state passed between flows
  const [formData, setFormData] = useState({
    message: '',
    urls: '',
    input_type: 'sms',
    user_state: 'received',
  });

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isUpdatingState, setIsUpdatingState] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Sync language with localStorage and update active incident if present
  const handleLangChange = async (newLang) => {
    setLang(newLang);
    localStorage.setItem('cf_lang', newLang);
    if (result?.incident_id) {
      setIsUpdatingState(true);
      try {
        const updated = await updateUserState(result.incident_id, formData.user_state, newLang);
        setResult(updated);
      } catch (err) {
        console.error("Language update error:", err);
      } finally {
        setIsUpdatingState(false);
      }
    }
  };

  // Sync font size
  const handleFontSizeChange = (size) => {
    setFontSize(size);
    localStorage.setItem('cf_fontsize', size);
    const scale = size === 'small' ? '0.9' : size === 'large' ? '1.1' : '1';
    document.documentElement.style.setProperty('--font-scale', scale);
  };

  // Sync theme
  const handleThemeToggle = () => {
    const nextDark = !isDark;
    setIsDark(nextDark);
    localStorage.setItem('cf_theme', nextDark ? 'dark' : 'light');
    if (nextDark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      document.documentElement.classList.remove('dark');
    }
  };

  // Initial theme and health sync on mount
  useEffect(() => {
    if (isDark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.setAttribute('data-theme', 'light');
      document.documentElement.classList.remove('dark');
    }

    const scale = fontSize === 'small' ? '0.9' : fontSize === 'large' ? '1.1' : '1';
    document.documentElement.style.setProperty('--font-scale', scale);

    fetchHealth()
      .then(setHealthData)
      .catch(() => {});

    fetchCurrentUser()
      .then(setCurrentUser)
      .catch(() => {});
  }, []);

  const handleSelectHistoryIncident = async (incidentId) => {
    setIsAnalyzing(true);
    setError(null);
    try {
      const token = localStorage.getItem('cf_auth_token');
      const headers = { 'X-Requested-With': 'XMLHttpRequest' };
      if (token) headers['Authorization'] = `Bearer ${token}`;
      const res = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`, { headers });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
        setCurrentFlow('result');
      } else {
        setError('Failed to reopen past incident');
      }
    } catch (e) {
      setError('Error retrieving incident');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const openAuth = (prompt = null, tab = 'login', nextFlow = null) => {
    setAuthModalPrompt(prompt);
    setAuthModalTab(tab);
    if (nextFlow) setPendingFlow(nextFlow);
    setAuthModalOpen(true);
  };

  const handleAuthSuccess = (user) => {
    setCurrentUser(user);
    if (pendingPreset) {
      const p = pendingPreset;
      setPendingPreset(null);
      setFormData({
        message: p.message || '',
        urls: p.urls || '',
        input_type: p.type || 'sms',
        user_state: p.state || 'received',
      });
      setError(null);
      setCurrentFlow('message');
    } else if (pendingFlow) {
      setCurrentFlow(pendingFlow);
      setPendingFlow(null);
    }
  };

  // Quick preset scenario trigger from Home or other components
  const handleSelectPreset = (preset) => {
    if (!currentUser) {
      setPendingPreset(preset);
      openAuth('Please sign in or register to test this benchmark fraud scenario.', 'login', 'message');
      return;
    }
    setFormData({
      message: preset.message || '',
      urls: preset.urls || '',
      input_type: preset.type || 'sms',
      user_state: preset.state || 'received',
    });
    setError(null);
    setCurrentFlow('message');
  };

  // Flow submission handler connecting to the real backend
  const handleFlowSubmit = async (submissionData) => {
    if (!currentUser) {
      openAuth('Citizen authentication required to submit messages for forensic analysis.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResult(null);

    setFormData((prev) => ({
      ...prev,
      ...submissionData,
    }));

    try {
      const data = await analyzeMessage({
        message: submissionData.message,
        urls: submissionData.urls,
        user_state: submissionData.user_state,
        language: lang,
        input_type: submissionData.input_type || 'sms',
      });
      setResult(data);
      setCurrentFlow('result');
    } catch (err) {
      setError(err.message || 'An error occurred during forensic triage. Please check server status.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Adaptive response state change handler
  const handleStateChange = async (newState) => {
    if (!result?.incident_id) return;
    setIsUpdatingState(true);
    try {
      const updated = await updateUserState(result.incident_id, newState, lang);
      setResult(updated);
      setFormData((prev) => ({ ...prev, user_state: newState }));
    } catch (err) {
      // Fallback
    } finally {
      setIsUpdatingState(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 flex flex-col font-sans transition-colors duration-150">
      {/* First-visit and On-demand Language Selection Modal */}
      <LanguageSelectionModal
        isOpen={languageModalOpen}
        onClose={() => setLanguageModalOpen(false)}
        onSelectLanguage={(selected) => {
          handleLangChange(selected);
          setLanguageModalOpen(false);
        }}
        currentLang={lang}
      />

      {/* Official Institutional Header with Flow Navigation Ribbon */}
      <Header
        lang={lang}
        onLangChange={handleLangChange}
        fontSize={fontSize}
        onFontSizeChange={handleFontSizeChange}
        isDark={isDark}
        onThemeToggle={handleThemeToggle}
        onOpenMethodology={() => setMethodologyOpen(true)}
        onOpenLanguageModal={() => setLanguageModalOpen(true)}
        healthData={healthData}
        currentFlow={currentFlow}
        onSelectFlow={(flow) => {
          if (!currentUser && flow !== 'home') {
            openAuth(`Please sign in or register to access the ${flow} triage engine.`, 'login', flow);
            return;
          }
          setError(null);
          setCurrentFlow(flow);
        }}
        currentUser={currentUser}
        onOpenAuthModal={(prompt, tab) => openAuth(prompt, tab)}
      />

      {/* Main Content View Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 py-6" id="main-content">
        {/* Error Notification */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 text-red-900 dark:bg-red-950/60 dark:border-red-800 dark:text-red-200 rounded-xl text-xs sm:text-sm flex items-center justify-between shadow-xs">
            <span>{error}</span>
            <button
              onClick={() => setError(null)}
              className="text-red-700 dark:text-red-400 font-bold hover:underline ml-3 cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Real Multi-Stage Analysis Progress View */}
        {isAnalyzing ? (
          <LoadingPipeline lang={lang} />
        ) : currentFlow === 'result' && result ? (
          /* Shared Incident / Result View */
          <ResultsDashboard
            result={result}
            currentUserState={formData.user_state}
            onStateChange={handleStateChange}
            isUpdatingState={isUpdatingState}
            onCheckAnother={() => setCurrentFlow('home')}
            lang={lang}
          />
        ) : currentFlow === 'message' ? (
          /* Task Flow B: Check Message / SMS */
          <FlowMessage
            onBack={() => setCurrentFlow('home')}
            onSubmit={handleFlowSubmit}
            isAnalyzing={isAnalyzing}
            initialMessage={formData.message}
            initialUrls={formData.urls}
            initialState={formData.user_state}
            initialChannel={formData.input_type}
            lang={lang}
          />
        ) : currentFlow === 'url' ? (
          /* Task Flow C: Check URL / Website */
          <FlowUrl
            onBack={() => setCurrentFlow('home')}
            onSubmit={handleFlowSubmit}
            isAnalyzing={isAnalyzing}
            initialUrl={typeof formData.urls === 'string' ? formData.urls.split('\n')[0] : ''}
            lang={lang}
          />
        ) : currentFlow === 'screenshot' ? (
          /* Task Flow D: Check Screenshot / Photo */
          <FlowScreenshot
            onBack={() => setCurrentFlow('home')}
            onSubmit={handleFlowSubmit}
            isAnalyzing={isAnalyzing}
            lang={lang}
          />
        ) : (
          /* Task Flow A: Minimal Citizen Home Starting Point */
          <HomeChoice
            onSelectFlow={(flow) => {
              if (!currentUser) {
                openAuth(`Please sign in or register to access the ${flow} triage engine.`, 'login', flow);
                return;
              }
              setError(null);
              setCurrentFlow(flow);
            }}
            onSelectPreset={handleSelectPreset}
            lang={lang}
            currentUser={currentUser}
            onOpenAuthModal={(prompt, tab) => openAuth(prompt, tab)}
          />
        )}
      </main>

      {/* Institutional Footer */}
      <Footer onOpenMethodology={() => setMethodologyOpen(true)} lang={lang} />

      {/* Technical Methodology & Audit Modal */}
      <MethodologyModal
        isOpen={methodologyOpen}
        onClose={() => setMethodologyOpen(false)}
        lang={lang}
      />

      {/* Citizen Authentication & My Checks Modal */}
      <AuthModal
        isOpen={authModalOpen}
        onClose={() => {
          setAuthModalOpen(false);
          setAuthModalPrompt(null);
          setPendingFlow(null);
          setPendingPreset(null);
        }}
        currentUser={currentUser}
        onUserChange={setCurrentUser}
        onSelectIncident={handleSelectHistoryIncident}
        initialPrompt={authModalPrompt}
        initialTab={authModalTab}
        onAuthSuccess={handleAuthSuccess}
      />
    </div>
  );
}
