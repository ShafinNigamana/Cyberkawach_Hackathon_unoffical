import React, { useState, useEffect, useMemo } from 'react';
import { 
  X, 
  User, 
  Lock, 
  Mail, 
  Phone, 
  ShieldCheck, 
  ShieldAlert,
  LogIn, 
  UserPlus, 
  History, 
  CheckCircle, 
  AlertTriangle,
  Loader2,
  ExternalLink,
  LogOut,
  Eye,
  EyeOff,
  Check,
  KeyRound,
  Sparkles,
  Info
} from 'lucide-react';
import { 
  loginCitizen, 
  registerCitizen, 
  logoutCitizen, 
  fetchMyChecks 
} from '../services/api';

export default function AuthModal({ 
  isOpen, 
  onClose, 
  currentUser, 
  onUserChange,
  onSelectIncident,
  initialPrompt = null,
  initialTab = 'login',
  onAuthSuccess = () => {}
}) {
  const [tab, setTab] = useState(initialTab); // 'login' | 'register' | 'history'
  
  // Login State
  const [loginEmail, setLoginEmail] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginShowPassword, setLoginShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(true);

  // Register State
  const [registerName, setRegisterName] = useState('');
  const [registerEmail, setRegisterEmail] = useState('');
  const [registerPassword, setRegisterPassword] = useState('');
  const [registerConfirmPassword, setRegisterConfirmPassword] = useState('');
  const [registerShowPassword, setRegisterShowPassword] = useState(false);
  const [registerShowConfirm, setRegisterShowConfirm] = useState(false);
  const [registerPhone, setRegisterPhone] = useState('');
  const [registerLang, setRegisterLang] = useState('en');
  const [agreeTerms, setAgreeTerms] = useState(false);

  // Validation & UI State
  const [touched, setTouched] = useState({});
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // History state
  const [historyItems, setHistoryItems] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // Sync tab and reset alerts when modal opens
  useEffect(() => {
    if (isOpen) {
      setError(null);
      setSuccessMsg(null);
      setTouched({});
      if (currentUser) {
        setTab('history');
        loadHistory();
      } else {
        setTab(initialTab || 'login');
      }
    }
  }, [isOpen, currentUser, initialTab]);

  const loadHistory = async () => {
    setHistoryLoading(true);
    try {
      const res = await fetchMyChecks();
      setHistoryItems(res.incidents || []);
    } catch (e) {
      console.error("Error loading check history:", e);
    } finally {
      setHistoryLoading(false);
    }
  };

  // ─── Input Validation Helpers ───
  const emailRegex = useMemo(() => /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/, []);

  const loginEmailValid = useMemo(() => {
    if (!loginEmail.trim()) return false;
    return emailRegex.test(loginEmail.trim());
  }, [loginEmail, emailRegex]);

  const registerEmailValid = useMemo(() => {
    if (!registerEmail.trim()) return false;
    return emailRegex.test(registerEmail.trim());
  }, [registerEmail, emailRegex]);

  const registerNameValid = useMemo(() => {
    return registerName.trim().length >= 2;
  }, [registerName]);

  // Password Strength Calculation (Score 0 - 4)
  const passwordCriteria = useMemo(() => {
    const pwd = registerPassword;
    return {
      hasLength: pwd.length >= 8,
      hasNumber: /\d/.test(pwd),
      hasUpper: /[A-Z]/.test(pwd),
      hasSpecial: /[^A-Za-z0-9]/.test(pwd),
    };
  }, [registerPassword]);

  const passwordScore = useMemo(() => {
    const { hasLength, hasNumber, hasUpper, hasSpecial } = passwordCriteria;
    return [hasLength, hasNumber, hasUpper, hasSpecial].filter(Boolean).length;
  }, [passwordCriteria]);

  const passwordStrengthLabel = useMemo(() => {
    if (!registerPassword) return { text: 'Not entered', color: 'text-slate-400', barColor: 'bg-slate-200 dark:bg-slate-700' };
    if (passwordScore <= 1) return { text: 'Weak', color: 'text-red-600 dark:text-red-400', barColor: 'bg-red-500' };
    if (passwordScore === 2) return { text: 'Fair', color: 'text-amber-600 dark:text-amber-400', barColor: 'bg-amber-500' };
    if (passwordScore === 3) return { text: 'Good', color: 'text-blue-600 dark:text-blue-400', barColor: 'bg-blue-500' };
    return { text: 'Strong', color: 'text-emerald-600 dark:text-emerald-400', barColor: 'bg-emerald-500' };
  }, [registerPassword, passwordScore]);

  const passwordsMatch = useMemo(() => {
    if (!registerConfirmPassword) return false;
    return registerPassword === registerConfirmPassword;
  }, [registerPassword, registerConfirmPassword]);

  const canSubmitLogin = useMemo(() => {
    return loginEmailValid && loginPassword.length >= 1 && !loading;
  }, [loginEmailValid, loginPassword, loading]);

  const canSubmitRegister = useMemo(() => {
    return (
      registerNameValid &&
      registerEmailValid &&
      passwordCriteria.hasLength &&
      passwordsMatch &&
      agreeTerms &&
      !loading
    );
  }, [registerNameValid, registerEmailValid, passwordCriteria.hasLength, passwordsMatch, agreeTerms, loading]);

  if (!isOpen) return null;

  // ─── Actions ───
  const handleLogin = async (e) => {
    e.preventDefault();
    if (!canSubmitLogin) return;

    setError(null);
    setLoading(true);
    try {
      const res = await loginCitizen({
        email: loginEmail.trim().toLowerCase(),
        password: loginPassword,
      });
      onUserChange(res.user);
      setSuccessMsg(`Welcome back, ${res.user.display_name || res.user.email}!`);
      onAuthSuccess(res.user);
      setTimeout(() => {
        onClose();
      }, 700);
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    if (!canSubmitRegister) return;

    setError(null);
    setLoading(true);
    try {
      const res = await registerCitizen({
        email: registerEmail.trim().toLowerCase(),
        password: registerPassword,
        display_name: registerName.trim(),
        phone: registerPhone.trim() || undefined,
        preferred_language: registerLang,
      });
      onUserChange(res.user);
      setSuccessMsg(`Citizen account created! Welcome, ${res.user.display_name}.`);
      onAuthSuccess(res.user);
      setTimeout(() => {
        onClose();
      }, 800);
    } catch (err) {
      setError(err.message || 'Registration failed. An account with this email may already exist.');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await logoutCitizen();
      onUserChange(null);
      setTab('login');
      setHistoryItems([]);
      setSuccessMsg('Logged out successfully.');
    } catch (err) {
      console.warn("Logout error:", err);
    } finally {
      setLoading(false);
    }
  };

  const getRiskBadge = (level) => {
    const l = String(level).toLowerCase();
    if (l === 'critical') return 'bg-red-100 text-red-800 border-red-300 dark:bg-red-950 dark:text-red-300';
    if (l === 'high') return 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950 dark:text-orange-300';
    if (l === 'suspicious') return 'bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950 dark:text-amber-300';
    return 'bg-emerald-100 text-emerald-800 border-emerald-300 dark:bg-emerald-950 dark:text-emerald-300';
  };

  return (
    <div 
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-sm transition-opacity"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div 
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden text-slate-800 dark:text-slate-200 flex flex-col max-h-[92vh] animate-in fade-in zoom-in-95 duration-150"
        role="dialog"
        aria-modal="true"
        aria-labelledby="auth-modal-title"
      >
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/70">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-600/10 dark:bg-cyan-500/20 text-cyan-700 dark:text-cyan-400 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 id="auth-modal-title" className="text-base font-bold text-slate-900 dark:text-white leading-tight">
                {currentUser ? 'Citizen Account & Triage Records' : 'Citizen Authentication Gateway'}
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                {currentUser ? 'Neo4j AuraDB • PBKDF2 Cryptographic Session' : 'National Cyber Threat Triage • Access Protection'}
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
            aria-label="Close authentication modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Informational Prompt Alert (if user tried to access a protected action) */}
        {!currentUser && initialPrompt && (
          <div className="mx-6 mt-4 p-3 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/80 text-xs text-amber-900 dark:text-amber-200 flex items-start space-x-2.5 shadow-2xs">
            <ShieldAlert className="w-4 h-4 text-amber-600 dark:text-amber-400 mt-0.5 flex-shrink-0" />
            <div className="flex-1 leading-relaxed">
              <span className="font-bold">Authentication Required:</span> {initialPrompt}
            </div>
          </div>
        )}

        {/* Tab Bar */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 bg-slate-100/60 dark:bg-slate-950/40 text-xs font-semibold px-6 pt-2">
          {!currentUser ? (
            <>
              <button
                type="button"
                onClick={() => { setTab('login'); setError(null); setSuccessMsg(null); }}
                className={`flex-1 py-3 text-center transition-all border-b-2 cursor-pointer flex items-center justify-center space-x-1.5 ${
                  tab === 'login' 
                    ? 'border-cyan-600 text-cyan-700 dark:text-cyan-400 font-bold bg-white dark:bg-slate-900 rounded-t-lg' 
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'
                }`}
              >
                <LogIn className="w-3.5 h-3.5" />
                <span>Citizen Sign In</span>
              </button>
              <button
                type="button"
                onClick={() => { setTab('register'); setError(null); setSuccessMsg(null); }}
                className={`flex-1 py-3 text-center transition-all border-b-2 cursor-pointer flex items-center justify-center space-x-1.5 ${
                  tab === 'register' 
                    ? 'border-cyan-600 text-cyan-700 dark:text-cyan-400 font-bold bg-white dark:bg-slate-900 rounded-t-lg' 
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'
                }`}
              >
                <UserPlus className="w-3.5 h-3.5" />
                <span>Register Account</span>
              </button>
            </>
          ) : (
            <>
              <button
                type="button"
                onClick={() => { setTab('history'); loadHistory(); }}
                className={`flex-1 py-3 text-center transition-all border-b-2 cursor-pointer flex items-center justify-center space-x-1.5 ${
                  tab === 'history' 
                    ? 'border-cyan-600 text-cyan-700 dark:text-cyan-400 font-bold bg-white dark:bg-slate-900 rounded-t-lg' 
                    : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-300'
                }`}
              >
                <History className="w-3.5 h-3.5" />
                <span>My Scam Checks ({historyItems.length})</span>
              </button>
              <button
                type="button"
                onClick={handleLogout}
                disabled={loading}
                className="py-3 px-4 text-center text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition-colors flex items-center space-x-1 font-semibold cursor-pointer"
                title="Sign out of citizen session"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </>
          )}
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-4 flex-1">
          {/* General Error Banner */}
          {error && (
            <div className="p-3.5 rounded-xl bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900/80 text-xs text-red-700 dark:text-red-300 flex items-start space-x-2.5 shadow-2xs">
              <AlertTriangle className="w-4 h-4 text-red-600 dark:text-red-400 mt-0.5 flex-shrink-0" />
              <div className="flex-1 font-medium">{error}</div>
            </div>
          )}

          {/* Success Banner */}
          {successMsg && (
            <div className="p-3.5 rounded-xl bg-emerald-50 dark:bg-emerald-950/50 border border-emerald-200 dark:border-emerald-800 text-xs text-emerald-700 dark:text-emerald-300 flex items-center space-x-2.5 shadow-2xs">
              <CheckCircle className="w-4 h-4 text-emerald-600 dark:text-emerald-400 flex-shrink-0" />
              <span className="font-semibold">{successMsg}</span>
            </div>
          )}

          {/* ══════════════════════════════════════════════════════
              LOGIN FORM
             ══════════════════════════════════════════════════════ */}
          {tab === 'login' && !currentUser && (
            <form onSubmit={handleLogin} className="space-y-4" noValidate>
              {/* Email Address */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Citizen Email Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="email"
                    required
                    value={loginEmail}
                    onChange={(e) => {
                      setLoginEmail(e.target.value);
                      if (error) setError(null);
                    }}
                    onBlur={() => setTouched((prev) => ({ ...prev, loginEmail: true }))}
                    placeholder="citizen@cyberkawach.gov.in"
                    className={`w-full pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border rounded-xl focus:outline-none transition-colors ${
                      touched.loginEmail && !loginEmailValid && loginEmail
                        ? 'border-red-400 focus:border-red-500 dark:border-red-700'
                        : 'border-slate-300 dark:border-slate-700 focus:border-cyan-500'
                    }`}
                  />
                </div>
                {touched.loginEmail && loginEmail && !loginEmailValid && (
                  <p className="text-[11px] text-red-600 dark:text-red-400 mt-1">
                    Please enter a valid email format (e.g. name@domain.com).
                  </p>
                )}
              </div>

              {/* Password */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Password <span className="text-red-500">*</span>
                  </label>
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type={loginShowPassword ? 'text' : 'password'}
                    required
                    value={loginPassword}
                    onChange={(e) => {
                      setLoginPassword(e.target.value);
                      if (error) setError(null);
                    }}
                    placeholder="Enter your account password"
                    className="w-full pl-9 pr-10 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl focus:outline-none focus:border-cyan-500 transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setLoginShowPassword(!loginShowPassword)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                    title={loginShowPassword ? "Hide password" : "Show password"}
                  >
                    {loginShowPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Remember Me & Privacy Notice */}
              <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400 pt-1">
                <label className="flex items-center space-x-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={rememberMe}
                    onChange={(e) => setRememberMe(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-700 text-cyan-600 focus:ring-cyan-500"
                  />
                  <span>Keep session active</span>
                </label>
                <span className="text-[11px] text-slate-400 flex items-center space-x-1">
                  <KeyRound className="w-3 h-3 text-cyan-600" />
                  <span>PBKDF2-SHA256</span>
                </span>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={!canSubmitLogin}
                className="w-full py-2.5 px-4 bg-cyan-700 hover:bg-cyan-800 active:bg-cyan-900 text-white text-sm font-bold rounded-xl transition-all shadow-md flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Authenticating Citizen...</span>
                  </>
                ) : (
                  <>
                    <LogIn className="w-4 h-4" />
                    <span>Sign In to Cyber Fraud Guardian</span>
                  </>
                )}
              </button>

              <div className="pt-2 text-center text-xs text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800">
                Don't have a Citizen Account yet?{' '}
                <button
                  type="button"
                  onClick={() => { setTab('register'); setError(null); }}
                  className="text-cyan-600 dark:text-cyan-400 font-bold hover:underline cursor-pointer"
                >
                  Register here
                </button>
              </div>
            </form>
          )}

          {/* ══════════════════════════════════════════════════════
              REGISTRATION FORM
             ══════════════════════════════════════════════════════ */}
          {tab === 'register' && !currentUser && (
            <form onSubmit={handleRegister} className="space-y-3.5" noValidate>
              {/* Full Name */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Full Name / Citizen Display Name <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <User className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="text"
                    required
                    value={registerName}
                    onChange={(e) => setRegisterName(e.target.value)}
                    onBlur={() => setTouched((prev) => ({ ...prev, registerName: true }))}
                    placeholder="e.g. Ramesh Kumar"
                    className={`w-full pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border rounded-xl focus:outline-none transition-colors ${
                      touched.registerName && !registerNameValid
                        ? 'border-red-400 focus:border-red-500 dark:border-red-700'
                        : 'border-slate-300 dark:border-slate-700 focus:border-cyan-500'
                    }`}
                  />
                </div>
                {touched.registerName && !registerNameValid && (
                  <p className="text-[11px] text-red-600 dark:text-red-400 mt-0.5">
                    Name must be at least 2 characters.
                  </p>
                )}
              </div>

              {/* Email Address */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Email Address <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type="email"
                    required
                    value={registerEmail}
                    onChange={(e) => setRegisterEmail(e.target.value)}
                    onBlur={() => setTouched((prev) => ({ ...prev, registerEmail: true }))}
                    placeholder="citizen@cyberkawach.gov.in"
                    className={`w-full pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border rounded-xl focus:outline-none transition-colors ${
                      touched.registerEmail && !registerEmailValid && registerEmail
                        ? 'border-red-400 focus:border-red-500 dark:border-red-700'
                        : 'border-slate-300 dark:border-slate-700 focus:border-cyan-500'
                    }`}
                  />
                </div>
                {touched.registerEmail && registerEmail && !registerEmailValid && (
                  <p className="text-[11px] text-red-600 dark:text-red-400 mt-0.5">
                    Please provide a valid email format.
                  </p>
                )}
              </div>

              {/* Password & Strength Meter */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300">
                    Password <span className="text-red-500">*</span>
                  </label>
                  {registerPassword && (
                    <span className={`text-[11px] font-bold ${passwordStrengthLabel.color}`}>
                      Strength: {passwordStrengthLabel.text}
                    </span>
                  )}
                </div>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type={registerShowPassword ? 'text' : 'password'}
                    required
                    value={registerPassword}
                    onChange={(e) => setRegisterPassword(e.target.value)}
                    placeholder="Min 8 characters, number & symbol"
                    className="w-full pl-9 pr-10 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl focus:outline-none focus:border-cyan-500 transition-colors"
                  />
                  <button
                    type="button"
                    onClick={() => setRegisterShowPassword(!registerShowPassword)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                    title={registerShowPassword ? "Hide password" : "Show password"}
                  >
                    {registerShowPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>

                {/* Password Strength Indicator Bars */}
                {registerPassword && (
                  <div className="mt-2 space-y-1.5">
                    <div className="grid grid-cols-4 gap-1.5 h-1.5 w-full">
                      {[1, 2, 3, 4].map((step) => (
                        <div 
                          key={step} 
                          className={`rounded-full transition-all duration-300 ${
                            passwordScore >= step 
                              ? passwordStrengthLabel.barColor 
                              : 'bg-slate-200 dark:bg-slate-800'
                          }`}
                        />
                      ))}
                    </div>

                    {/* Requirements Checklist */}
                    <div className="grid grid-cols-2 gap-1 text-[10px] text-slate-500 dark:text-slate-400 pt-0.5">
                      <span className={`flex items-center space-x-1 ${passwordCriteria.hasLength ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''}`}>
                        <Check className="w-3 h-3" />
                        <span>Min 8 characters</span>
                      </span>
                      <span className={`flex items-center space-x-1 ${passwordCriteria.hasNumber ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''}`}>
                        <Check className="w-3 h-3" />
                        <span>At least 1 number</span>
                      </span>
                      <span className={`flex items-center space-x-1 ${passwordCriteria.hasUpper ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''}`}>
                        <Check className="w-3 h-3" />
                        <span>1 uppercase letter</span>
                      </span>
                      <span className={`flex items-center space-x-1 ${passwordCriteria.hasSpecial ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : ''}`}>
                        <Check className="w-3 h-3" />
                        <span>1 special symbol</span>
                      </span>
                    </div>
                  </div>
                )}
              </div>

              {/* Confirm Password */}
              <div>
                <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                  Confirm Password <span className="text-red-500">*</span>
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                  <input
                    type={registerShowConfirm ? 'text' : 'password'}
                    required
                    value={registerConfirmPassword}
                    onChange={(e) => setRegisterConfirmPassword(e.target.value)}
                    placeholder="Re-enter password"
                    className={`w-full pl-9 pr-10 py-2 text-sm bg-slate-50 dark:bg-slate-950 border rounded-xl focus:outline-none transition-colors ${
                      registerConfirmPassword && !passwordsMatch
                        ? 'border-red-400 focus:border-red-500 dark:border-red-700'
                        : registerConfirmPassword && passwordsMatch
                        ? 'border-emerald-400 focus:border-emerald-500 dark:border-emerald-700'
                        : 'border-slate-300 dark:border-slate-700 focus:border-cyan-500'
                    }`}
                  />
                  <button
                    type="button"
                    onClick={() => setRegisterShowConfirm(!registerShowConfirm)}
                    className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors cursor-pointer"
                    title={registerShowConfirm ? "Hide password" : "Show password"}
                  >
                    {registerShowConfirm ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {registerConfirmPassword && (
                  <p className={`text-[11px] mt-0.5 flex items-center space-x-1 ${passwordsMatch ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-600 dark:text-red-400'}`}>
                    {passwordsMatch ? (
                      <>
                        <Check className="w-3 h-3" />
                        <span>Passwords match securely.</span>
                      </>
                    ) : (
                      <>
                        <X className="w-3 h-3" />
                        <span>Passwords do not match.</span>
                      </>
                    )}
                  </p>
                )}
              </div>

              {/* Phone & Preferred Language Row */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Mobile Number (Optional)
                  </label>
                  <div className="relative">
                    <Phone className="w-4 h-4 text-slate-400 absolute left-3 top-3 pointer-events-none" />
                    <input
                      type="tel"
                      value={registerPhone}
                      onChange={(e) => setRegisterPhone(e.target.value)}
                      placeholder="+91 9876543210"
                      className="w-full pl-9 pr-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
                    Preferred Language
                  </label>
                  <select
                    value={registerLang}
                    onChange={(e) => setRegisterLang(e.target.value)}
                    className="w-full px-3 py-2 text-sm bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded-xl focus:outline-none focus:border-cyan-500"
                  >
                    <option value="en">English</option>
                    <option value="hi">हिंदी (Hindi)</option>
                    <option value="gu">ગુજરાતી (Gujarati)</option>
                    <option value="ta">தமிழ் (Tamil)</option>
                    <option value="te">తెలుగు (Telugu)</option>
                    <option value="bn">বাংলা (Bengali)</option>
                  </select>
                </div>
              </div>

              {/* Consent Checkbox */}
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800">
                <label className="flex items-start space-x-2.5 cursor-pointer text-xs text-slate-600 dark:text-slate-400 select-none">
                  <input
                    type="checkbox"
                    checked={agreeTerms}
                    onChange={(e) => setAgreeTerms(e.target.checked)}
                    className="rounded border-slate-300 dark:border-slate-700 text-cyan-600 focus:ring-cyan-500 mt-0.5"
                  />
                  <span className="leading-relaxed">
                    I acknowledge that submitted messages will undergo automated threat triage with <strong>0-PII retention</strong> and evidence stored strictly for forensic incident dossiers.
                  </span>
                </label>
              </div>

              {/* Register Button */}
              <button
                type="submit"
                disabled={!canSubmitRegister}
                className="w-full py-2.5 px-4 bg-emerald-700 hover:bg-emerald-800 active:bg-emerald-900 text-white text-sm font-bold rounded-xl transition-all shadow-md flex items-center justify-center space-x-2 disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Creating Account in Neo4j Aura...</span>
                  </>
                ) : (
                  <>
                    <UserPlus className="w-4 h-4" />
                    <span>Register Citizen Account</span>
                  </>
                )}
              </button>

              <div className="pt-2 text-center text-xs text-slate-500 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800">
                Already registered?{' '}
                <button
                  type="button"
                  onClick={() => { setTab('login'); setError(null); }}
                  className="text-cyan-600 dark:text-cyan-400 font-bold hover:underline cursor-pointer"
                >
                  Sign in to your account
                </button>
              </div>
            </form>
          )}

          {/* ══════════════════════════════════════════════════════
              MY CHECKS / INCIDENT HISTORY TAB
             ══════════════════════════════════════════════════════ */}
          {tab === 'history' && currentUser && (
            <div className="space-y-3.5">
              {/* Profile Card */}
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-10 h-10 rounded-full bg-cyan-700 text-white font-bold flex items-center justify-center text-sm shadow-xs">
                    {(currentUser.display_name || currentUser.email)[0].toUpperCase()}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900 dark:text-white leading-tight">
                      {currentUser.display_name || currentUser.email}
                    </h3>
                    <p className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                      {currentUser.email}
                    </p>
                  </div>
                </div>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
                  Verified Citizen
                </span>
              </div>

              {/* Incident History Header */}
              <div className="flex items-center justify-between text-xs text-slate-600 dark:text-slate-400 pt-1">
                <span className="font-semibold text-slate-800 dark:text-slate-200">
                  Past Triage Dossiers ({historyItems.length})
                </span>
                <span className="text-[11px] text-slate-400">Neo4j Aura Persisted</span>
              </div>

              {historyLoading ? (
                <div className="py-10 flex flex-col items-center justify-center text-slate-400 text-xs">
                  <Loader2 className="w-6 h-6 animate-spin mb-2 text-cyan-600" />
                  <span>Retrieving persistent incident history from Neo4j...</span>
                </div>
              ) : historyItems.length === 0 ? (
                <div className="py-10 text-center text-xs text-slate-500 dark:text-slate-400 border border-dashed border-slate-200 dark:border-slate-800 rounded-xl p-4">
                  <History className="w-8 h-8 mx-auto text-slate-300 dark:text-slate-700 mb-2" />
                  <p className="font-bold text-slate-700 dark:text-slate-300">No scam checks recorded yet</p>
                  <p className="mt-1 max-w-xs mx-auto text-[11px]">
                    Suspicious messages, links, or screenshots analyzed while signed in will automatically be recorded here.
                  </p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[45vh] overflow-y-auto pr-1">
                  {historyItems.map((inc) => (
                    <div 
                      key={inc.incident_id}
                      className="p-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl hover:border-cyan-500 dark:hover:border-cyan-500 transition-all cursor-pointer group shadow-2xs"
                      onClick={() => {
                        if (onSelectIncident) {
                          onSelectIncident(inc.incident_id);
                          onClose();
                        }
                      }}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center space-x-2">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${getRiskBadge(inc.risk_level)}`}>
                            {inc.risk_level}
                          </span>
                          <span className="font-mono text-xs text-slate-900 dark:text-slate-100 font-bold truncate">
                            {inc.incident_id}
                          </span>
                        </div>
                        <ExternalLink className="w-3.5 h-3.5 text-slate-400 group-hover:text-cyan-600 transition-colors flex-shrink-0" />
                      </div>

                      <p className="text-xs text-slate-600 dark:text-slate-300 truncate mt-1">
                        {inc.message_preview || inc.title || 'Message analysis'}
                      </p>

                      <div className="flex items-center space-x-3 text-[10px] text-slate-400 mt-1.5 pt-1.5 border-t border-slate-200/60 dark:border-slate-800/60">
                        <span>{inc.created_at ? new Date(inc.created_at).toLocaleDateString() : 'Recent'}</span>
                        <span>Category: <strong className="text-slate-600 dark:text-slate-400">{inc.fraud_category || 'Uncategorized'}</strong></span>
                        <span>State: <strong className="text-slate-600 dark:text-slate-400">{inc.current_user_state}</strong></span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
