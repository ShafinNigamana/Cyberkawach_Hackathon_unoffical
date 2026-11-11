/**
 * Cyber Fraud Guardian — Complete Multi-Lingual Internationalization (i18n) Engine.
 * Dynamically toggles the language of the entire website in real-time.
 * Supported Languages: English (en), Hindi (hi), Gujarati (gu), Tamil (ta).
 */

const I18N = {
    currentLang: localStorage.getItem('cf_lang') || 'en',

    translations: {
        en: {
            title: "Cyber Fraud Guardian",
            panelTitle: "Analyze Message",
            messageLabel: "Paste suspicious message",
            messagePlaceholder: "Paste the suspicious SMS, email, or chat message here...",
            uploadScreenshot: "Upload Screenshot (OCR)",
            messageType: "Message type",
            situation: "Your situation",
            sitReceived: "I only received this message",
            sitClicked: "I clicked a link in it",
            sitEntered: "I entered my details/OTP",
            sitPaid: "I made a payment",
            typeText: "Text",
            typeSms: "SMS",
            typeEmail: "Email",
            typeChat: "Chat/WhatsApp",
            urlsLabel: "Additional URLs (optional, one per line)",
            urlsPlaceholder: "https://suspicious-link.example.com",
            analyzeBtn: "Analyze Message",
            analyzingBtn: "Analyzing...",
            loadSampleBtn: "Load Sample",
            resultsTitle: "Analysis Results",
            explanationTitle: "Explanation",
            evidenceTitle: "Evidence Items",
            threatIntelTitle: "Threat Intelligence",
            urlAnalysisTitle: "URL Analysis",
            responseTitle: "What You Should Do",
            attackPathTitle: "Threat Attack Path",
            stateSwitcherLabel: "Change your situation (demo):",
            btnReceived: "Only Received",
            btnClicked: "Clicked Link",
            btnEntered: "Entered Details",
            btnPaid: "Made Payment",
            checkingStatus: "Checking...",
            systemOnline: "System Online",
            systemOffline: "Backend Offline",
            analyzingText: "Analyzing message through 6-layer detection pipeline...",
            exportBtn: "📄 Download 1930 / Cyber Police Complaint Dossier",
            footer: "Cyber Fraud Guardian — National Citizen Threat Triage Portal",
            immediateActions: "Immediate Actions",
            recoverySteps: "Recovery Steps",
            reportThis: "Report This",
            syndicateAlert: "🧬 Fraud DNA Syndicate Campaign Alert",
            infrastructureFingerprint: "Infrastructure Fingerprint",
            firstOccurrence: "First tracked occurrence for this threat signature.",
            multiStageProgression: "Multi-Stage Threat Progression",
            keyReasons: "Key Reasons",
            noExplanation: "No explanation available.",
            noThreatIntel: "No threat intelligence data (APIs may not be configured).",
            sourceDeterministic: "Deterministic Rules",
            sourceGemini: "Gemini AI",

            // Risk Levels
            level_CRITICAL: "CRITICAL RISK",
            level_HIGH: "HIGH RISK",
            level_MEDIUM: "MEDIUM RISK",
            level_LOW: "LOW RISK",
            level_SAFE: "SAFE (NO THREAT)",
            level_UNKNOWN: "UNKNOWN RISK",

            // Fraud Categories
            cat_banking: "Banking Phishing",
            cat_electricity: "Electricity Bill Cutoff Scam",
            cat_digital_arrest: "Digital Arrest Police Scam",
            cat_courier: "Fake Courier Delivery Scam",
            cat_lottery_prize: "Lottery / Prize Scam",
            cat_job_offer: "Fake Job Offer Scam",
            cat_government: "Government Impersonation",
            cat_investment: "Investment / Crypto Scam",
            cat_tech_support: "Tech Support Scam",
            cat_unknown: "Suspicious Communication",

            // Threat Intel Status
            status_MATCH: "MATCH",
            status_Clean: "Clean",
            status_Unavailable: "Unavailable",

            // Urgencies
            urgency_CRITICAL: "CRITICAL",
            urgency_URGENT: "URGENT",
            urgency_NORMAL: "ADVISORY",

            // OCR
            ocrScanning: "Scanning {file} with OCR engine...",
            ocrSuccess: "✓ Successfully extracted text from {file}. Review below and click 'Analyze Message'.",
            ocrFail: "Upload failed: ",
        },

        hi: {
            title: "साइबर फ्रॉड गार्डियन",
            panelTitle: "संदेश की जांच करें",
            messageLabel: "संदिग्ध संदेश पेस्ट करें",
            messagePlaceholder: "संदिग्ध एसएमएस, ईमेल या व्हाट्सएप संदेश यहां पेस्ट करें...",
            uploadScreenshot: "स्क्रीनशॉट अपलोड करें (OCR)",
            messageType: "संदेश का प्रकार",
            situation: "आपकी वर्तमान स्थिति",
            sitReceived: "मुझे केवल यह संदेश मिला है",
            sitClicked: "मैंने इसमें दिए लिंक पर क्लिक किया है",
            sitEntered: "मैंने अपनी गोपनीय जानकारी / ओटीपी दर्ज की है",
            sitPaid: "मेरे बैंक खाते से पैसे कट गए हैं",
            typeText: "सामान्य टेक्स्ट",
            typeSms: "एसएमएस (SMS)",
            typeEmail: "ईमेल (Email)",
            typeChat: "व्हाट्सएप / चैट",
            urlsLabel: "अतिरिक्त लिंक (वैकल्पिक, प्रति पंक्ति एक)",
            urlsPlaceholder: "https://suspicious-link.example.com",
            analyzeBtn: "धोखाधड़ी की जांच करें",
            analyzingBtn: "जांच जारी है...",
            loadSampleBtn: "नमूना संदेश लोड करें",
            resultsTitle: "जांच परिणाम एवं निष्कर्ष",
            explanationTitle: "सरल भाषा में व्याख्या",
            evidenceTitle: "तकनीकी साक्ष्य एवं प्रमाण",
            threatIntelTitle: "वैश्विक खतरा डेटाबेस (Threat Intel)",
            urlAnalysisTitle: "वेबसाइट URL विश्लेषण",
            responseTitle: "नागरिक सुरक्षा सलाह एवं तत्काल कदम",
            attackPathTitle: "साइबर हमले का चक्र (Attack Path)",
            stateSwitcherLabel: "अपनी स्थिति बदलें (डेमो):",
            btnReceived: "केवल प्राप्त हुआ",
            btnClicked: "लिंक पर क्लिक किया",
            btnEntered: "जानकारी दर्ज की",
            btnPaid: "पैसे कट गए",
            checkingStatus: "जांच जारी...",
            systemOnline: "सिस्टम ऑनलाइन",
            systemOffline: "बैकएंड ऑफलाइन",
            analyzingText: "6-स्तरीय सुरक्षा पाइपलाइन द्वारा संदेश की जांच की जा रही है...",
            exportBtn: "📄 1930 / साइबर पुलिस शिकायत रिपोर्ट डाउनलोड करें",
            footer: "साइबर फ्रॉड गार्डियन — राष्ट्रीय नागरिक खतरा ट्राइएज पोर्टल",
            immediateActions: "तत्काल आवश्यक कदम",
            recoverySteps: "नुकसान से बचाव के उपाय",
            reportThis: "शिकायत दर्ज करें",
            syndicateAlert: "🧬 फ्रॉड डीएनए सिंडिकेट अभियान चेतावनी",
            infrastructureFingerprint: "इन्फ्रास्ट्रक्चर फिंगरप्रिंट",
            firstOccurrence: "इस खतरे के हस्ताक्षर की पहली बार पहचान हुई है।",
            multiStageProgression: "बहु-चरणीय साइबर हमले का चक्र",
            keyReasons: "मुख्य कारण एवं साक्ष्य",
            noExplanation: "व्याख्या उपलब्ध नहीं है।",
            noThreatIntel: "वैश्विक थ्रेट इंटेलिजेंस में कोई रिकॉर्ड नहीं मिला।",
            sourceDeterministic: "नियम आधारित इंजन",
            sourceGemini: "जेमिनी एआई (Gemini AI)",

            // Risk Levels
            level_CRITICAL: "अत्यधिक गंभीर जोखिम (CRITICAL)",
            level_HIGH: "उच्च जोखिम (HIGH)",
            level_MEDIUM: "मध्यम जोखिम (MEDIUM)",
            level_LOW: "कम जोखिम (LOW)",
            level_SAFE: "सुरक्षित (कोई खतरा नहीं)",
            level_UNKNOWN: "अज्ञात जोखिम",

            // Fraud Categories
            cat_banking: "बैंक धोखाधड़ी (Banking Scam)",
            cat_electricity: "बिजली बिल डिस्कनेक्शन फ्रॉड (Bijli Scam)",
            cat_digital_arrest: "डिजिटल अरेस्ट / पुलिस वसूली (Digital Arrest)",
            cat_courier: "कूरियर / पार्सल डिलीवरी फ्रॉड",
            cat_lottery_prize: "लॉटरी / इनाम घोटाला",
            cat_job_offer: "फर्जी नौकरी का झांसा (Job Scam)",
            cat_government: "सरकारी विभाग के नाम पर धोखा",
            cat_investment: "फर्जी निवेश / पोंजी घोटाला",
            cat_tech_support: "तकनीकी सहायता फ्रॉड",
            cat_unknown: "संदिग्ध संदेश",

            // Threat Intel Status
            status_MATCH: "खतरा मिला (MATCH)",
            status_Clean: "सुरक्षित (Clean)",
            status_Unavailable: "अनुपलब्ध",

            // Urgencies
            urgency_CRITICAL: "अत्यंत गंभीर",
            urgency_URGENT: "तत्काल",
            urgency_NORMAL: "सलाह",

            // OCR
            ocrScanning: "{file} का OCR द्वारा विश्लेषण किया जा रहा है...",
            ocrSuccess: "✓ {file} से सफलतापूर्वक टेक्स्ट निकाल लिया गया। नीचे समीक्षा करें और 'धोखाधड़ी की जांच करें' पर क्लिक करें।",
            ocrFail: "अपलोड विफल: ",
        },

        gu: {
            title: "સાયબર ફ્રોડ ગાર્ડિયન",
            panelTitle: "સંદેશની ચકાસણી કરો",
            messageLabel: "શંકાસ્પદ સંદેશ પેસ્ટ કરો",
            messagePlaceholder: "શંકાસ્પદ એસએમએસ, ઈમેલ અથવા વોટ્સએપ મેસેજ અહીં પેસ્ટ કરો...",
            uploadScreenshot: "સ્ક્રીનશોટ અપલોડ કરો (OCR)",
            messageType: "સંદેશનો પ્રકાર",
            situation: "તમારી વર્તમાન પરિસ્થિતિ",
            sitReceived: "મને માત્ર આ સંદેશ મળ્યો છે",
            sitClicked: "મેં તેમાં આવેલી લિંક પર ક્લિક કર્યું છે",
            sitEntered: "મેં મારી વિગતો / ઓટીપી દાખલ કરી છે",
            sitPaid: "મારા ખાતામાંથી નાણાં કપાઈ ગયા છે",
            typeText: "સામાન્ય લખાણ",
            typeSms: "એસએમએસ (SMS)",
            typeEmail: "ઈમેલ (Email)",
            typeChat: "વોટ્સએપ / ચેટ",
            urlsLabel: "વધારાની લિંક્સ (વૈકલ્પિક, એક લીટીમાં એક)",
            urlsPlaceholder: "https://suspicious-link.example.com",
            analyzeBtn: "છેતરપિંડી તપાસો",
            analyzingBtn: "તપાસ ચાલુ છે...",
            loadSampleBtn: "નમૂનો લોડ કરો",
            resultsTitle: "તપાસ પરિણામો",
            explanationTitle: "સરળ ભાષામાં સમજૂતી",
            evidenceTitle: "ટેકનિકલ પુરાવા દસ્તાવેજ",
            threatIntelTitle: "વૈશ્વિક થ્રેટ ઇન્ટેલિજન્સ ફીડ્સ",
            urlAnalysisTitle: "વેબસાઇટ URL વિશ્લેષણ",
            responseTitle: "નાગરિક સુરક્ષા પગલાં અને માર્ગદર્શન",
            attackPathTitle: "સાયબર હુમલાની પ્રગતિ (Attack Path)",
            stateSwitcherLabel: "તમારી પરિસ્થિતિ બદલો (ડેમો):",
            btnReceived: "ફક્ત મળ્યો",
            btnClicked: "લિંક ક્લિક કરી",
            btnEntered: "વિગતો દાખલ કરી",
            btnPaid: "નાણાં ચૂકવ્યા",
            checkingStatus: "તપાસ ચાલુ...",
            systemOnline: "સિસ્ટમ ઑનલાઇન",
            systemOffline: "બેકએન્ડ ઑફલાઇન",
            analyzingText: "6-લેયર સુરક્ષા પાઇપલાઇન દ્વારા વિશ્લેષણ થઈ રહ્યું છે...",
            exportBtn: "📄 1930 / સાયબર પોલીસ ફરિયાદ અહેવાલ ડાઉનલોડ કરો",
            footer: "સાયબર ફ્રોડ ગાર્ડિયન — રાષ્ટ્રીય નાગરિક જોખમ તપાસ પોર્ટલ",
            immediateActions: "તાત્કાલિક જરૂરી પગલાં",
            recoverySteps: "બચાવના પગલાં",
            reportThis: "અહીં ફરિયાદ નોંધાવો",
            syndicateAlert: "🧬 ફ્રોડ ડીએનએ સિન્ડિકેટ અભિયાન ચેતવણી",
            infrastructureFingerprint: "ઇન્ફ્રાસ્ટ્રક્ચર ફિંગરપ્રિન્ટ",
            firstOccurrence: "આ સુરક્ષા સહી માટે પ્રથમ નોંધાયેલ ઘટના.",
            multiStageProgression: "બહુ-તબક્કાવાર સાયબર હુમલાની પ્રગતિ",
            keyReasons: "મુખ્ય કારણો અને પુરાવા",
            noExplanation: "સમજૂતી ઉપલબ્ધ નથી.",
            noThreatIntel: "ગ્લોબલ થ્રેટ ઇન્ટેલમાં કોઈ ડેટા નથી.",
            sourceDeterministic: "રૂલ આધારિત એન્જિન",
            sourceGemini: "જેમિની એઆઈ (Gemini AI)",

            // Risk Levels
            level_CRITICAL: "અત્યંત ગંભીર જોખમ (CRITICAL)",
            level_HIGH: "ઉચ્ચ જોખમ (HIGH)",
            level_MEDIUM: "મધ્યમ જોખમ (MEDIUM)",
            level_LOW: "ઓછું જોખમ (LOW)",
            level_SAFE: "સુરક્ષિત (કોઈ જોખમ નથી)",
            level_UNKNOWN: "અજ્ઞાત જોખમ",

            // Fraud Categories
            cat_banking: "બેંક છેતરપિંડી (Banking Scam)",
            cat_electricity: "વીજળી બિલ કટઓફ છેતરપિંડી",
            cat_digital_arrest: "ડિજિટલ ધરપકડ / પોલીસ એક્સટોર્શન",
            cat_courier: "કુરિયર / પાર્સલ ડિલિવરી ફ્રોડ",
            cat_lottery_prize: "લોટરી / ઇનામ કૌભાંડ",
            cat_job_offer: "નકલી નોકરી ઓફર છેતરપિંડી",
            cat_government: "સરકારી વિભાગના નામે છેતરપિંડી",
            cat_investment: "રોકાણ કૌભાંડ",
            cat_tech_support: "ટેક સપોર્ટ સ્કેમ",
            cat_unknown: "શંકાસ્પદ સંદેશ",

            // Threat Intel Status
            status_MATCH: "જોખમ મળ્યું (MATCH)",
            status_Clean: "સુરક્ષિત (Clean)",
            status_Unavailable: "અનુપલબ્ધ",

            // Urgencies
            urgency_CRITICAL: "અતિ ગંભીર",
            urgency_URGENT: "તાત્કાલિક",
            urgency_NORMAL: "સલાહ",

            // OCR
            ocrScanning: "{file} નું OCR વડે વિશ્લેષણ થઈ રહ્યું છે...",
            ocrSuccess: "✓ {file} માંથી લખાણ સફળતાપૂર્વક મેળવાયું. ચકાસીને 'છેતરપિંડી તપાસો' ક્લિક કરો.",
            ocrFail: "અપલોડ નિષ્ફળ: ",
        },

        ta: {
            title: "சைபர் மோசடி காவலர்",
            panelTitle: "செய்தியை பகுப்பாய்வு செய்க",
            messageLabel: "சந்தேகத்திற்குரிய செய்தியை ஒட்டவும்",
            messagePlaceholder: "சந்தேகத்திற்குரிய எஸ்எம்எஸ், மின்னஞ்சல் அல்லது வாட்ஸ்அப் செய்தியை இங்கே ஒட்டவும்...",
            uploadScreenshot: "ஸ்கிரீன்ஷாட் பதிவேற்றவும் (OCR)",
            messageType: "செய்தி வகை",
            situation: "உங்கள் தற்போதைய நிலை",
            sitReceived: "எனக்கு இந்த செய்தி மட்டுமே வந்தது",
            sitClicked: "நான் இதில் உள்ள இணைப்பைக் கிளிக் செய்தேன்",
            sitEntered: "எனது விவரங்கள் / OTP ஐ உள்ளிட்டேன்",
            sitPaid: "நான் பணம் செலுத்திவிட்டேன்",
            typeText: "உரை",
            typeSms: "எஸ்எம்எஸ் (SMS)",
            typeEmail: "மின்னஞ்சல் (Email)",
            typeChat: "வாட்ஸ்அப் / அரட்டை",
            urlsLabel: "கூடுதல் இணைப்புகள் (விருப்பத்தேர்வு)",
            urlsPlaceholder: "https://suspicious-link.example.com",
            analyzeBtn: "மோசடி சரிபார்க்கவும்",
            analyzingBtn: "ஆய்வு செய்யப்படுகிறது...",
            loadSampleBtn: "மாதிரியை ஏற்றுக",
            resultsTitle: "பகுப்பாய்வு முடிவுகள்",
            explanationTitle: "எளிய மொழி விளக்கம்",
            evidenceTitle: "தொழில்நுட்ப ஆதாரங்கள்",
            threatIntelTitle: "அச்சுறுத்தல் நுண்ணறிவு",
            urlAnalysisTitle: "இணைப்பு பகுப்பாய்வு",
            responseTitle: "பரிந்துரைக்கப்பட்ட நடவடிக்கைகள்",
            attackPathTitle: "தாக்குதல் முன்னேற்றம் (Attack Path)",
            stateSwitcherLabel: "உங்கள் நிலையை மாற்றவும் (டெமோ):",
            btnReceived: "பெறப்பட்டது மட்டும்",
            btnClicked: "இணைப்பு கிளிக் செய்யப்பட்டது",
            btnEntered: "விவரங்கள் உள்ளிட்டவை",
            btnPaid: "பணம் செலுத்தப்பட்டது",
            checkingStatus: "சரிபார்க்கிறது...",
            systemOnline: "அமைப்பு ஆன்லைன்",
            systemOffline: "ஆஃப்லைன்",
            analyzingText: "6-அடுக்கு பாதுகாப்பு அமைப்பில் ஆய்வு செய்யப்படுகிறது...",
            exportBtn: "📄 1930 / சைபர் காவல் புகார் அறிக்கையைப் பதிவிறக்கவும்",
            footer: "சைபர் மோசடி காவலர் — தேசிய குடிமக்கள் அச்சுறுத்தல் பகுப்பாய்வு தளம்",
            immediateActions: "உடனடி நடவடிக்கைகள்",
            recoverySteps: "மீட்பு நடவடிக்கைகள்",
            reportThis: "புகார் செய்க",
            syndicateAlert: "🧬 மோசடி டிஎன்ஏ பிரச்சார எச்சரிக்கை",
            infrastructureFingerprint: "கட்டமைப்பு கைரேகை",
            firstOccurrence: "இந்த அச்சுறுத்தல் கையொப்பத்திற்கான முதல் பதிவு.",
            multiStageProgression: "தாக்குதல் முன்னேற்றம்",
            keyReasons: "முக்கிய காரணங்கள் மற்றும் ஆதாரங்கள்",
            noExplanation: "விளக்கம் கிடைக்கவில்லை.",
            noThreatIntel: "அச்சுறுத்தல் தரவு எதுவும் கிடைக்கவில்லை.",
            sourceDeterministic: "விதி அடிப்படையிலான இயந்திரம்",
            sourceGemini: "ஜெமினி AI",

            // Risk Levels
            level_CRITICAL: "மிகக் கடுமையான ஆபத்து (CRITICAL)",
            level_HIGH: "அதிக ஆபத்து (HIGH)",
            level_MEDIUM: "நடுத்தர ஆபத்து (MEDIUM)",
            level_LOW: "குறைந்த ஆபத்து (LOW)",
            level_SAFE: "பாதுகாப்பானது (ஆபத்து இல்லை)",
            level_UNKNOWN: "தெரியாத ஆபத்து",

            // Fraud Categories
            cat_banking: "வங்கி மோசடி (Banking Scam)",
            cat_electricity: "மின் கட்டண துண்டிப்பு மோசடி",
            cat_digital_arrest: "டிஜிட்டல் கைது மிரட்டல் மோசடி",
            cat_courier: "பார்சல் டெலிவரி மோசடி",
            cat_lottery_prize: "லாட்டரி / பரிசு மோசடி",
            cat_job_offer: "போலி வேலை வாய்ப்பு மோசடி",
            cat_government: "அரசு ஆள்மாறாட்ட மோசடி",
            cat_investment: "முதலீட்டு மோசடி",
            cat_tech_support: "தொழில்நுட்ப உதவி மோசடி",
            cat_unknown: "சந்தேகத்திற்குரிய செய்தி",

            // Threat Intel Status
            status_MATCH: "பொருந்தியது (MATCH)",
            status_Clean: "தூய்மையானது (Clean)",
            status_Unavailable: "கிடைக்கவில்லை",

            // Urgencies
            urgency_CRITICAL: "மிக முக்கியமானது",
            urgency_URGENT: "உடனடி",
            urgency_NORMAL: "ஆலோசனை",

            // OCR
            ocrScanning: "{file} OCR மூலம் ஸ்கேன் செய்யப்படுகிறது...",
            ocrSuccess: "✓ {file} இலிருந்து உரை வெற்றிகரமாக பிரித்தெடுக்கப்பட்டது. கீழே சரிபார்த்து 'மோசடி சரிபார்க்கவும்' என்பதைக் கிளிக் செய்யவும்.",
            ocrFail: "பதிவேற்றம் தோல்வியுற்றது: ",
        },
    },

    // ─── Localized Sample Messages for each supported language ───
    samples: {
        en: [
            {
                id: 'demo-banking',
                label: '🏦 SBI KYC Scam (Banking)',
                input_type: 'sms',
                message: 'Dear Customer, Your SBI account has been BLOCKED due to incomplete KYC verification. Update your KYC immediately to avoid permanent account closure. Click here: https://sbi-kyc-update.xyz/verify?ref=8827361 or call 9876543210. Last date: 24 hours. -SBI Team',
            },
            {
                id: 'demo-electricity',
                label: '⚡ Electricity Bill Cutoff (Bijli Scam)',
                input_type: 'sms',
                message: 'Dear Consumer, Your electricity power will be disconnected tonight at 9:30 PM from the electricity office because your previous month bill was not updated. Please immediately contact our electricity officer at 9812345678 or visit http://quick-bijli-pay.xyz/update -BSES Officer',
            },
            {
                id: 'demo-digital-arrest',
                label: '👮 Digital Arrest / Police Extortion',
                input_type: 'sms',
                message: 'URGENT NOTICE: A parcel containing contraband narcotics and fake passports in your name has been seized by Customs. An FIR and arrest warrant has been registered under PMLA by Mumbai Police and CBI. Connect to Skype immediately or police team will reach your residence within 1 hour.',
            },
            {
                id: 'demo-courier',
                label: '📦 Fake Delivery (Courier)',
                input_type: 'sms',
                message: 'Your parcel from Amazon could not be delivered due to incorrect address. Please reschedule delivery by paying Rs. 25 customs charge: https://amaz0n-delivery.top/reschedule Track: AWB7839201. -Delhivery',
            },
            {
                id: 'demo-govt',
                label: '💰 Income Tax Refund (Government)',
                input_type: 'email',
                message: 'Subject: Income Tax Refund - Rs 18,500 Credited\n\nDear Taxpayer,\n\nYour income tax refund of Rs 18,500 has been approved. Due to outdated bank details, the refund could not be processed. Please update your bank account details within 48 hours to receive your refund:\n\nhttps://incometax-refund.click/update-bank\n\nFailure to update will result in cancellation of refund.\n\nRegards,\nIncome Tax Department, Govt. of India',
            },
            {
                id: 'demo-lottery',
                label: '🎁 Google Lottery Prize Scam',
                input_type: 'chat',
                message: 'CONGRATULATIONS! You have WON Rs 25,00,000 in the Google Annual Lottery 2026! Your ticket number: GL-29384. To claim your prize, pay the processing fee of Rs 4,999 via Google Pay to merchant@gpay. Contact: lottery.winner2026@gmail.com. Hurry, offer expires in 12 hours!',
            },
            {
                id: 'demo-clean',
                label: '🟢 Legitimate Bank OTP (Clean - 0% Scam)',
                input_type: 'sms',
                message: '849201 is your OTP for purchase of Rs 1,450.00 at Swiggy on HDFC Bank Card ending 4019. OTP valid for 5 mins. Do not share OTP with anyone.',
            },
        ],

        hi: [
            {
                id: 'demo-hi-electricity',
                label: '⚡ बिजली बिल डिस्कनेक्शन नोटिस (Bijli Scam)',
                input_type: 'sms',
                message: 'प्रिय उपभोक्ता, आपका बिजली कनेक्शन आज रात 9:30 बजे काट दिया जाएगा क्योंकि पिछले महीने का बिल अपडेट नहीं हुआ है। तुरंत बिजली अधिकारी से 9812345678 पर संपर्क करें या http://quick-bijli-pay.xyz/update पर भुगतान करें। -बिजली विभाग',
            },
            {
                id: 'demo-hi-digital-arrest',
                label: '👮 डिजिटल अरेस्ट - सीबीआई / मुंबई पुलिस नोटिस',
                input_type: 'sms',
                message: 'अति आवश्यक सूचना: आपके नाम से एक संदिग्ध पार्सल जब्त किया गया है जिसमें मादक पदार्थ पाए गए हैं। सीबीआई और मुंबई पुलिस द्वारा आपके खिलाफ गिरफ्तारी वारंट जारी किया गया है। तुरंत स्काइप पर जुड़ें अन्यथा पुलिस टीम 1 घंटे में आपके पते पर पहुंचेगी।',
            },
            {
                id: 'demo-hi-banking',
                label: '🏦 एसबीआई बैंक खाता ब्लॉक - केवाईसी अपडेट',
                input_type: 'sms',
                message: 'प्रिय ग्राहक, आपका एसबीआई बैंक खाता केवाईसी अधूरा होने के कारण ब्लॉक कर दिया गया है। स्थायी रोक से बचने के लिए तुरंत केवाईसी अपडेट करें: https://sbi-kyc-update.xyz/verify या कॉल करें 9876543210. अंतिम समय 24 घंटे। -एसबीआई टीम',
            },
            {
                id: 'demo-hi-courier',
                label: '📦 कूरियर पार्सल डिलीवरी शुल्क (कूरियर फ्रॉड)',
                input_type: 'sms',
                message: 'अमेज़न से आपका पार्सल गलत पते के कारण डिलीवर नहीं हो सका। 25 रुपये कस्टम शुल्क देकर डिलीवरी दोबारा शेड्यूल करें: https://amaz0n-delivery.top/reschedule ट्रैकिंग: AWB7839201.',
            },
            {
                id: 'demo-hi-clean',
                label: '🟢 प्रामाणिक बैंक ओटीपी (सुरक्षित लेन-देन)',
                input_type: 'sms',
                message: 'स्विगी पर एचडीएफसी कार्ड के जरिए 1,450.00 रुपये के भुगतान के लिए आपका ओटीपी 849201 है। यह 5 मिनट के लिए वैध है। किसी के साथ साझा न करें।',
            },
        ],

        gu: [
            {
                id: 'demo-gu-electricity',
                label: '⚡ વીજળી બિલ કટઓફ ચેતવણી (Bijli Scam)',
                input_type: 'sms',
                message: 'માનનીય ગ્રાહક, તમારા ગયા મહિનાના વીજળી બિલની ચુકવણી ન થવાને કારણે આજે રાત્રે 9:30 કલાકે તમારું પાવર કનેક્શન કાપી નાખવામાં આવશે. તાત્કાલિક અમારા વીજળી અધિકારીનો 9812345678 પર સંપર્ક કરો અથવા http://quick-bijli-pay.xyz પર અપડેટ કરો.',
            },
            {
                id: 'demo-gu-digital-arrest',
                label: '👮 ડિજિટલ ધરપકડ - સીબીઆઈ અરેસ્ટ વોરંટ',
                input_type: 'sms',
                message: 'તાકીદની નોટિસ: તમારા નામે કુરિયરમાં ગેરકાયદેસર સામાન જપ્ત કરવામાં આવ્યો છે. મુંબઈ પોલીસ અને સીબીઆઈ દ્વારા તમારી સામે ડિજિટલ ધરપકડ અને એફઆઈઆર નોંધવામાં આવી છે. તાત્કાલિક સ્કાઇપ પર જોડાઓ અથવા 1 કલાકમાં પોલીસ ટીમ તમારા ઘરે પહોંચશે.',
            },
            {
                id: 'demo-gu-banking',
                label: '🏦 એસબીઆઈ ખાતું બ્લોક - કેવાયસી અપડેટ',
                input_type: 'sms',
                message: 'પ્રિય ગ્રાહક, અધૂરા કેવાયસી વેરિફિકેશનને કારણે તમારું એસબીઆઈ ખાતું બ્લોક કરવામાં આવ્યું છે. કાયમી બંધ ટાળવા માટે તાત્કાલિક કેવાયસી અપડેટ કરો: https://sbi-kyc-update.xyz/verify અથવા 9876543210 પર કોલ કરો.',
            },
            {
                id: 'demo-gu-clean',
                label: '🟢 અસલી બેંક ઓટીપી (સુરક્ષિત સંદેશ)',
                input_type: 'sms',
                message: '849201 એ એચડીએફસી બેંક કાર્ડ માટે સ્વિગી ખાતે રૂ. 1,450 ના પેમેન્ટ માટેનો તમારો ઓટીપી છે. ઓટીપી 5 મિનિટ માટે માન્ય છે. કોઈની સાથે શેર કરશો નહીં.',
            },
        ],

        ta: [
            {
                id: 'demo-ta-electricity',
                label: '⚡ மின் இணைப்பு துண்டிப்பு எச்சரிக்கை (Bijli Scam)',
                input_type: 'sms',
                message: 'அன்புள்ள நுகர்வோரே, கடந்த மாத மின் கட்டணம் செலுத்தப்படாததால் இன்று இரவு 9:30 மணிக்கு உங்கள் மின் இணைப்பு துண்டிக்கப்படும். உடனடியாக மின்சார அதிகாரியை 9812345678 என்ற எண்ணில் தொடர்பு கொள்ளவும் அல்லது http://quick-bijli-pay.xyz/update இல் புதுப்பிக்கவும்.',
            },
            {
                id: 'demo-ta-digital-arrest',
                label: '👮 டிஜிட்டல் கைது - சிபிஐ / காவல் துறை மிரட்டல்',
                input_type: 'sms',
                message: 'அவசர அறிவிப்பு: உங்கள் பெயரில் வந்த பார்சலில் தடைசெய்யப்பட்ட பொருட்கள் கைப்பற்றப்பட்டுள்ளன. மும்பை போலீஸ் மற்றும் சிபிஐ மூலம் உங்கள் மீது கைது வாரண்ட் பிறப்பிக்கப்பட்டுள்ளது. உடனடியாக ஸ்கைப் மூலம் இணையவும், இல்லையெனில் 1 மணி நேரத்தில் போலீஸ் உங்கள் இருப்பிடத்தை அடையும்.',
            },
            {
                id: 'demo-ta-banking',
                label: '🏦 எஸ்பிஐ வங்கி கணக்கு முடக்கம் - KYC புதுப்பிப்பு',
                input_type: 'sms',
                message: 'அன்புள்ள வாடிக்கையாளரே, முழுமையடையாத KYC சரிபார்ப்பு காரணமாக உங்கள் எஸ்பிஐ கணக்கு முடக்கப்பட்டுள்ளது. கணக்கு ரத்தாவதைத் தவிர்க்க உடனடியாக KYC ஐப் புதுப்பிக்கவும்: https://sbi-kyc-update.xyz/verify அல்லது 9876543210 ஐ அழைக்கவும்.',
            },
            {
                id: 'demo-ta-clean',
                label: '🟢 பாதுகாப்பான வங்கி OTP (உண்மையான செய்தி)',
                input_type: 'sms',
                message: 'ஸ்விக்கியில் ரூ. 1,450.00 செலுத்துவதற்கான உங்கள் HDFC வங்கி அட்டை OTP 849201 ஆகும். இந்த OTP 5 நிமிடங்களுக்கு மட்டுமே செல்லுபடியாகும். இதை யாருடனும் பகிர வேண்டாம்.',
            },
        ],
    },

    t(key, defaultVal) {
        const langMap = this.translations[this.currentLang] || this.translations['en'];
        const fallbackMap = this.translations['en'];
        return langMap[key] || fallbackMap[key] || defaultVal || key;
    },

    getSamples() {
        return this.samples[this.currentLang] || this.samples['en'];
    },

    setLanguage(lang) {
        if (!this.translations[lang]) lang = 'en';
        this.currentLang = lang;
        localStorage.setItem('cf_lang', lang);
        this.applyTranslations();

        // Broadcast to listeners (e.g. app.js) to re-render dynamic components
        window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
    },

    applyTranslations() {
        const lang = this.currentLang;
        document.documentElement.lang = lang;

        // 1. Page Title
        document.title = this.t('title');

        // 2. Static text elements with data-i18n
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            const translation = this.t(key);
            if (translation) {
                if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
                    el.placeholder = translation;
                } else {
                    el.textContent = translation;
                }
            }
        });

        // 3. Form Select Options (Message Type)
        const inputTypeSelect = document.getElementById('input-type');
        if (inputTypeSelect) {
            const options = {
                text: this.t('typeText'),
                sms: this.t('typeSms'),
                email: this.t('typeEmail'),
                chat: this.t('typeChat')
            };
            Array.from(inputTypeSelect.options).forEach(opt => {
                if (options[opt.value]) opt.textContent = options[opt.value];
            });
        }

        // 4. User Situation Options
        const userStateSelect = document.getElementById('user-state');
        if (userStateSelect) {
            const sitOptions = {
                received: this.t('sitReceived'),
                clicked: this.t('sitClicked'),
                entered_credentials: this.t('sitEntered'),
                paid: this.t('sitPaid')
            };
            Array.from(userStateSelect.options).forEach(opt => {
                if (sitOptions[opt.value]) opt.textContent = sitOptions[opt.value];
            });
        }

        // 5. Input Placeholders
        const msgInput = document.getElementById('message-input');
        if (msgInput) msgInput.placeholder = this.t('messagePlaceholder');

        const urlsInput = document.getElementById('urls-input');
        if (urlsInput) urlsInput.placeholder = this.t('urlsPlaceholder');

        // 6. Buttons
        const analyzeBtn = document.getElementById('analyze-btn');
        if (analyzeBtn && !analyzeBtn.disabled) {
            const iconSvg = analyzeBtn.querySelector('svg');
            const iconHtml = iconSvg ? iconSvg.outerHTML : '';
            analyzeBtn.innerHTML = `${iconHtml} <span>${this.t('analyzeBtn')}</span>`;
        }

        const sampleBtn = document.getElementById('sample-btn');
        if (sampleBtn) sampleBtn.textContent = this.t('loadSampleBtn');

        // 7. State Switcher Demo Buttons
        const stateButtons = document.getElementById('state-buttons');
        if (stateButtons) {
            const mapping = {
                received: this.t('btnReceived'),
                clicked: this.t('btnClicked'),
                entered_credentials: this.t('btnEntered'),
                paid: this.t('btnPaid')
            };
            stateButtons.querySelectorAll('[data-state]').forEach(btn => {
                const state = btn.getAttribute('data-state');
                if (mapping[state]) btn.textContent = mapping[state];
            });
        }

        // 8. Health status badge
        const healthStatus = document.getElementById('health-status');
        if (healthStatus) {
            if (healthStatus.classList.contains('error')) {
                healthStatus.textContent = this.t('systemOffline');
            } else if (healthStatus.textContent && healthStatus.textContent !== 'Checking...' && healthStatus.textContent !== this.t('checkingStatus')) {
                healthStatus.textContent = this.t('systemOnline');
            }
        }
    }
};

window.I18N = I18N;
