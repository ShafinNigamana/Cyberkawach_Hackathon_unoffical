"""
Adaptive response state machine.

RSP-01: Branches guidance based on user's interaction state with the scam:
  - received: User only received the message
  - clicked: User clicked a link
  - entered_credentials: User entered login/OTP/card details
  - paid: User made a payment

Phase 8 Accuracy Refinements:
- Epistemic proportionality: LOW and UNKNOWN risks receive calm, educational guidance
  instead of alarmist account-freezing emergency procedures.
- High-fidelity Indian cyber infrastructure: Surfaces 1930 (Golden Hour inter-bank fund freeze),
  cybercrime.gov.in, 1909 (TRAI DND), and DoT Chakshu portal (sancharsaathi.gov.in/sfc).
- Contextual enrichment: Tailored actions for identified brands (official domains),
  UPI payment dispute steps, and specific scam typologies (electricity, courier).
"""

from __future__ import annotations

from backend.models.evidence import (
    AdaptiveResponse,
    IncidentEvidence,
    RiskLevel,
    UserState,
)


# ─── Standard Response Guidance by Interaction State ───

# ─── Standard Response Guidance by Interaction State ───

_DEFAULT_RESPONSES: dict[str, dict[UserState, dict]] = {
    "en": {
        UserState.RECEIVED: {
            "urgency": "normal",
            "immediate_actions": [
                "Do NOT click any links in this message",
                "Do NOT call any phone numbers mentioned",
                "Do NOT reply to the sender or share OTPs",
                "Do NOT forward this message to others",
            ],
            "recovery_steps": [
                "Block the sender's number/email address",
                "Mark the message as spam/junk in your messaging app",
                "If the message claims to be from a known organization, verify by contacting them through their official website or helpline",
            ],
            "reporting_info": [
                "Report at cybercrime.gov.in (National Cyber Crime Reporting Portal)",
                "Call 1930 (National Cyber Crime Helpline)",
                "Forward fraudulent SMS to DoT Chakshu portal (sancharsaathi.gov.in/sfc)",
                "Forward spam SMS to 1909 (TRAI DND service)",
            ],
        },
        UserState.CLICKED: {
            "urgency": "urgent",
            "immediate_actions": [
                "CLOSE the website/page immediately",
                "Do NOT enter any information, passwords, or OTPs on the page",
                "Clear your browser history, cache, and cookies for that site",
                "If on mobile, close all browser tabs and check recent downloads",
            ],
            "recovery_steps": [
                "Run a security scan on your device using a trusted antivirus tool",
                "Check if any unknown apps, profiles, or APKs were installed — remove them immediately",
                "Monitor your accounts for the next 48 hours for unusual activity",
                "Enable two-factor authentication on important accounts if not already active",
                "Change passwords for any accounts accessed recently from that device",
            ],
            "reporting_info": [
                "Report at cybercrime.gov.in with details and screenshot of the link clicked",
                "Call 1930 (National Cyber Crime Helpline)",
                "Report the malicious URL to Google Safe Browsing: safebrowsing.google.com/safebrowsing/report_phish/",
                "Report fraudulent communication on DoT Chakshu portal: sancharsaathi.gov.in/sfc",
            ],
        },
        UserState.ENTERED_CREDENTIALS: {
            "urgency": "critical",
            "immediate_actions": [
                "IMMEDIATELY change the password for the affected account",
                "IMMEDIATELY change passwords for any other accounts sharing the same password",
                "Contact your bank's official emergency helpline immediately to lock netbanking or block cards",
                "Request your bank to temporarily freeze online transactions and UPI access",
                "Enable two-factor authentication (prefer authenticator app over SMS)",
            ],
            "recovery_steps": [
                "Log out of all active sessions across devices for compromised accounts",
                "Review recent account activity and audit active login sessions",
                "Check if email forwarding rules or secondary recovery numbers were modified",
                "Set up instant transaction alerts on all linked accounts",
                "Monitor credit reports and bank statements for unauthorized inquiries",
                "Consider a credit freeze if national identity documents (Aadhaar/PAN) were shared",
            ],
            "reporting_info": [
                "File an immediate complaint at cybercrime.gov.in",
                "Call 1930 (National Cyber Crime Helpline) — available 24/7",
                "Contact your bank's fraud prevention department through their official helpline",
                "File a complaint with the local cyber police station",
                "Preserve all evidence (messages, screenshots, URLs, call logs)",
            ],
        },
        UserState.PAID: {
            "urgency": "critical",
            "immediate_actions": [
                "IMMEDIATELY contact your bank to report unauthorized debit and request transaction reversal",
                "Call 1930 IMMEDIATELY — the first 'Golden Hour' is critical for inter-bank fund freezing via I4C",
                "Request your bank to freeze your account / UPI ID to prevent further unauthorized debits",
                "If paid via UPI, report the transaction immediately inside your UPI app under 'Report Dispute'",
                "Do NOT make any additional payments even if the scammer promises a refund or fee release",
            ],
            "recovery_steps": [
                "File a cybercrime report at cybercrime.gov.in with UTR number, transaction IDs, and bank statements",
                "File an FIR at the nearest cyber police station with all gathered evidence",
                "Gather evidence: transaction UTR reference, screenshots, call logs, message records",
                "Change all banking PINs, netbanking passwords, and UPI PINs",
                "Contact the RBI Banking Ombudsman (cms.rbi.org.in) if your bank does not provide timely assistance",
                "Monitor all linked accounts for additional unauthorized debits",
            ],
            "reporting_info": [
                "Call 1930 — National Cyber Crime Helpline (24/7, critical for Golden Hour fund freezing)",
                "File complaint at cybercrime.gov.in (Citizen Financial Cyber Fraud Reporting System)",
                "Raise dispute with National Payments Corporation of India (NPCI) at npci.org.in if UPI transfer",
                "Contact your bank's fraud response desk and note the complaint acknowledgement number",
                "Follow up on your complaint within 24-48 hours",
            ],
        },
    },
    "hi": {
        UserState.RECEIVED: {
            "urgency": "normal",
            "immediate_actions": [
                "इस संदेश में दिए गए किसी भी लिंक पर क्लिक न करें",
                "उल्लिखित किसी भी फ़ोन नंबर पर कॉल न करें",
                "प्रेषक को उत्तर न दें और कोई OTP साझा न करें",
                "इस संदेश को दूसरों को अग्रेषित (forward) न करें",
            ],
            "recovery_steps": [
                "प्रेषक के नंबर/ईमेल पते को ब्लॉक करें",
                "अपने मैसेजिंग ऐप में संदेश को स्पैम/जंक के रूप में चिह्नित करें",
                "यदि संदेश किसी संगठन से होने का दावा करता है, तो उनकी आधिकारिक वेबसाइट या हेल्पलाइन से पुष्टि करें",
            ],
            "reporting_info": [
                "cybercrime.gov.in पर रिपोर्ट करें (राष्ट्रीय साइबर अपराध रिपोर्टिंग पोर्टल)",
                "1930 पर कॉल करें (राष्ट्रीय साइबर अपराध हेल्पलाइन)",
                "DoT चक्षु पोर्टल (sancharsaathi.gov.in/sfc) पर धोखाधड़ी SMS अग्रेषित करें",
                "1909 पर स्पैम SMS अग्रेषित करें (TRAI DND सेवा)",
            ],
        },
        UserState.CLICKED: {
            "urgency": "urgent",
            "immediate_actions": [
                "वेबसाइट/पेज को तुरंत बंद करें",
                "पेज पर कोई भी जानकारी, पासवर्ड या OTP दर्ज न करें",
                "उस साइट के लिए अपने ब्राउज़र का इतिहास, कैश और कुकीज़ साफ़ करें",
                "यदि मोबाइल पर हैं, तो सभी ब्राउज़र टैब बंद करें और हाल ही में डाउनलोड की गई फ़ाइलों की जांच करें",
            ],
            "recovery_steps": [
                "विश्वसनीय एंटीवायरस टूल से अपने डिवाइस को स्कैन करें",
                "जांचें कि क्या कोई अज्ञात ऐप या APK इंस्टॉल हुआ है — उसे तुरंत हटाएं",
                "असामान्य गतिविधि के लिए अगले 48 घंटों तक अपने खातों पर नज़र रखें",
                "महत्वपूर्ण खातों पर टू-फैक्टर ऑथेंटिकेशन (2FA) सक्षम करें",
                "उस डिवाइस से हाल ही में एक्सेस किए गए खातों के पासवर्ड बदलें",
            ],
            "reporting_info": [
                "cybercrime.gov.in पर क्लिक किए गए लिंक के विवरण और स्क्रीनशॉट के साथ रिपोर्ट करें",
                "1930 पर कॉल करें (राष्ट्रीय साइबर अपराध हेल्पलाइन)",
                "Google Safe Browsing पर दुर्भावनापूर्ण URL की रिपोर्ट करें: safebrowsing.google.com/safebrowsing/report_phish/",
                "DoT चक्षु पोर्टल पर रिपोर्ट करें: sancharsaathi.gov.in/sfc",
            ],
        },
        UserState.ENTERED_CREDENTIALS: {
            "urgency": "critical",
            "immediate_actions": [
                "प्रभावित खाते का पासवर्ड तुरंत बदलें",
                "समान पासवर्ड साझा करने वाले अन्य सभी खातों के पासवर्ड तुरंत बदलें",
                "नेटबैंकिंग लॉक करने या कार्ड ब्लॉक करने के लिए अपने बैंक की हेल्पलाइन से तुरंत संपर्क करें",
                "ऑनलाइन लेनदेन और UPI एक्सेस को अस्थायी रूप से रोकने के लिए बैंक से अनुरोध करें",
                "टू-फैक्टर ऑथेंटिकेशन सक्षम करें (SMS के बजाय प्रमाणक ऐप को प्राथमिकता दें)",
            ],
            "recovery_steps": [
                "सभी डिवाइसों से प्रभावित खातों के सक्रिय सत्रों (sessions) से लॉग आउट करें",
                "हाल की खाता गतिविधि की समीक्षा करें",
                "जांचें कि क्या ईमेल अग्रेषण नियम या रिकवरी नंबर बदले गए हैं",
                "सभी लिंक किए गए खातों पर तत्काल लेनदेन अलर्ट सेट करें",
                "अनधिकृत पूछताछ के लिए बैंक विवरण की निगरानी करें",
                "यदि आधार/पैन साझा किया गया था तो क्रेडिट लॉक पर विचार करें",
            ],
            "reporting_info": [
                "cybercrime.gov.in पर तुरंत शिकायत दर्ज करें",
                "1930 पर कॉल करें (राष्ट्रीय साइबर अपराध हेल्पलाइन — 24/7 उपलब्ध)",
                "अपने बैंक के धोखाधड़ी रोकथाम विभाग से संपर्क करें",
                "स्थानीय साइबर पुलिस स्टेशन में शिकायत दर्ज करें",
                "सभी साक्ष्य (संदेश, स्क्रीनशॉट, URL, कॉल लॉग) सुरक्षित रखें",
            ],
        },
        UserState.PAID: {
            "urgency": "critical",
            "immediate_actions": [
                "अनधिकृत डेबिट की रिपोर्ट करने और लेनदेन को उलटने के लिए तुरंत अपने बैंक से संपर्क करें",
                "तुरंत 1930 पर कॉल करें — I4C के माध्यम से बैंक फंड फ्रीज करने के लिए पहला 'गोल्डन ऑवर' महत्वपूर्ण है",
                "आगे के डेबिट को रोकने के लिए अपने बैंक से खाता/UPI ID फ्रीज करने का अनुरोध करें",
                "यदि UPI से भुगतान किया है, तो UPI ऐप में 'Report Dispute' के तहत तुरंत लेनदेन की रिपोर्ट करें",
                "स्कैमर द्वारा रिफंड का वादा किए जाने पर भी कोई अतिरिक्त भुगतान न करें",
            ],
            "recovery_steps": [
                "UTR नंबर, ट्रांजेक्शन आईडी और बैंक स्टेटमेंट के साथ cybercrime.gov.in पर रिपोर्ट दर्ज करें",
                "सभी एकत्रित साक्ष्यों के साथ निकटतम साइबर पुलिस स्टेशन में प्राथमिकी (FIR) दर्ज करें",
                "साक्ष्य एकत्र करें: UTR संदर्भ, स्क्रीनशॉट, कॉल लॉग, संदेश रिकॉर्ड",
                "सभी बैंकिंग पिन, नेटबैंकिंग पासवर्ड और UPI पिन बदलें",
                "यदि बैंक सहायता नहीं करता है तो RBI बैंकिंग लोकपाल (cms.rbi.org.in) से संपर्क करें",
                "अतिरिक्त अनधिकृत लेनदेन के लिए सभी लिंक किए गए खातों की निगरानी करें",
            ],
            "reporting_info": [
                "1930 पर कॉल करें — राष्ट्रीय साइबर अपराध हेल्पलाइन (24/7, गोल्डन ऑवर फंड फ्रीज के लिए)",
                "cybercrime.gov.in पर शिकायत दर्ज करें (नागरिक वित्तीय साइबर धोखाधड़ी रिपोर्टिंग प्रणाली)",
                "UPI ट्रांसफर होने पर NPCI (npci.org.in) के साथ विवाद दर्ज करें",
                "अपने बैंक के फ्रॉड रिस्पॉन्स डेस्क से संपर्क करें और पावती नंबर नोट करें",
                "24-48 घंटों के भीतर अपनी शिकायत पर अनुवर्ती कार्रवाई करें",
            ],
        },
    },
    "gu": {
        UserState.RECEIVED: {
            "urgency": "normal",
            "immediate_actions": [
                "આ સંદેશમાં આપેલી કોઈપણ લિંક પર ક્લિક કરશો નહીં",
                "ઉલ્લેખિત કોઈપણ ફોન નંબર પર કૉલ કરશો નહીં",
                "મોકલનારને જવાબ આપશો નહીં અથવા OTP શેર કરશો નહીં",
                "આ સંદેશ અન્ય લોકોને ફોરવર્ડ કરશો નહીં",
            ],
            "recovery_steps": [
                "મોકલનારના નંબર/ઇમેઇલ એડ્રેસને બ્લોક કરો",
                "તમારી મેસેજિંગ એપ્લિકેશનમાં સંદેશને સ્પામ/જંક તરીકે ચિહ્નિત કરો",
                "જો સંદેશ કોઈ જાણીતી સંસ્થાનો હોવાનો દાવો કરે, તો તેમની સત્તાવાર વેબસાઇટ અથવા હેલ્પલાઇન દ્વારા ચકાસો",
            ],
            "reporting_info": [
                "cybercrime.gov.in પર રિપોર્ટ કરો (નેશનલ સાયબર ક્રાઈમ રિપોર્ટિંગ પોર્ટલ)",
                "1930 પર કૉલ કરો (નેશનલ સાયબર ક્રાઈમ હેલ્પલાઇન)",
                "DoT ચક્ષુ પોર્ટલ (sancharsaathi.gov.in/sfc) પર છેતરપિંડી SMS ફોરવર્ડ કરો",
                "1909 પર સ્પામ SMS ફોરવર્ડ કરો (TRAI DND સેવા)",
            ],
        },
        UserState.CLICKED: {
            "urgency": "urgent",
            "immediate_actions": [
                "વેબસાઇટ/પેજ તાત્કાલિક બંધ કરો",
                "પેજ પર કોઈપણ માહિતી, પાસવર્ડ અથવા OTP દાખલ કરશો નહીં",
                "તે સાઇટ માટે તમારા બ્રાઉઝરનો ઇતિહાસ, કેશ અને કૂકીઝ સાફ કરો",
                "જો મોબાઇલ પર હોય, તો તમામ બ્રાઉઝર ટૅબ બંધ કરો અને તાજેતરના ડાઉનલોડ તપાસો",
            ],
            "recovery_steps": [
                "વિશ્વસનીય એન્ટિવાયરસ ટૂલ વડે તમારા ઉપકરણને સ્કેન કરો",
                "તપાસો કે કોઈ અજાણી એપ્લિકેશન અથવા APK ઇન્સ્ટોલ થઈ છે કે નહીં — તેને તરત જ દૂર કરો",
                "અસામાન્ય પ્રવૃત્તિ માટે આગામી 48 કલાક સુધી તમારા એકાઉન્ટ્સ પર નજર રાખો",
                "મહત્વપૂર્ણ એકાઉન્ટ્સ પર ટૂ-ફેક્ટર ઓથેન્ટિકેશન (2FA) સક્ષમ કરો",
                "તે ઉપકરણમાંથી તાજેતરમાં ઍક્સેસ કરેલા એકાઉન્ટ્સના પાસવર્ડ બદલો",
            ],
            "reporting_info": [
                "cybercrime.gov.in પર ક્લિક કરેલ લિંકની વિગતો અને સ્ક્રીનશૉટ સાથે રિપોર્ટ કરો",
                "1930 પર કૉલ કરો (નેશનલ સાયબર ક્રાઈમ હેલ્પલાઇન)",
                "Google Safe Browsing પર દૂષિત URL નો રિપોર્ટ કરો: safebrowsing.google.com/safebrowsing/report_phish/",
                "DoT ચક્ષુ પોર્ટલ પર છેતરપિંડીની જાણ કરો: sancharsaathi.gov.in/sfc",
            ],
        },
        UserState.ENTERED_CREDENTIALS: {
            "urgency": "critical",
            "immediate_actions": [
                "અસરગ્રસ્ત એકાઉન્ટનો પાસવર્ડ તરત જ બદલો",
                "સમાન પાસવર્ડ ધરાવતા અન્ય તમામ એકાઉન્ટ્સના પાસવર્ડ તાત્કાલિક બદલો",
                "નેટબેંકિંગ લૉક કરવા અથવા કાર્ડ બ્લૉક કરવા માટે તમારી બેંકની હેલ્પલાઇનનો તાત્કાલિક સંપર્ક કરો",
                "ઓનલાઇન વ્યવહારો અને UPI ઍક્સેસને અસ્થાયી રૂપે ફ્રીઝ કરવા માટે બેંકને વિનંતી કરો",
                "ટૂ-ફેક્ટર ઓથેન્ટિકેશન સક્ષમ કરો",
            ],
            "recovery_steps": [
                "બધા ઉપકરણોમાંથી અસરગ્રસ્ત એકાઉન્ટ્સના સક્રિય સત્રોમાંથી લૉગ આઉટ કરો",
                "તાજેતરની એકાઉન્ટ પ્રવૃત્તિની સમીક્ષા કરો",
                "તપાસો કે ઇમેઇલ ફોરવર્ડિંગ નિયમો અથવા પુનઃપ્રાપ્તિ નંબરો બદલાયા છે કે નહીં",
                "બધા લિંક કરેલા એકાઉન્ટ્સ પર ત્વરિત વ્યવહાર ચેતવણીઓ સેટ કરો",
                "અનધિકૃત વ્યવહારો માટે બેંક સ્ટેટમેન્ટ તપાસો",
                "જો આધાર/પાન શેર કરવામાં આવ્યું હોય તો સાવચેત રહો",
            ],
            "reporting_info": [
                "cybercrime.gov.in પર તાત્કાલિક ફરિયાદ નોંધાવો",
                "1930 પર કૉલ કરો (નેશનલ સાયબર ક્રાઈમ હેલ્પલાઇન — 24/7 ઉપલબ્ધ)",
                "તમારી બેંકના ફ્રોડ નિવારણ વિભાગનો સંપર્ક કરો",
                "સ્થાનિક સાયબર પોલીસ સ્ટેશનમાં ફરિયાદ નોંધાવો",
                "તમામ પુરાવા (સંદેશા, સ્ક્રીનશૉટ્સ, URL, કૉલ લૉગ્સ) સાચવો",
            ],
        },
        UserState.PAID: {
            "urgency": "critical",
            "immediate_actions": [
                "અનધિકૃત ડેબિટની જાણ કરવા અને ટ્રાન્ઝેક્શન રિવર્સલની વિનંતી કરવા તાત્કાલિક તમારી બેંકનો સંપર્ક કરો",
                "તરત જ 1930 પર કૉલ કરો — I4C દ્વારા બેંક ફંડ ફ્રીઝ કરવા માટે પ્રથમ 'ગોલ્ડન અવર' અત્યંત મહત્વપૂર્ણ છે",
                "વધુ ડેબિટ અટકાવવા માટે તમારું ખાતું / UPI ID ફ્રીઝ કરવા માટે તમારી બેંકને વિનંતી કરો",
                "જો UPI દ્વારા ચૂકવણી કરી હોય, તો UPI એપમાં 'Report Dispute' હેઠળ તરત જ રિપોર્ટ કરો",
                "સ્કેમર રિફંડનું વચન આપે તો પણ કોઈ વધારાની ચૂકવણી કરશો નહીં",
            ],
            "recovery_steps": [
                "UTR નંબર, ટ્રાન્ઝેક્શન આઈડી અને બેંક સ્ટેટમેન્ટ સાથે cybercrime.gov.in પર રિપોર્ટ નોંધાવો",
                "બધા એકત્રિત પુરાવા સાથે નજીકના સાયબર પોલીસ સ્ટેશનમાં FIR નોંધાવો",
                "પુરાવા એકત્રિત કરો: UTR સંદર્ભ, સ્ક્રીનશૉટ્સ, કૉલ લૉગ્સ, સંદેશ રેકોર્ડ્સ",
                "તમામ બેંકિંગ પિન, નેટબેંકિંગ પાસવર્ડ અને UPI પિન બદલો",
                "જો બેંક સમયસર સહાય ન કરે તો RBI બેંકિંગ ઓમ્બડ્સમેન (cms.rbi.org.in) નો સંપર્ક કરો",
                "વધારાના અનધિકૃત વ્યવહારો માટે બધા લિંક કરેલા એકાઉન્ટ્સ પર નજર રાખો",
            ],
            "reporting_info": [
                "1930 પર કૉલ કરો — નેશનલ સાયબર ક્રાઈમ હેલ્પલાઇન (24/7, ગોલ્ડન અવર ફંડ ફ્રીઝિંગ માટે)",
                "cybercrime.gov.in પર ફરિયાદ નોંધાવો (સિટીઝન ફાઇનાન્શિયલ સાયબર ફ્રોડ રિપોર્ટિંગ સિસ્ટમ)",
                "જો UPI ટ્રાન્સફર હોય તો NPCI (npci.org.in) સાથે વિવાદ ઉઠાવો",
                "તમારી બેંકના ફ્રોડ રિસ્પોન્સ ડેસ્કનો સંપર્ક કરો અને ફરિયાદ સ્વીકૃતિ નંબર નોંધો",
                "24-48 કલાકની અંદર તમારી ફરિયાદ પર ફોલો-અપ લો",
            ],
        },
    },
    "ta": {
        UserState.RECEIVED: {
            "urgency": "normal",
            "immediate_actions": [
                "இந்தச் செய்தியில் உள்ள எந்த இணைப்புகளையும் கிளிக் செய்ய வேண்டாம்",
                "குறிப்பிடப்பட்டுள்ள எந்த தொலைபேசி எண்ணுக்கும் அழைக்க வேண்டாம்",
                "அனுப்புநருக்கு பதிலளிக்க வேண்டாம் அல்லது OTP-ஐ பகிர வேண்டாம்",
                "இந்தச் செய்தியை மற்றவர்களுக்கு அனுப்ப வேண்டாம்",
            ],
            "recovery_steps": [
                "அனுப்புநரின் எண்/மின்னஞ்சல் முகவரியைத் தடுக்கவும்",
                "செய்தியிடல் பயன்பாட்டில் செய்தியை ஸ்பேம் என குறிக்கவும்",
                "செய்தி தெரிந்த நிறுவனத்திடமிருந்து வந்ததாகக் கூறினால், அவர்களின் அதிகாரப்பூர்வ இணையதளம் மூலம் சரிபார்க்கவும்",
            ],
            "reporting_info": [
                "cybercrime.gov.in இல் புகாரளிக்கவும் (தேசிய இணையக் குற்றப் புகாரளிப்பு தளம்)",
                "1930 ஐ அழைக்கவும் (தேசிய இணையக் குற்ற உதவி எண்)",
                "DoT சக்ஷு தளத்தில் (sancharsaathi.gov.in/sfc) மோசடி SMS-ஐ அனுப்பவும்",
                "1909 க்கு ஸ்பேம் SMS-ஐ அனுப்பவும் (TRAI DND சேவை)",
            ],
        },
        UserState.CLICKED: {
            "urgency": "urgent",
            "immediate_actions": [
                "இணையதளத்தை உடனடியாக மூடவும்",
                "பக்கத்தில் எந்த தகவலும், கடவுச்சொல்லும் அல்லது OTP-ஐயும் உள்ளிட வேண்டாம்",
                "உங்கள் உலாவியின் வரலாறு, தற்காலிக சேமிப்பு மற்றும் குக்கீகளை அழிக்கவும்",
                "மொபைலில் இருந்தால், அனைத்து தாவல்களையும் மூடி சமீபத்திய பதிவிறக்கங்களைச் சரிபார்க்கவும்",
            ],
            "recovery_steps": [
                "நம்பகமான வைரஸ் தடுப்பு கருவி மூலம் உங்கள் சாதனத்தை ஸ்கேன் செய்யவும்",
                "தெரியாத செயலிகள் அல்லது APK நிறுவப்பட்டுள்ளதா என சரிபார்த்து உடனே நீக்கவும்",
                "அடுத்த 48 மணி நேரத்திற்கு உங்கள் கணக்குகளைக் கண்காணிக்கவும்",
                "முக்கியமான கணக்குகளில் இரண்டு காரணி அங்கீகாரத்தை (2FA) இயக்கவும்",
                "சமீபத்தில் அணுகிய கணக்குகளின் கடவுச்சொற்களை மாற்றவும்",
            ],
            "reporting_info": [
                "cybercrime.gov.in இல் கிளிக் செய்த இணைப்பின் விவரங்களுடன் புகாரளிக்கவும்",
                "1930 ஐ அழைக்கவும் (தேசிய இணையக் குற்ற உதவி எண்)",
                "Google Safe Browsing இல் தீங்கிழைக்கும் URL ஐப் புகாரளிக்கவும்: safebrowsing.google.com/safebrowsing/report_phish/",
                "DoT சக்ஷு தளத்தில் புகாரளிக்கவும்: sancharsaathi.gov.in/sfc",
            ],
        },
        UserState.ENTERED_CREDENTIALS: {
            "urgency": "critical",
            "immediate_actions": [
                "பாதிக்கப்பட்ட கணக்கின் கடவுச்சொல்லை உடனடியாக மாற்றவும்",
                "அதே கடவுச்சொல்லைப் பகிரும் பிற கணக்குகளின் கடவுச்சொற்களை உடனடியாக மாற்றவும்",
                "நெட்பேங்கிங் பூட்ட அல்லது கார்டுகளைத் தடுக்க உங்கள் வங்கியின் அவசர உதவி எண்ணைத் தொடர்பு கொள்ளவும்",
                "ஆன்லைன் பரிவர்த்தனைகள் மற்றும் UPI அணுகலை தற்காலிகமாக முடக்க வங்கிக்குக் கோரிக்கை விடுக்கவும்",
                "இரண்டு காரணி அங்கீகாரத்தை இயக்கவும்",
            ],
            "recovery_steps": [
                "அனைத்து சாதனங்களிலிருந்தும் பாதிக்கப்பட்ட கணக்குகளிலிருந்து வெளியேறவும்",
                "சமீபத்திய கணக்கு செயல்பாட்டை மதிப்பாய்வு செய்யவும்",
                "மின்னஞ்சல் பகிர்தல் விதிகள் மாற்றப்பட்டுள்ளதா என சரிபார்க்கவும்",
                "அனைத்து இணைக்கப்பட்ட கணக்குகளிலும் உடனடி பரிவர்த்தனை விழிப்பூட்டல்களை அமைக்கவும்",
                "அங்கீகரிக்கப்படாத பரிவர்த்தனைகளுக்கு வங்கி அறிக்கைகளைக் கண்காணிக்கவும்",
            ],
            "reporting_info": [
                "cybercrime.gov.in இல் உடனடியாக புகார் அளிக்கவும்",
                "1930 ஐ அழைக்கவும் (தேசிய இணையக் குற்ற உதவி எண் — 24/7)",
                "உங்கள் வங்கியின் மோசடி தடுப்புத் துறையைத் தொடர்பு கொள்ளவும்",
                "உள்ளூர் சைபர் காவல் நிலையத்தில் புகார் அளிக்கவும்",
                "அனைத்து ஆதாரங்களையும் (செய்திகள், ஸ்கிரீன்ஷாட்கள், URLகள்) பாதுகாக்கவும்",
            ],
        },
        UserState.PAID: {
            "urgency": "critical",
            "immediate_actions": [
                "அங்கீகரிக்கப்படாத டெபிட்டைப் புகாரளிக்கவும் பரிவர்த்தனை ரத்து செய்யக் கோரவும் உடனடியாக உங்கள் வங்கியைத் தொடர்பு கொள்ளவும்",
                "உடனடியாக 1930 ஐ அழைக்கவும் — I4C மூலம் வங்கி நிதியை முடக்க முதல் 'கோல்டன் ஹவர்' மிகவும் முக்கியமானது",
                "மேலும் டெபிட்களைத் தடுக்க உங்கள் கணக்கு / UPI ஐடியை முடக்க உங்கள் வங்கியிடம் கோரவும்",
                "UPI மூலம் பணம் செலுத்தியிருந்தால், UPI செயலியில் 'Report Dispute' இன் கீழ் உடனடியாகப் புகாரளிக்கவும்",
                "மோசடி செய்பவர் பணத்தைத் திருப்பித் தருவதாக உறுதியளித்தாலும் கூடுதல் பணம் செலுத்த வேண்டாம்",
            ],
            "recovery_steps": [
                "UTR எண், பரிவர்த்தனை ஐடி மற்றும் வங்கி அறிக்கைகளுடன் cybercrime.gov.in இல் புகாரளிக்கவும்",
                "அனைத்து ஆதாரங்களுடன் அருகிலுள்ள சைபர் காவல் நிலையத்தில் எஃப்.ஐ.ஆர் பதிவு செய்யவும்",
                "ஆதாரங்களை சேகரிக்கவும்: UTR குறிப்பு, ஸ்கிரீன்ஷாட்கள், அழைப்பு பதிவுகள்",
                "அனைத்து வங்கி பின்கள், நெட்பேங்கிங் கடவுச்சொற்கள் மற்றும் UPI பின்களை மாற்றவும்",
                "வங்கி உதவவில்லை என்றால் RBI வங்கி ஆம்புட்ஸ்மேனை (cms.rbi.org.in) தொடர்பு கொள்ளவும்",
                "கூடுதல் அங்கீகரிக்கப்படாத டெபிட்டுகளுக்கு இணைக்கப்பட்ட அனைத்து கணக்குகளையும் கண்காணிக்கவும்",
            ],
            "reporting_info": [
                "1930 ஐ அழைக்கவும் — தேசிய இணையக் குற்ற உதவி எண் (24/7, கோல்டன் ஹவர் நிதி முடக்கத்திற்கு)",
                "cybercrime.gov.in இல் புகார் அளிக்கவும் (குடிமக்கள் நிதி இணைய மோசடி அறிக்கை அமைப்பு)",
                "UPI பரிமாற்றம் என்றால் NPCI (npci.org.in) உடன் தகராறை எழுப்பவும்",
                "உங்கள் வங்கியின் மோசடி பதிலளிப்பு மையத்தைத் தொடர்பு கொள்ளவும்",
                "24-48 மணி நேரத்திற்குள் உங்கள் புகாரைப் பின்தொடரவும்",
            ],
        },
    },
}

# ─── Proportional Guidance for Low / Unknown Risk (Received State) ───

_LOW_RISK_RECEIVED_GUIDANCE: dict[str, dict] = {
    "en": {
        "urgency": "normal",
        "immediate_actions": [
            "Verify sender details before taking any requested action",
            "If this was an expected message (such as a requested OTP or transaction alert), proceed securely via the official app or website",
            "Do NOT click unverified third-party links or share OTPs with callers",
            "Never share OTPs, PINs, passwords, or CVV numbers with anyone over call or chat",
        ],
        "recovery_steps": [
            "Keep official bank and utility helpline numbers saved from verified official websites",
            "Ensure two-factor authentication is active on your primary accounts",
        ],
        "reporting_info": [
            "If you did not initiate this communication, notify your service provider's verified helpline",
            "Forward unsolicited promotional or spam SMS to 1909 (TRAI DND service)",
        ],
    },
    "hi": {
        "urgency": "normal",
        "immediate_actions": [
            "कोई भी कार्रवाई करने से पहले प्रेषक के विवरण को सत्यापित करें",
            "यदि यह एक अपेक्षित संदेश था (जैसे कि अनुरोधित OTP), तो आधिकारिक ऐप या वेबसाइट के माध्यम से सुरक्षित रूप से आगे बढ़ें",
            "असत्यापित लिंक पर क्लिक न करें या कॉल करने वालों के साथ OTP साझा न करें",
            "कॉल या चैट पर किसी के साथ OTP, PIN, पासवर्ड या CVV साझा न करें",
        ],
        "recovery_steps": [
            "सत्यापित आधिकारिक वेबसाइटों से आधिकारिक बैंक हेल्पलाइन नंबर सहेज कर रखें",
            "सुनिश्चित करें कि आपके प्राथमिक खातों पर टू-फैक्टर ऑथेंटिकेशन सक्रिय है",
        ],
        "reporting_info": [
            "यदि आपने यह संचार शुरू नहीं किया है, तो अपने सेवा प्रदाता की हेल्पलाइन को सूचित करें",
            "1909 पर अवांछित प्रचार SMS अग्रेषित करें (TRAI DND सेवा)",
        ],
    },
    "gu": {
        "urgency": "normal",
        "immediate_actions": [
            "કોઈપણ પગલાં લેતા પહેલા મોકલનારની વિગતો ચકાસો",
            "જો આ અપેક્ષિત સંદેશ હતો (જેમ કે વિનંતી કરેલ OTP), તો સત્તાવાર એપ્લિકેશન અથવા વેબસાઇટ દ્વારા સુરક્ષિત રીતે આગળ વધો",
            "અસત્યાપિત લિંક્સ પર ક્લિક કરશો નહીં અથવા કૉલ કરનારાઓ સાથે OTP શેર કરશો નહીં",
            "કોલ અથવા ચેટ પર ક્યારેય OTP, PIN, પાસવર્ડ અથવા CVV શેર કરશો નહીં",
        ],
        "recovery_steps": [
            "સત્તાવાર વેબસાઇટ્સ પરથી બેંક હેલ્પલાઇન નંબરો સાચવી રાખો",
            "તમારા પ્રાથમિક ખાતાઓ પર ટૂ-ફેક્ટર ઓથેન્ટિકેશન સક્રિય છે તેની ખાતરી કરો",
        ],
        "reporting_info": [
            "જો તમે આ શરૂ ન કર્યું હોય, તો તમારા સેવા પ્રદાતાની હેલ્પલાઇનને જાણ કરો",
            "1909 પર અનિચ્છનીય પ્રમોશનલ SMS ફોરવર્ડ કરો (TRAI DND સેવા)",
        ],
    },
    "ta": {
        "urgency": "normal",
        "immediate_actions": [
            "எந்த நடவடிக்கையும் எடுப்பதற்கு முன் அனுப்புநர் விவரங்களைச் சரிபார்க்கவும்",
            "இது எதிர்பார்க்கப்படும் செய்தியாக இருந்தால் (OTP போன்றவை), அதிகாரப்பூர்வ செயலி அல்லது இணையதளம் வழியாக தொடரவும்",
            "சரிபார்க்கப்படாத இணைப்புகளைக் கிளிக் செய்யாதீர்கள் அல்லது அழைப்பாளர்களுடன் OTP-ஐ பகிராதீர்கள்",
            "அழைப்பு அல்லது அரட்டையில் OTP, PIN, கடவுச்சொல் அல்லது CVV-ஐ யாரிடமும் பகிர வேண்டாம்",
        ],
        "recovery_steps": [
            "அதிகாரப்பூர்வ இணையதளங்களில் இருந்து பெறப்பட்ட உதவி எண்களைச் சேமித்து வைக்கவும்",
            "உங்கள் முதன்மைக் கணக்குகளில் 2FA செயலில் உள்ளதை உறுதிசெய்யவும்",
        ],
        "reporting_info": [
            "இந்தத் தகவல்தொடர்பை நீங்கள் தொடங்கவில்லை என்றால், சேவை வழங்குநரின் உதவி மையத்திற்குத் தெரிவிக்கவும்",
            "1909 க்கு ஸ்பேம் SMS-ஐ அனுப்பவும் (TRAI DND சேவை)",
        ],
    },
}

_UNKNOWN_RISK_RECEIVED_GUIDANCE: dict[str, dict] = {
    "en": {
        "urgency": "normal",
        "immediate_actions": [
            "Do NOT click any links in this unverified message",
            "Do NOT share OTPs, passwords, or personal identity details",
            "Treat unsolicited or ambiguous messages with standard caution",
            "Avoid downloading any unverified attachments or apps",
        ],
        "recovery_steps": [
            "If the message claims to represent an organization, contact them directly through their verified official website",
            "Do not rely on contact numbers or links provided within an unverified message",
        ],
        "reporting_info": [
            "Forward unsolicited promotional SMS to 1909 (TRAI DND)",
            "For suspected cyber fraud, report to cybercrime.gov.in or helpline 1930",
        ],
    },
    "hi": {
        "urgency": "normal",
        "immediate_actions": [
            "इस असत्यापित संदेश में किसी भी लिंक पर क्लिक न करें",
            "OTP, पासवर्ड या व्यक्तिगत पहचान विवरण साझा न करें",
            "अवांछित या अस्पष्ट संदेशों के प्रति सामान्य सावधानी बरतें",
            "किसी भी असत्यापित अटैचमेंट या ऐप को डाउनलोड करने से बचें",
        ],
        "recovery_steps": [
            "यदि संदेश किसी संगठन का प्रतिनिधित्व करने का दावा करता है, तो उनकी आधिकारिक वेबसाइट के माध्यम से संपर्क करें",
            "असत्यापित संदेश में दिए गए संपर्क नंबरों या लिंक पर भरोसा न करें",
        ],
        "reporting_info": [
            "1909 पर अवांछित प्रचार SMS अग्रेषित करें (TRAI DND)",
            "संदिग्ध साइबर धोखाधड़ी के लिए cybercrime.gov.in या हेल्पलाइन 1930 पर रिपोर्ट करें",
        ],
    },
    "gu": {
        "urgency": "normal",
        "immediate_actions": [
            "આ અસત્યાપિત સંદેશમાંની કોઈપણ લિંક પર ક્લિક કરશો નહીં",
            "OTP, પાસવર્ડ અથવા વ્યક્તિગત ઓળખ વિગતો શેર કરશો નહીં",
            "અનિચ્છનીય સંદેશાઓ સાથે પ્રમાણભૂત સાવચેતી રાખો",
            "કોઈપણ અસત્યાપિત ફાઇલ અથવા એપ્લિકેશન ડાઉનલોડ કરવાનું ટાળો",
        ],
        "recovery_steps": [
            "જો સંદેશ કોઈ સંસ્થાનો હોવાનો દાવો કરે, તો તેમની સત્તાવાર વેબસાઇટ દ્વારા સીધો સંપર્ક કરો",
            "અસત્યાપિત સંદેશમાં આપેલા સંપર્ક નંબરો અથવા લિંક્સ પર આધાર રાખશો નહીં",
        ],
        "reporting_info": [
            "1909 પર અનિચ્છનીય પ્રમોશનલ SMS ફોરવર્ડ કરો (TRAI DND)",
            "શંકાસ્પદ સાયબર છેતરપિંડી માટે cybercrime.gov.in અથવા હેલ્પલાઇન 1930 પર જાણ કરો",
        ],
    },
    "ta": {
        "urgency": "normal",
        "immediate_actions": [
            "இந்தச் சரிபார்க்கப்படாத செய்தியில் உள்ள இணைப்புகளைக் கிளிக் செய்ய வேண்டாம்",
            "OTP, கடவுச்சொற்கள் அல்லது தனிப்பட்ட அடையாள விவரங்களைப் பகிர வேண்டாம்",
            "தெரியாத செய்திகளை எச்சரிக்கையுடன் கையாளவும்",
            "சரிபார்க்கப்படாத இணைப்புகள் அல்லது பயன்பாடுகளைப் பதிவிறக்குவதைத் தவிர்க்கவும்",
        ],
        "recovery_steps": [
            "செய்தி ஒரு நிறுவனத்தைப் பிரதிநிதித்துவப்படுத்துவதாகக் கூறினால், அவர்களின் அதிகாரப்பூர்வ தளம் மூலம் தொடர்பு கொள்ளவும்",
            "செய்தியில் கொடுக்கப்பட்டுள்ள தொடர்பு எண்களையோ இணைப்புகளையோ நம்ப வேண்டாம்",
        ],
        "reporting_info": [
            "1909 க்கு தேவையற்ற விளம்பர SMS-ஐ அனுப்பவும் (TRAI DND)",
            "சந்தேகத்திற்கிடமான சைபர் மோசடிக்கு cybercrime.gov.in அல்லது உதவி எண் 1930 இல் புகாரளிக்கவும்",
        ],
    },
}


def generate_response(evidence: IncidentEvidence, user_state: UserState) -> IncidentEvidence:
    """
    Generate adaptive response based on user's interaction state and chosen response language.
    Enforces epistemic proportionality and context-aware enrichment.
    """
    risk_level = evidence.risk.level
    lang = getattr(evidence, "response_language", None) or getattr(evidence, "language", "en")
    if lang not in _DEFAULT_RESPONSES:
        lang = "en"

    # 1. Base template selection
    if user_state == UserState.RECEIVED:
        if risk_level == RiskLevel.LOW:
            base = _LOW_RISK_RECEIVED_GUIDANCE.get(lang, _LOW_RISK_RECEIVED_GUIDANCE["en"])
        elif risk_level == RiskLevel.UNKNOWN:
            base = _UNKNOWN_RISK_RECEIVED_GUIDANCE.get(lang, _UNKNOWN_RISK_RECEIVED_GUIDANCE["en"])
        else:
            lang_responses = _DEFAULT_RESPONSES.get(lang, _DEFAULT_RESPONSES["en"])
            base = lang_responses[UserState.RECEIVED]
    else:
        # In escalated interaction states (CLICKED, ENTERED_CREDENTIALS, PAID),
        # use the escalated response protocols regardless of initial message risk score.
        lang_responses = _DEFAULT_RESPONSES.get(lang, _DEFAULT_RESPONSES["en"])
        base = lang_responses.get(user_state, lang_responses[UserState.RECEIVED])

    immediate_actions = list(base["immediate_actions"])
    recovery_steps = list(base["recovery_steps"])
    reporting_info = list(base["reporting_info"])
    urgency = base["urgency"]

    # 2. Urgency adjustment based on risk and state
    if risk_level == RiskLevel.CRITICAL:
        if user_state == UserState.RECEIVED:
            urgency = "urgent"
        else:
            urgency = "critical"
    elif risk_level == RiskLevel.HIGH and user_state in (UserState.ENTERED_CREDENTIALS, UserState.PAID):
        urgency = "critical"

    # 3. Contextual Enrichment
    # Brand impersonation enrichment
    if evidence.brands:
        primary_brand = evidence.brands[0]
        if primary_brand.legitimate_domain:
            if lang == "hi":
                recovery_steps.append(
                    f"आधिकारिक {primary_brand.brand_name} चैनल: केवल https://{primary_brand.legitimate_domain} पर जाएं या उनके आधिकारिक मोबाइल ऐप का उपयोग करें"
                )
            elif lang == "gu":
                recovery_steps.append(
                    f"સત્તાવાર {primary_brand.brand_name} ચેનલ: માત્ર https://{primary_brand.legitimate_domain} ની મુલાકાત લો અથવા તેમની સત્તાવાર મોબાઇલ એપ્લિકેશનનો ઉપયોગ કરો"
                )
            elif lang == "ta":
                recovery_steps.append(
                    f"அதிகாரப்பூர்வ {primary_brand.brand_name} தளம்: https://{primary_brand.legitimate_domain} ஐ மட்டும் பார்வையிடவும் அல்லது அவர்களின் அதிகாரப்பூர்வ செயலியைப் பயன்படுத்தவும்"
                )
            else:
                recovery_steps.append(
                    f"Official {primary_brand.brand_name} channel: Visit only https://{primary_brand.legitimate_domain} or use their official mobile app"
                )

    # UPI fraud enrichment
    category = (evidence.fraud_category or "").lower()
    has_upi = category == "upi" or any("upi" in item.description.lower() for item in evidence.evidence) or any("upi" in str(ioc).lower() or "@" in str(ioc) for ioc in evidence.iocs)
    if has_upi and user_state in (UserState.CLICKED, UserState.ENTERED_CREDENTIALS, UserState.PAID):
        if lang == "hi":
            reporting_info.append(
                "UPI विवाद: अपने UPI ऐप (Google Pay, PhonePe, Paytm, BHIM) में लेनदेन इतिहास पर जाएं और 'Raise Dispute / Report Problem' चुनें"
            )
        elif lang == "gu":
            reporting_info.append(
                "UPI વિવાદ: તમારી UPI એપ્લિકેશનમાં (Google Pay, PhonePe, Paytm, BHIM) ટ્રાન્ઝેક્શન ઇતિહાસ પર જાઓ અને 'Raise Dispute / Report Problem' પસંદ કરો"
            )
        elif lang == "ta":
            reporting_info.append(
                "UPI சர்ச்சை: உங்கள் UPI செயலியில் (Google Pay, PhonePe, Paytm, BHIM) பரிவர்த்தனை வரலாற்றுக்குச் சென்று 'Raise Dispute / Report Problem' என்பதைத் தேர்ந்தெடுக்கவும்"
            )
        else:
            reporting_info.append(
                "UPI Dispute: In your UPI app (Google Pay, PhonePe, Paytm, BHIM), navigate to transaction history and select 'Raise Dispute / Report Problem'"
            )

    # Typology-specific advisories
    if category in ("electricity", "electricity_bill") and user_state == UserState.RECEIVED:
        if lang == "hi":
            immediate_actions.append(
                "बिजली काटने के नोटिस कभी भी व्यक्तिगत मोबाइल नंबरों से जारी नहीं किए जाते हैं; केवल अपने राज्य बिजली पोर्टल पर ही बकाया राशि की जांच करें"
            )
        elif lang == "gu":
            immediate_actions.append(
                "વીજળી કનેક્શન કાપવાની નોટિસ ક્યારેય વ્યક્તિગત મોબાઇલ નંબર પરથી જારી કરવામાં આવતી નથી; માત્ર તમારા રાજ્યના પાવર યુટિલિટી પોર્ટલ પર બાકી રકમ તપાસો"
            )
        elif lang == "ta":
            immediate_actions.append(
                "மின்சார துண்டிப்பு அறிவிப்புகள் தனிப்பட்ட மொபைல் எண்களிலிருந்து வழங்கப்படுவதில்லை; உங்கள் மாநில மின்சார வாரிய போர்ட்டலில் மட்டுமே நிலுவைத் தொகையை சரிபார்க்கவும்"
            )
        else:
            immediate_actions.append(
                "Electricity disconnection notices are never issued via individual mobile numbers; check dues only on your state power utility portal"
            )
    elif category == "courier" and user_state == UserState.RECEIVED:
        if lang == "hi":
            immediate_actions.append(
                "वैध डाक/कूरियर सेवाओं को पार्सल जारी करने के लिए SMS लिंक के माध्यम से छोटे शुल्क के भुगतान की आवश्यकता नहीं होती है"
            )
        elif lang == "gu":
            immediate_actions.append(
                "કાયદેસર કુરિયર સેવાઓ પેકેજ આપવા માટે SMS લિંક્સ દ્વારા નાની ફી ચૂકવવાની જરૂર રાખતી નથી"
            )
        elif lang == "ta":
            immediate_actions.append(
                "சட்டபூர்வமான கூரியர் சேவைகள் பேக்கேஜ்களை வழங்க SMS இணைப்புகள் மூலம் சிறிய கட்டணங்களைச் செலுத்தக் கோருவதில்லை"
            )
        else:
            immediate_actions.append(
                "Legitimate postal/courier services do not require small fee payments via SMS links to release packages"
            )
    elif category in ("upi", "upi_fraud") and user_state == UserState.RECEIVED:
        if lang == "hi":
            immediate_actions.append(
                "पैसे प्राप्त करने के लिए कभी भी अपना UPI PIN दर्ज न करें या कलेक्ट अनुरोध को स्वीकार न करें; UPI पर पैसे प्राप्त करने के लिए कभी भी PIN की आवश्यकता नहीं होती है"
            )
        elif lang == "gu":
            immediate_actions.append(
                "પૈસા મેળવવા માટે ક્યારેય તમારો UPI PIN દાખલ કરશો નહીં અથવા કલેક્ટ વિનંતીઓ મંજૂર કરશો નહીં; UPI પર પૈસા મેળવવા માટે ક્યારેય PIN ની જરૂર હોતી નથી"
            )
        elif lang == "ta":
            immediate_actions.append(
                "பணத்தைப் பெற உங்கள் UPI PIN-ஐ உள்ளிடவோ அல்லது கோரிக்கைகளை அங்கீகரிக்கவோ வேண்டாம்; UPI-ல் பணத்தைப் பெற எப்போதும் PIN தேவைப்படாது"
            )
        else:
            immediate_actions.append(
                "Never enter your UPI PIN or approve collect requests to receive refunds or payments; receiving money on UPI never requires entering a PIN"
            )

    evidence.response = AdaptiveResponse(
        user_state=user_state,
        immediate_actions=immediate_actions,
        recovery_steps=recovery_steps,
        reporting_info=reporting_info,
        urgency=urgency,
    )

    return evidence
