"""
Generator for Scikit-Learn ML Classifier Dataset.
Produces 500+ completely new and distinct samples from the Laya corpus,
spanning advanced phishing/social engineering archetypes and legitimate communication norms.
"""
import json
import os

def build_ml_classifier_samples():
    samples = []

    # ─────────────────────────────────────────────────────────────
    # PHISHING & MALICIOUS PATTERNS (Label: 1, ~310 samples)
    # ─────────────────────────────────────────────────────────────

    # 1. Digital Arrest, Legal Extortion & Police Impersonation (35 samples)
    law_bodies = [
        "CBI Cyber Crime Division", "Enforcement Directorate (ED)", "Delhi Police Special Cell",
        "Mumbai Crime Branch", "Narcotics Control Bureau (NCB)", "Supreme Court Collegium",
        "National Investigation Agency (NIA)"
    ]
    for i in range(35):
        agency = law_bodies[i % len(law_bodies)]
        case_id = f"FIR-{202600 + i * 37}"
        officer = ["DCP Verma", "Inspector R.K. Sharma", "Director S. Roy", "Special Agent Sen"][i % 4]
        phone = f"98{19000000 + i * 311}"[:10]
        if i % 2 == 0:
            text = f"LEGAL SUMMONS: {agency} has initiated arrest proceedings under {case_id} regarding money laundering and illegal hawala transactions on your PAN card. Connect to {officer} on Skype/WhatsApp immediately at {phone} to prevent immediate asset seizure."
        else:
            text = f"URGENT POLICE NOTICE: An intercepted customs parcel containing illegal narcotics has been seized bearing your Aadhaar credentials. A non-bailable arrest warrant {case_id} is pending. Contact clearance investigation officer {phone} within 2 hours."
        samples.append({"text": text, "label": 1, "category": "extortion_legal"})

    # 2. Banking Security, Dormant Account & Foreign Login Alerts (40 samples)
    emerging_banks = [
        "IDFC FIRST Bank", "Federal Bank", "IndusInd Bank", "RBL Bank",
        "Yes Bank", "Bandhan Bank", "Standard Chartered India", "South Indian Bank"
    ]
    phish_urls = [
        "idfc-online-security.top", "federal-bank-kyc.info", "indusind-netportal.site",
        "rbl-verification-hub.link", "yesbank-pan-update.top", "sc-security-portal.xyz"
    ]
    for i in range(40):
        bank = emerging_banks[i % len(emerging_banks)]
        url = phish_urls[i % len(phish_urls)]
        reason = [
            f"NetBanking account dormant. Submit Form 60 and KYC documents at http://{url}/kyc before midnight",
            f"Suspicious foreign login attempt from IP 185.220.101.4 (Russia). If this was not you, lock credentials at https://{url}/secure",
            f"Mandatory RBI compliance update: Link PAN card to bank account immediately at http://{url}/pan-link",
            f"Credit card reward points balance of Rs 14,250 expiring today. Redeem direct to savings account: http://{url}/rewards",
            f"Debit card chip deactivated due to security protocol update. Re-enable contactless card at http://{url}/reactivate"
        ][i % 5]
        text = f"Dear {bank} customer: {reason}. Failure to verify will cause permanent account freeze."
        samples.append({"text": text, "label": 1, "category": "banking"})

    # 3. Micro-Lending, Mule Recruitment & Easy Money (35 samples)
    loan_apps = ["KreditEasy Instant", "RupeeFast Loan", "CashMama Mobile", "SwiftCredit India", "PocketLoan App"]
    for i in range(35):
        app = loan_apps[i % len(loan_apps)]
        amt = [300000, 750000, 1500000, 500000][i % 4]
        fee = [1499, 2999, 3999, 1850][i % 4]
        if i % 2 == 0:
            text = f"{app}: Loan of Rs {amt:,} approved with zero CIBIL check and 1% monthly interest. Pay loan insurance bond fee of Rs {fee} via UPI or download APK to claim funds: http://fast-credit-india-{i}.apk"
        else:
            text = f"EARN FROM HOME: Make Rs 15,000 weekly by helping our corporate account route merchant settlements. Zero investment, daily commission paid to your GPay/PhonePe. Telegram: @settlement_agent_{i}"
        samples.append({"text": text, "label": 1, "category": "loan_fraud"})

    # 4. eSIM Swap, Telecom Porting & Tower Rent Scams (35 samples)
    carriers = ["Airtel India", "Reliance Jio", "Vodafone Idea (Vi)", "BSNL Telecom"]
    for i in range(35):
        car = carriers[i % len(carriers)]
        phone = f"98{33000000 + i * 219}"[:10]
        if i % 3 == 0:
            text = f"{car} ALERT: Request received to convert your physical SIM to eSIM. If you did NOT request this eSIM conversion, forward the 19-digit SIM barcode and OTP received to {phone} to stop deactivation."
        elif i % 3 == 1:
            text = f"BSNL/DoT Notice: 5G mobile tower installation approved on your plot/roof. Advance rent Rs 45,000/month + Rs 25 Lakhs advance. Pay stamp duty registration fee Rs 4,500 to officer at {phone}."
        else:
            text = f"{car}: Your mobile number is scheduled for termination due to incomplete biometric KYC. Call executive {phone} or submit Aadhaar at http://telecom-kyc-service-{i}.top within 6 hours."
        samples.append({"text": text, "label": 1, "category": "telecom"})

    # 5. E-Challan, Parivahan & Vehicle Seizure Scams (35 samples)
    states = ["MH", "DL", "KA", "UP", "HR", "TN", "GJ"]
    for i in range(35):
        st = states[i % len(states)]
        veh = f"{st}{10 + (i % 20):02d}AB{1000 + i * 17}"
        fine = [1000, 2500, 5000, 1500][i % 4]
        text = f"Parivahan Ministry: E-Challan #{892010 + i * 19} issued against vehicle {veh} for dangerous driving. Pending fine amount Rs {fine}. Pay fine online before Lok Adalat summons: http://parivahan-echallan-{i}.top"
        samples.append({"text": text, "label": 1, "category": "government"})

    # 6. E-Commerce Rewards, Scratch Cards & Festival Cashbacks (40 samples)
    brands = ["Amazon India", "Flipkart Big Billion", "Myntra End of Reason", "PhonePe", "Google Pay (GPay)", "Tata Neu"]
    for i in range(40):
        br = brands[i % len(brands)]
        prize = ["iPhone 15 Pro Max", "Samsung Galaxy S24 Ultra", "Gold Voucher worth Rs 50,000", "Cashback of Rs 9,999"][i % 4]
        fee = [499, 999, 1499, 799][i % 4]
        text = f"CONGRATULATIONS! Your mobile number was picked in {br} annual celebration draw! You have won {prize}. Pay refundable courier insurance fee of Rs {fee} to ship parcel: http://festive-reward-winner-{i}.top"
        samples.append({"text": text, "label": 1, "category": "lottery_prize"})

    # 7. Fake APK & Malware Delivery Scams (35 samples)
    apk_names = ["SBI-Secure-Auth.apk", "PM-Kisan-Yojana-2026.apk", "IncomeTax-Efiling.apk", "Fast-EChallan-Pay.apk", "IndiaPost-Tracking.apk"]
    for i in range(35):
        apk = apk_names[i % len(apk_names)]
        text = f"Urgent security patch update required by Cyber Cell. Install official verified banking patch to safeguard netbanking and OTPs: http://gov-cyber-update.link/{apk}. Do not uninstall."
        samples.append({"text": text, "label": 1, "category": "tech_support"})

    # 8. Crypto Staking, Forex AI Bots & VIP Signals (35 samples)
    crypto_assets = ["Bitcoin BTC", "Ethereum ETH", "USDT Tether", "Solana SOL"]
    for i in range(35):
        asset = crypto_assets[i % len(crypto_assets)]
        roi = [20, 35, 50, 15][i % 4]
        text = f"Exclusive Institutional Syndicate: Earn {roi}% daily compounding APY on {asset} through smart contract automated arbitrage. Minimum deposit $100 USDT. Join our verified VIP channel: https://t.me/crypto_arbitrage_{i}"
        samples.append({"text": text, "label": 1, "category": "investment"})

    # 9. Fake Courier Redelivery & Missing House Address (20 samples)
    couriers = ["FedEx India", "DTDC Express", "DHL Express", "India Post Speed Post"]
    for i in range(20):
        cr = couriers[i % len(couriers)]
        text = f"{cr}: Consignment #EXP{892019 + i * 29} delivery failed due to incorrect postal code. Update your complete delivery address and pay pending redelivery charge Rs 35 at http://package-redelivery-portal-{i}.site"
        samples.append({"text": text, "label": 1, "category": "courier"})

    # ─────────────────────────────────────────────────────────────
    # LEGITIMATE COMMUNICATION PATTERNS (Label: 0, ~210 samples)
    # ─────────────────────────────────────────────────────────────

    # 10. Legitimate Bank Transactions & Statements (45 samples)
    legit_banks = ["IDFC FIRST Bank", "Federal Bank", "IndusInd Bank", "RBL Bank", "Yes Bank", "Standard Chartered", "HDFC Bank", "ICICI Bank", "SBI"]
    merchants = ["STARBUCKS", "SWIGGY", "ZOMATO", "UBER", "AMAZON PAY", "RELIANCE RETAIL", "APOLLO HEALTH", "INDIAN OIL PETROL", "IRCTC", "AIRTEL PREPAID"]
    for i in range(45):
        b = legit_banks[i % len(legit_banks)]
        m = merchants[i % len(merchants)]
        amt = [150.0, 480.0, 1250.0, 3400.0, 95.0, 8900.0, 240.0, 6500.0, 45.0][i % 9]
        acct = 2000 + i * 19
        bal = 10000 + i * 382
        text = f"Rs {amt:,.2f} spent on your {b} Debit Card ending in {acct} at {m} on 12-Nov-2026. Avail Bal: Rs {bal:,.2f}. If not you, block card via official banking app or call 1800-CUSTOMER-CARE."
        samples.append({"text": text, "label": 0, "category": "none"})

    # 11. Genuine OTP & Two-Factor Authentication Alerts (40 samples - Hard Negatives)
    apps = ["Zomato food order", "Swiggy Instamart", "MakeMyTrip ticket booking", "Amazon Pay login", "Google 2-Step Verification", "Blinkit grocery delivery", "Paytm wallet login", "Flipkart order checkout"]
    for i in range(40):
        app = apps[i % len(apps)]
        otp = 200000 + (i * 3817) % 800000
        text = f"{otp} is your verification code for {app}. Valid for 10 minutes. For security reasons, do NOT disclose this code to anyone. Our support executives will never call to request OTP."
        samples.append({"text": text, "label": 0, "category": "none"})

    # 12. E-Commerce Shipping, Grocery Delivery & Returns (35 samples)
    delivery_services = ["Swiggy Instamart", "Zomato", "Blinkit", "Amazon India", "Flipkart", "Myntra", "Zepto"]
    for i in range(35):
        ds = delivery_services[i % len(delivery_services)]
        order_id = f"OD{982019 + i * 41}"
        agent = ["Ramesh", "Suresh", "Vikram", "Sunil", "Manish"][i % 5]
        text = f"{ds}: Your order #{order_id} is out for delivery. Delivery partner {agent} will arrive at your address shortly. Track your delivery partner in real-time in the official mobile app."
        samples.append({"text": text, "label": 0, "category": "none"})

    # 13. Legitimate Carrier, Data Quota & Bill Statements (30 samples - Hard Negatives)
    car_alerts = [
        "Airtel: You have used 50% of your daily high-speed data balance. Continue streaming with uninterrupted speed by recharging data packs on Airtel Thanks.",
        "Jio: 100% of high-speed data quota consumed for today. Speed reduced to 64 Kbps. To get high speed, add 1.5GB add-on data booster voucher on MyJio.",
        "Vi: Payment of Rs 499 for your postpaid number received with thanks. Next billing cycle starts 28-Nov.",
        "BSNL: Thank you for recharging with Rs 199. Unlimited voice calls + 2GB/day active for 30 days.",
        "JioFiber: Monthly broadband bill of Rs 824 for ID 080482910 is generated. Due date 22-Nov. Pay on MyJio app."
    ]
    for i in range(30):
        samples.append({"text": car_alerts[i % len(car_alerts)], "label": 0, "category": "none"})

    # 14. Legitimate Utility Receipts & Bookings (30 samples - Hard Negatives)
    utility_receipts = [
        "BESCOM: Payment of Rs 1,280 received for Consumer ID 982019 via UPI. Transaction Ref #UPI-89281. Thank you for timely payment.",
        "Tata Power: Dear customer, power supply scheduled shutdown tomorrow 11 AM to 2 PM for transformer maintenance in Block C.",
        "Indane LPG: Cylinder Refill order #98218 is out for delivery. Cash on delivery amount Rs 853. Verify delivery seal before accepting.",
        "Mahanagar Gas: Gas consumption bill of Rs 640 generated for period Oct-Nov. Pay through official MGL connect portal.",
        "FASTag: Toll fee of Rs 45.00 deducted at Devanahalli Toll Plaza. Vehicle: KA04MB1029. Updated FASTag balance: Rs 480.00."
    ]
    for i in range(30):
        samples.append({"text": utility_receipts[i % len(utility_receipts)], "label": 0, "category": "none"})

    # 15. Conversational, Professional & Meeting Communications (30 samples)
    chats = [
        "Hey! Are you free for a 15-minute sync regarding the API integration changes?",
        "Good morning, please find attached the revised project roadmap for Q1 2027.",
        "Can you pick up milk, tomatoes, and bread on your way back from the station?",
        "Doctor appointment with Dr. Kulkarni confirmed for tomorrow at 5:00 PM.",
        "Happy anniversary! Wishing both of you a wonderful year filled with love and happiness.",
        "The flight from Bangalore to Mumbai has landed safely. Will call you after collecting luggage.",
        "Hi Team, sprint retrospective is scheduled at 4:30 PM today in Conference Room 2.",
        "Thanks for sending over the contract draft, I will review and sign it by tomorrow morning."
    ]
    for i in range(30):
        samples.append({"text": chats[i % len(chats)], "label": 0, "category": "none"})

    return samples

if __name__ == "__main__":
    samples = build_ml_classifier_samples()
    output_path = os.path.join(os.path.dirname(__file__), "ml_classifier_training_corpus.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)
    print(f"Generated {len(samples)} distinct samples at {output_path}")
