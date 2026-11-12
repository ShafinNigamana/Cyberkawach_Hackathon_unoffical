"""
Master 1,000-Sample Dataset Generator for CyberKawach Detection Engines.
Generates 1,000 high-fidelity, linguistically diverse Indian cybersecurity threat patterns
and legitimate communication norms with full multi-task annotations.
"""

import json
import os
import random

def generate_1000_samples():
    random.seed(42)
    samples = []

    # ─────────────────────────────────────────────────────────────
    # PART 1: THREAT PATTERNS (600 Samples across 13 Categories)
    # ─────────────────────────────────────────────────────────────

    # 1. Banking Phishing (50 samples)
    banks = [
        "State Bank of India (SBI)", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Mahindra Bank",
        "Punjab National Bank (PNB)", "Canara Bank", "Bank of Baroda", "Union Bank of India",
        "IDFC FIRST Bank", "Federal Bank", "IndusInd Bank", "Yes Bank", "RBL Bank"
    ]
    bank_reasons = [
        ("account suspended due to pending mandatory PAN-Aadhaar KYC. Update within 24 hours at", 0.95, 0.92, 0.93, 0.20, 0.45),
        ("NetBanking profile temporarily locked due to suspicious international login. Unlock at", 0.96, 0.90, 0.95, 0.20, 0.45),
        ("debit card blocked for security verification. Reactivate your card online at", 0.94, 0.88, 0.91, 0.20, 0.40),
        ("reward points worth Rs 8,450 expiring tonight. Claim cash credit direct to your bank account:", 0.92, 0.85, 0.85, 0.40, 0.45),
        ("dormant account alert: Submit Form 60 and KYC documents immediately at", 0.94, 0.88, 0.92, 0.20, 0.40),
    ]
    phish_tlds = ["xyz", "top", "icu", "site", "online", "live", "info", "link", "club"]
    for i in range(50):
        b = banks[i % len(banks)]
        r_text, f_score, b_imp, c_req, p_req, d_req = bank_reasons[i % len(bank_reasons)]
        tld = phish_tlds[i % len(phish_tlds)]
        domain = f"{b.lower().split()[0]}-secure-portal{i}.{tld}"
        text = f"Dear {b} Customer: Your {r_text} http://{domain} to prevent permanent account suspension."
        samples.append({
            "text": text, "fraud": f_score, "label": 1, "category": "banking",
            "brand_imp": b_imp, "cred_req": c_req, "pay_req": p_req, "deep_analysis": d_req
        })

    # 2. Electricity & Utility Cutoff Scams (45 samples)
    util_providers = [
        "Electricity Department", "Mahavitaran (MSEDCL)", "BESCOM Bangalore", "Tata Power",
        "BSES Yamuna", "BSES Rajdhani", "UPPCL", "Torrent Power", "Adani Electricity", "PSPCL Punjab"
    ]
    cutoff_times = ["tonight at 9:30 PM", "in 2 hours", "today by 8:00 PM", "tonight at 10:00 PM"]
    for i in range(45):
        prov = util_providers[i % len(util_providers)]
        tm = cutoff_times[i % len(cutoff_times)]
        phone = f"98{20000000 + i * 187}"[:10]
        cid = 100000 + i * 31
        if i % 2 == 0:
            text = f"Dear Consumer (ID: {cid}), your electricity power line will be disconnected {tm} from {prov} office because last month bill is not updated. Please call our power officer immediately at {phone}."
            samples.append({"text": text, "fraud": 0.93, "label": 1, "category": "electricity", "brand_imp": 0.75, "cred_req": 0.25, "pay_req": 0.92, "deep_analysis": 0.60})
        else:
            text = f"URGENT: Power disconnection notice issued by {prov}. Settle pending dues or download bill verification update APK: http://vidhyut-bill-pay-{i}.apk to avoid black-out."
            samples.append({"text": text, "fraud": 0.95, "label": 1, "category": "electricity", "brand_imp": 0.80, "cred_req": 0.30, "pay_req": 0.95, "deep_analysis": 0.65})

    # 3. Courier & Parcel Delivery Fraud (45 samples)
    couriers = ["India Post", "BlueDart Express", "Delhivery", "DTDC Courier", "FedEx India", "Speed Post", "DHL Express", "Shadowfax"]
    for i in range(45):
        c = couriers[i % len(couriers)]
        track = f"IN{890000 + i * 49}"
        fee = [25, 48, 75, 35][i % 4]
        if i % 2 == 0:
            text = f"{c}: Your parcel #{track} failed delivery due to incomplete street address. Update your delivery address and pay re-delivery fee Rs {fee} at http://track-package-{i}.top within 24 hours."
            samples.append({"text": text, "fraud": 0.94, "label": 1, "category": "courier", "brand_imp": 0.85, "cred_req": 0.65, "pay_req": 0.85, "deep_analysis": 0.50})
        else:
            text = f"{c} Notice: Consignment #{track} is detained at sorting hub due to unpaid customs clearance duty. Pay Rs {fee * 4} immediately: http://customs-release-{i}.site to avoid return to sender."
            samples.append({"text": text, "fraud": 0.93, "label": 1, "category": "courier", "brand_imp": 0.80, "cred_req": 0.60, "pay_req": 0.90, "deep_analysis": 0.55})

    # 4. Mandatory KYC Suspension Scams (45 samples)
    kyc_entities = ["Paytm Payments Bank", "PhonePe Wallet", "Google Pay UPI", "Aadhaar UIDAI Portal", "PAN NSDL Portal", "FASTag NHAI", "DigiLocker"]
    for i in range(45):
        tgt = kyc_entities[i % len(kyc_entities)]
        ph = f"91{70000000 + i * 293}"[:10]
        if i % 2 == 0:
            text = f"Dear User, your {tgt} KYC validation has expired. Outgoing transactions and wallet balance will be permanently frozen. Complete online re-KYC at http://kyc-verification-{i}.top before midnight."
            samples.append({"text": text, "fraud": 0.94, "label": 1, "category": "kyc", "brand_imp": 0.85, "cred_req": 0.92, "pay_req": 0.30, "deep_analysis": 0.50})
        else:
            text = f"Mandatory Compliance Alert: {tgt} requires biometric PAN-Aadhaar linking within 6 hours. Call customer executive {ph} or download quick KYC assistant: http://biometric-kyc-{i}.icu"
            samples.append({"text": text, "fraud": 0.95, "label": 1, "category": "kyc", "brand_imp": 0.85, "cred_req": 0.94, "pay_req": 0.35, "deep_analysis": 0.55})

    # 5. Lottery, Scratch Cards & Lucky Draw Scams (45 samples)
    lottery_promos = ["Kaun Banega Crorepati (KBC) Lucky Draw", "Jio 5G Celebration Prize", "Amazon Diwali Mega Jackpot", "Flipkart Big Billion Winner", "PhonePe Golden Scratch Card", "Tata Neu Festival Voucher"]
    for i in range(45):
        promo = lottery_promos[i % len(lottery_promos)]
        amt = [2500000, 5000000, 1500000, 3500000, 750000][i % 5]
        fee = [12500, 25000, 7500, 15000, 4999][i % 5]
        ph = f"98{11000000 + i * 113}"[:10]
        text = f"CONGRATULATIONS! You have won Rs {amt:,} from {promo}. To release your winning cheque, transfer refundable government tax & processing charge Rs {fee} to manager. WhatsApp {ph} or visit http://claim-prize-{i}.top"
        samples.append({"text": text, "fraud": 0.96, "label": 1, "category": "lottery_prize", "brand_imp": 0.80, "cred_req": 0.40, "pay_req": 0.95, "deep_analysis": 0.40})

    # 6. Part-Time Job & Task Scams (45 samples)
    task_types = [
        "like YouTube videos and follow channels", "write 5-star Google Maps hotel reviews",
        "rate merchant products on Amazon & Flipkart", "complete 15-minute movie trailer surveys",
        "perform online freelance typing and data entry"
    ]
    for i in range(45):
        task = task_types[i % len(task_types)]
        daily = [2500, 4500, 8000, 6000][i % 4]
        deposit = [999, 1499, 2500, 1999][i % 4]
        text = f"WORK FROM MOBILE: Earn Rs {daily:,} daily part time! Simply {task}. No previous experience required. Same day withdrawal to UPI. Transfer refundable registration fee Rs {deposit} to HR manager on Telegram @daily_task_{i}."
        samples.append({"text": text, "fraud": 0.92, "label": 1, "category": "job_offer", "brand_imp": 0.65, "cred_req": 0.25, "pay_req": 0.90, "deep_analysis": 0.45})

    # 7. UPI Collect & Fake Refund Scams (45 samples)
    upi_brands = ["PhonePe", "Google Pay (GPay)", "Paytm UPI", "BHIM UPI", "Amazon Pay"]
    for i in range(45):
        app = upi_brands[i % len(upi_brands)]
        amt = [2499, 4500, 8900, 3150, 6200][i % 5]
        text = f"{app} Alert: Your merchant refund of Rs {amt:,} for order #{10000+i} is waiting. Open {app}, tap the pending collect request, and enter your 6-digit UPI PIN to credit money into your savings account."
        samples.append({"text": text, "fraud": 0.95, "label": 1, "category": "upi_fraud", "brand_imp": 0.75, "cred_req": 0.85, "pay_req": 0.95, "deep_analysis": 0.65})

    # 8. Fake Instant Loan Scams (45 samples)
    loan_brands = ["Dhani Cash Loan", "KreditBee Fast Cash", "Bajaj Finserv Personal Loan", "Instant Mudra Credit", "PocketCash India", "RupeeSpeed Loan"]
    for i in range(45):
        lb = loan_brands[i % len(loan_brands)]
        amt = [500000, 1000000, 250000, 750000][i % 4]
        fee = [1850, 2499, 3200, 1499][i % 4]
        text = f"{lb}: Pre-approved personal loan of Rs {amt:,} at 0.5% interest with zero document verification. Pay loan processing and insurance fee Rs {fee} via UPI or download APK: http://instant-cash-{i}.apk to disburse funds."
        samples.append({"text": text, "fraud": 0.94, "label": 1, "category": "loan_fraud", "brand_imp": 0.75, "cred_req": 0.40, "pay_req": 0.92, "deep_analysis": 0.60})

    # 9. Investment & Crypto Arbitrage Scams (45 samples)
    inv_schemes = [
        "Institutional Stock Market VIP Insider Group", "Automated AI Crypto Arbitrage Staking Pool",
        "Daily Compounding Forex High-Yield Syndicate", "Pre-IPO Unlisted Shares Private Allocation",
        "Gold Trading Algorithmic Robot"
    ]
    for i in range(45):
        inv = inv_schemes[i % len(inv_schemes)]
        roi = [25, 50, 100, 200][i % 4]
        text = f"GUARANTEED {roi}% PROFIT IN 7 DAYS! Join our {inv}. 100% capital protection guaranteed by smart contracts. Transfer initial deposit of Rs 10,000 to VIP trustee wallet in Telegram: @wealth_syndicate_{i}."
        samples.append({"text": text, "fraud": 0.93, "label": 1, "category": "investment", "brand_imp": 0.25, "cred_req": 0.30, "pay_req": 0.95, "deep_analysis": 0.65})

    # 10. Tech Support & Device Lock Scams (45 samples)
    tech_alerts = [
        ("Microsoft Windows Defender", "Critical Trojan.Spyware infection detected. Your personal passwords and banking details are compromised. Call Microsoft certified support 1800-891-"),
        ("Apple iCloud Security", "Unauthorized login attempt from Moscow. Your Apple ID is locked. Call Apple security specialist 1800-291-"),
        ("Google Android Security Center", "Vulnerability detected on your phone. System files corrupted. Download antivirus fix immediately from http://android-cleaner-"),
        ("QuickHeal Antivirus Alert", "Ransomware detected on computer. Device will be encrypted in 1 hour. Contact recovery helpdesk 1800-419-")
    ]
    for i in range(45):
        tb, msg = tech_alerts[i % len(tech_alerts)]
        phone_suffix = f"{1000 + i * 19}"
        if "http" in msg:
            text = f"{tb}: {msg}{i}.apk"
        else:
            text = f"{tb}: {msg}{phone_suffix} immediately to prevent complete data loss."
        samples.append({"text": text, "fraud": 0.91, "label": 1, "category": "tech_support", "brand_imp": 0.88, "cred_req": 0.70, "pay_req": 0.45, "deep_analysis": 0.50})

    # 11. Telecom, SIM Swap & Tower Scams (45 samples)
    telcos = ["Airtel India", "Reliance Jio", "Vodafone Idea (Vi)", "BSNL Telecom"]
    for i in range(45):
        t = telcos[i % len(telcos)]
        phone = f"98{45000000 + i * 179}"[:10]
        if i % 3 == 0:
            text = f"{t} ALERT: Your 4G/5G SIM card KYC is expired. Outgoing and incoming calls will be stopped tonight at 10 PM. Call customer executive {phone} or update Aadhaar at http://sim-kyc-{i}.top"
        elif i % 3 == 1:
            text = f"{t}: Request to convert your physical SIM to eSIM received. If this was not done by you, forward your 19-digit SIM number and OTP to {phone} to stop deactivation."
        else:
            text = f"DoT & {t} Notice: 5G Mobile Tower installation approved on your land/terrace. Monthly rent Rs 40,000 + Rs 20 Lakhs advance. Pay stamp duty fee Rs 3,500 to officer at {phone}."
        samples.append({"text": text, "fraud": 0.93, "label": 1, "category": "telecom", "brand_imp": 0.85, "cred_req": 0.88, "pay_req": 0.35, "deep_analysis": 0.50})

    # 12. Government & E-Challan Scams (50 samples)
    gov_schemes = [
        ("Income Tax Department: Your tax refund of Rs 24,850 under Section 143(1) is waiting. Submit your bank account and PAN details at http://incometax-efiling-refund-{i}.info/login to process payment.", "government", 0.94, 0.85, 0.88, 0.20, 0.50),
        ("Traffic Police Department: Pending speed violation e-challan MH02-8921. Pay fine of Rs 1,500 within 24 hours at http://echallan-parivahan-pay-{i}.site to avoid court summons.", "government", 0.92, 0.80, 0.30, 0.90, 0.55),
        ("PM Kisan Samman Nidhi: Beneficiary installment of Rs 6,000 credited on hold. Verify Aadhaar card at http://pm-kisan-portal-{i}.top to disburse payment.", "government", 0.93, 0.80, 0.85, 0.20, 0.50),
        ("PM Surya Ghar Muft Bijli Yojana: Free solar rooftop subsidy approved for your house. Deposit registration fee Rs 1,999 at http://surya-ghar-subsidy-{i}.site to book installation.", "government", 0.91, 0.75, 0.30, 0.88, 0.50),
    ]
    for i in range(50):
        tmpl, cat, f_sc, b_imp, c_req, p_req, d_req = gov_schemes[i % len(gov_schemes)]
        text = tmpl.replace("{i}", str(i))
        samples.append({"text": text, "fraud": f_sc, "label": 1, "category": cat, "brand_imp": b_imp, "cred_req": c_req, "pay_req": p_req, "deep_analysis": d_req})

    # 13. Digital Arrest & Police Extortion (50 samples)
    law_extortions = [
        ("CBI Cyber Crime Division: An FIR has been registered against your mobile number for illegal money laundering. Connect to Deputy Commissioner immediately on Skype video call {phone} to prevent physical arrest.", "extortion_legal", 0.96, 0.88, 0.40, 0.92, 0.75),
        ("Customs Border Control: An international courier parcel containing narcotics and fake passports has been seized bearing your Aadhaar ID. Pay penalty fine Rs 45,000 to clearance officer to stop prosecution.", "extortion_legal", 0.95, 0.80, 0.35, 0.95, 0.75),
        ("Delhi Police Special Cell: Arrest warrant issued under Section 420 IPC. Bank accounts are frozen. Join video interrogation room immediately or police team will raid your residence.", "extortion_legal", 0.96, 0.85, 0.40, 0.92, 0.75),
        ("Supreme Court Collegium Notice: You are summoned for financial tax evasion court hearing. Pay bail bond clearance Rs 25,000 to prevent immediate imprisonment.", "extortion_legal", 0.94, 0.80, 0.30, 0.94, 0.70),
    ]
    for i in range(50):
        tmpl, cat, f_sc, b_imp, c_req, p_req, d_req = law_extortions[i % len(law_extortions)]
        ph = f"98{19000000 + i * 211}"[:10]
        text = tmpl.replace("{phone}", ph) + f" (Case Ref #{202600 + i * 17})"
        samples.append({"text": text, "fraud": f_sc, "label": 1, "category": cat, "brand_imp": b_imp, "cred_req": c_req, "pay_req": p_req, "deep_analysis": d_req})

    # ─────────────────────────────────────────────────────────────
    # PART 2: BENIGN SAMPLES (400 Samples, Zero Brand Bias)
    # ─────────────────────────────────────────────────────────────

    # 14. Legitimate Bank Transactions & Statements (80 samples)
    legit_banks = [
        "State Bank of India (SBI)", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank",
        "Punjab National Bank", "Canara Bank", "Bank of Baroda", "IDFC FIRST Bank", "Federal Bank",
        "IndusInd Bank", "Yes Bank"
    ]
    merchants = ["AMAZON INDIA", "FLIPKART", "SWIGGY", "ZOMATO", "UBER INDIA", "BLINKIT", "APOLLO PHARMACY", "SHELL PETROL", "RELIANCE SMART", "ZEPTO"]
    for i in range(80):
        b = legit_banks[i % len(legit_banks)]
        m = merchants[i % len(merchants)]
        amt = [240.0, 1450.50, 499.0, 3200.0, 85.0, 12500.0, 780.0, 55.0, 2100.0, 95.0][i % 10]
        bal = [34500.20, 12890.0, 84320.10, 4210.50, 67200.0][i % 5]
        acct = 1000 + i * 17
        text = f"Dear {b} Customer, your A/c ending in {acct} has been debited by Rs {amt:,.2f} on 12-Nov-2026. Ref: UPI/POS/{m}. Avail Bal: Rs {bal:,.2f}. If not done by you, visit official website or call customer care."
        samples.append({"text": text, "fraud": 0.03, "label": 0, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.02, "deep_analysis": 0.05})

    # 15. Genuine OTP & Two-Factor Authentication Alerts (80 samples - Hard Negatives)
    auth_services = [
        "Amazon login", "IRCTC tatkal ticket booking", "Swiggy food order", "NetBanking profile login",
        "HDFC credit card payment", "ICICI iMobile app login", "Flipkart checkout", "Google 2-Step Verification",
        "Zomato food order", "Blinkit grocery delivery", "MakeMyTrip ticket booking", "Paytm wallet transfer"
    ]
    for i in range(80):
        svc = auth_services[i % len(auth_services)]
        otp = 100000 + (i * 2713) % 900000
        text = f"{otp} is your secret One Time Password (OTP) for {svc}. Valid for 5 minutes. NEVER share your OTP, PIN or password with anyone, including bank officials. Cyber vigilance pays."
        samples.append({"text": text, "fraud": 0.04, "label": 0, "category": "none", "brand_imp": 0.02, "cred_req": 0.02, "pay_req": 0.02, "deep_analysis": 0.05})

    # 16. Legitimate Telecom Data Quota & Recharges (60 samples - Hard Negatives)
    telco_legit = [
        "Jio: Your daily 1.5 GB high-speed data quota is 50% consumed. Renew or recharge via MyJio app.",
        "Airtel: Your unlimited pack of Rs 299 expires in 3 days. Recharge on Airtel Thanks app to enjoy uninterrupted data and calls.",
        "Vi: Your postpaid bill of Rs 499 for mobile number 98XXXX1234 is generated. Due date is 25-Nov. Pay via Vi App.",
        "BSNL: Plan validity extended till 31-Dec-2026. Thank you for choosing BSNL mobile services.",
        "Dear Jio customer, thank you for recharging with Rs 666. 1.5GB/day + unlimited 5G data is active for 84 days.",
        "Airtel Thanks: You have unlocked free Wynk Music subscription. Download Airtel Thanks app to activate.",
        "Jio: 100% of your daily high-speed internet data has been exhausted. Speed reduced to 64Kbps."
    ]
    for i in range(60):
        text = telco_legit[i % len(telco_legit)]
        samples.append({"text": text, "fraud": 0.02, "label": 0, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.03})

    # 17. Legitimate Utility Bills & Payment Confirmations (60 samples - Hard Negatives)
    utility_legit = [
        "BESCOM: Dear consumer, your electricity bill of Rs 890 for Account ID 892019 is generated. Due date 20-Nov. Pay online at official bescom.org portal.",
        "Mahavitaran (MSEDCL): Bill of Rs 1,420 for Consumer No 0192819 generated. Due date 24-Nov. Avail prompt payment discount on msedcl.in",
        "Tata Power: Dear customer, payment of Rs 2,150 against bill #98218 received with thanks on 11-Nov-2026. Receipt is available in customer portal.",
        "Indane Gas: Your LPG cylinder refill booking is confirmed. Order #89281. Delivery will be attempted within 2 working days.",
        "Torrent Power: Dear Consumer, scheduled maintenance work in your area tomorrow between 10 AM to 1 PM. Power supply may be temporarily affected.",
        "FASTag: Toll fee of Rs 45.00 deducted at Devanahalli Toll Plaza. Vehicle: KA04MB1029. Updated FASTag balance: Rs 480.00."
    ]
    for i in range(60):
        text = utility_legit[i % len(utility_legit)]
        samples.append({"text": text, "fraud": 0.02, "label": 0, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.04})

    # 18. Legitimate Delivery & Shipment Tracking (60 samples)
    courier_brands = ["BlueDart", "Delhivery", "Amazon India", "Flipkart", "DTDC", "Shadowfax", "Blinkit", "Zepto"]
    for i in range(60):
        cn = courier_brands[i % len(courier_brands)]
        pkg = f"PKG{918000 + i * 47}"
        pin = 1000 + i * 13
        text = f"Your shipment {pkg} from {cn} is out for delivery today. Delivery agent will arrive between 2 PM to 5 PM. Share delivery code {pin} with agent at doorstep."
        samples.append({"text": text, "fraud": 0.03, "label": 0, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.02, "deep_analysis": 0.05})

    # 19. Everyday Conversational, Workplace & Meeting Messages (60 samples)
    chats = [
        "Hey, are you free for a quick call this afternoon?",
        "Please find attached the presentation slides for tomorrow's client sync.",
        "Doctor appointment confirmed with Dr. Sharma tomorrow at 11:30 AM.",
        "Can we reschedule our lunch meeting to Friday 1 PM instead?",
        "Happy birthday! Wishing you a wonderful year ahead with family and friends.",
        "Don't forget to buy milk and groceries on your way back home.",
        "Thanks for the update, I will review the code pull request by evening.",
        "Flight ticket booked: BLR to DEL on 18th Nov. PNR: W92KP1. Have a safe journey!",
        "Hi Ramesh, can you send me the address of the venue for the party tonight?",
        "Please bring your laptop charger when you come to the office tomorrow.",
        "The project deployment was successful and all servers are responding normally.",
        "Good morning team, reminder that our weekly all-hands sprint review is at 11 AM today."
    ]
    for i in range(60):
        text = chats[i % len(chats)]
        samples.append({"text": text, "fraud": 0.01, "label": 0, "category": "none", "brand_imp": 0.01, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.02})

    return samples

if __name__ == "__main__":
    samples = generate_1000_samples()
    output_dir = os.path.dirname(__file__)
    
    # Save to both target locations
    laya_file = os.path.join(output_dir, "laya_training_corpus.json")
    with open(laya_file, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)
        
    ml_file = os.path.join(output_dir, "ml_classifier_training_corpus.json")
    with open(ml_file, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2)

    print(f"Generated {len(samples)} master samples across 13 threat categories + benign!")
    print(f"Saved to {laya_file} and {ml_file}")
