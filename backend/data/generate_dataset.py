"""
Dataset generator and builder for Laya Fast Typed-Decision Model.
Generates 500+ realistic, diverse cybersecurity threat and legitimate communication samples.
Ensures zero brand leakage (brands like SBI, Jio, BESCOM, Amazon appear in both fraud and benign classes).
"""
import json
import os

def build_500_samples():
    samples = []

    # ─────────────────────────────────────────────────────────────
    # 1. Banking Phishing (35 samples)
    # ─────────────────────────────────────────────────────────────
    banks = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Mahindra Bank", "Punjab National Bank", "Canara Bank", "Bank of Baroda", "Union Bank", "IndusInd Bank"]
    reasons = [
        ("suspended due to pending PAN KYC verification. Update immediately at", 0.95, 0.92, 0.92, 0.20, 0.45),
        ("blocked due to incomplete Aadhaar linkage. Submit details now at", 0.94, 0.90, 0.94, 0.20, 0.45),
        ("netbanking profile locked after suspicious login attempt. Unlock at", 0.95, 0.90, 0.95, 0.20, 0.45),
        ("debit card deactivated for security reasons. Reactivate online at", 0.93, 0.88, 0.90, 0.20, 0.40),
        ("reward points worth Rs 9,850 expiring tonight. Redeem cash to bank account at", 0.92, 0.85, 0.85, 0.40, 0.45),
    ]
    phish_domains = ["sbi-secure-portal.xyz", "hdfc-netbanking-verify.top", "icici-kyc-update.site", "axis-login-auth.icu", "kotak-support-online.link", "pnb-netbanking-portal.info", "bank-kyc-service.top"]
    
    count = 0
    for bank in banks:
        for r_text, f_score, b_imp, c_req, p_req, d_req in reasons:
            domain = phish_domains[(count) % len(phish_domains)]
            text = f"Dear {bank} customer, your account has been {r_text} http://{domain}"
            samples.append({
                "text": text,
                "fraud": f_score,
                "category": "banking",
                "brand_imp": b_imp,
                "cred_req": c_req,
                "pay_req": p_req,
                "deep_analysis": d_req
            })
            count += 1
            if count >= 35:
                break
        if count >= 35:
            break

    # ─────────────────────────────────────────────────────────────
    # 2. Electricity & Utility Disconnection (28 samples)
    # ─────────────────────────────────────────────────────────────
    providers = ["Electricity Department", "Mahavitaran (MSEDCL)", "BESCOM", "Tata Power", "BSES Yamuna", "Torrent Power", "UPPCL", "Adani Electricity"]
    times = ["tonight at 9:30 PM", "within 2 hours", "today at 10:00 PM", "tonight at 8:00 PM"]
    for i in range(28):
        prov = providers[i % len(providers)]
        tm = times[i % len(times)]
        phone = f"98{20000000 + i * 137}"[:10]
        if i % 2 == 0:
            text = f"Dear Consumer, your electricity power supply will be disconnected {tm} from {prov} office because your previous month bill was not updated. Please immediately contact our electricity officer at {phone}."
            samples.append({"text": text, "fraud": 0.93, "category": "electricity", "brand_imp": 0.75, "cred_req": 0.25, "pay_req": 0.92, "deep_analysis": 0.60})
        else:
            text = f"Urgent Notice: {prov} power cutoff order issued for consumer ID {10000+i}. Clear bill immediately via APK update: http://vidhyut-bill-pay{i}.apk or call {phone}"
            samples.append({"text": text, "fraud": 0.95, "category": "electricity", "brand_imp": 0.80, "cred_req": 0.30, "pay_req": 0.95, "deep_analysis": 0.65})

    # ─────────────────────────────────────────────────────────────
    # 3. Courier & Parcel Delivery Fraud (28 samples)
    # ─────────────────────────────────────────────────────────────
    couriers = ["India Post", "BlueDart", "Delhivery", "DTDC", "FedEx India", "Speed Post", "DHL Express"]
    for i in range(28):
        c = couriers[i % len(couriers)]
        track = f"IN{892019 + i * 43}"
        if i % 2 == 0:
            text = f"{c}: Your parcel #{track} cannot be delivered due to incorrect address or missing house number. Update your address and pay re-delivery fee Rs 48 at http://track-package-{c.lower().replace(' ', '')}.top within 24 hrs."
            samples.append({"text": text, "fraud": 0.94, "category": "courier", "brand_imp": 0.85, "cred_req": 0.65, "pay_req": 0.85, "deep_analysis": 0.50})
        else:
            text = f"Urgent notification from {c}: Package #{track} is held at regional sorting facility. Pay customs clearance charge of Rs 125 immediately: http://parcel-release-hub.site/{track}"
            samples.append({"text": text, "fraud": 0.93, "category": "courier", "brand_imp": 0.80, "cred_req": 0.60, "pay_req": 0.90, "deep_analysis": 0.55})

    # ─────────────────────────────────────────────────────────────
    # 4. Mandatory KYC Suspension Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    kyc_targets = ["Paytm Wallet", "PhonePe", "Google Pay UPI", "Aadhaar UIDAI", "PAN NSDL", "Voter ID Portal"]
    for i in range(28):
        tgt = kyc_targets[i % len(kyc_targets)]
        ph = f"91{70000000 + i * 281}"[:10]
        if i % 2 == 0:
            text = f"Dear User, your {tgt} KYC documents have expired today. Account services and wallet transfers will be permanently stopped. Complete online re-KYC at http://kyc-verification-{i}.top"
            samples.append({"text": text, "fraud": 0.94, "category": "kyc", "brand_imp": 0.85, "cred_req": 0.92, "pay_req": 0.30, "deep_analysis": 0.50})
        else:
            text = f"Mandatory Alert: {tgt} compliance requires biometric PAN update within 12 hours. Download QuickSupport app or verify at http://fast-kyc-portal.icu or call {ph}."
            samples.append({"text": text, "fraud": 0.95, "category": "kyc", "brand_imp": 0.85, "cred_req": 0.94, "pay_req": 0.35, "deep_analysis": 0.55})

    # ─────────────────────────────────────────────────────────────
    # 5. Lottery & Lucky Draw Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    schemes = ["Kaun Banega Crorepati (KBC) Lucky Draw", "Jio 5G Celebration Prize", "Amazon Diwali Mega Jackpot", "Flipkart Big Billion Winner", "PhonePe Gold Scratch Card"]
    for i in range(28):
        sch = schemes[i % len(schemes)]
        amt = [2500000, 5000000, 1000000, 750000][i % 4]
        fee = [12500, 25000, 5500, 999][i % 4]
        ph = f"98{11000000 + i * 99}"[:10]
        text = f"CONGRATULATIONS! You have won Rs {amt:,} from {sch}. To claim your winning prize cheque, deposit refundable processing and tax fee of Rs {fee} to our manager. WhatsApp {ph} immediately or visit http://claim-prize-{i}.top"
        samples.append({"text": text, "fraud": 0.96, "category": "lottery_prize", "brand_imp": 0.80, "cred_req": 0.40, "pay_req": 0.95, "deep_analysis": 0.40})

    # ─────────────────────────────────────────────────────────────
    # 6. Part-Time Job & Task Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    job_templates = [
        "Earn Rs 2,500 to Rs 8,000 daily from home! Part time online job: like YouTube videos and write hotel reviews. No experience needed. Contact HR manager on Telegram @daily_task_{i} to start.",
        "Work from mobile: Complete 15 minutes Google Maps rating task and earn Rs 3,000 daily. WhatsApp HR to get registered with deposit.",
        "Freelance online typing and data entry job: Earn Rs 25,000 monthly. Transfer refundable registration fee Rs 999 to receive project files.",
        "Amazon telegram product review task: Earn Rs 150 per review. Join our VIP merchant channel @amazon_task_{i} to claim daily payout.",
    ]
    for i in range(28):
        t = job_templates[i % len(job_templates)].replace("{i}", str(i))
        samples.append({"text": t, "fraud": 0.92, "category": "job_offer", "brand_imp": 0.65, "cred_req": 0.25, "pay_req": 0.90, "deep_analysis": 0.45})

    # ─────────────────────────────────────────────────────────────
    # 7. UPI Collect & Refund Fraud (28 samples)
    # ─────────────────────────────────────────────────────────────
    upi_apps = ["PhonePe", "Google Pay (GPay)", "Paytm UPI", "BHIM UPI"]
    for i in range(28):
        app = upi_apps[i % len(upi_apps)]
        amt = [3500, 4999, 8200, 2150, 6800][i % 5]
        text = f"{app} Alert: Your cash refund of Rs {amt:,} for recent failed transaction has been approved. Open {app}, tap the pending collect request, and enter your 6-digit UPI PIN to receive money."
        samples.append({"text": text, "fraud": 0.95, "category": "upi_fraud", "brand_imp": 0.75, "cred_req": 0.85, "pay_req": 0.95, "deep_analysis": 0.65})

    # ─────────────────────────────────────────────────────────────
    # 8. Fake Instant Loan Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    loan_orgs = ["Dhani Cash", "KreditBee Instant", "Bajaj Finserv Personal Loan", "SBI Instant Mudra", "QuickCash Fast Loan"]
    for i in range(28):
        org = loan_orgs[i % len(loan_orgs)]
        loan_amt = [500000, 1000000, 250000, 800000][i % 4]
        fee = [1999, 2499, 3500, 1499][i % 4]
        text = f"{org}: Pre-approved personal loan of Rs {loan_amt:,} at 1% interest with zero document verification. Transfer file processing fee of Rs {fee} via UPI or download APK: http://instant-loan-{i}.apk to disburse funds."
        samples.append({"text": text, "fraud": 0.94, "category": "loan_fraud", "brand_imp": 0.75, "cred_req": 0.40, "pay_req": 0.92, "deep_analysis": 0.60})

    # ─────────────────────────────────────────────────────────────
    # 9. Investment & Crypto Arbitrage Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    inv_types = ["Institutional Stock Market Insider Group", "Crypto Arbitrage Automated AI Bot", "Forex Daily Compounding Syndicate", "Pre-IPO Unlisted Shares Private Allocation"]
    for i in range(28):
        inv = inv_types[i % len(inv_types)]
        ret = [500, 300, 1000, 250][i % 4]
        text = f"Guaranteed {ret}% return in 7 days with {inv}! Zero risk, 100% principal protection verified by smart contracts. Transfer initial deposit of Rs 10,000 to VIP manager wallet in Telegram @wealth_group_{i}."
        samples.append({"text": text, "fraud": 0.93, "category": "investment", "brand_imp": 0.25, "cred_req": 0.30, "pay_req": 0.95, "deep_analysis": 0.65})

    # ─────────────────────────────────────────────────────────────
    # 10. Tech Support & Device Lock Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    tech_brands = ["Microsoft Windows Defender", "Apple iCloud Security", "Google Android Device Protection", "QuickHeal Antivirus"]
    for i in range(28):
        tb = tech_brands[i % len(tech_brands)]
        phone = f"1800-89{1000 + i * 29}"
        text = f"{tb} CRITICAL ALERT: Suspicious Trojan.Spyware infection detected on your device! Your financial data is exposed. Do not shut down. Call certified customer support hotline {phone} immediately."
        samples.append({"text": text, "fraud": 0.91, "category": "tech_support", "brand_imp": 0.88, "cred_req": 0.70, "pay_req": 0.45, "deep_analysis": 0.50})

    # ─────────────────────────────────────────────────────────────
    # 11. Telecom & SIM Deactivation Scams (28 samples)
    # ─────────────────────────────────────────────────────────────
    telcos = ["Airtel", "Jio", "Vodafone Idea (Vi)", "BSNL"]
    for i in range(28):
        tel = telcos[i % len(telcos)]
        phone = f"98{45000000 + i * 77}"[:10]
        text = f"Notice from {tel}: Your 4G/5G SIM card KYC verification is pending. Outgoing calls and mobile data will be permanently blocked tonight at 10 PM. Call customer support officer {phone} or update Aadhaar at http://sim-kyc-{tel.lower().split()[0]}.top"
        samples.append({"text": text, "fraud": 0.93, "category": "telecom", "brand_imp": 0.85, "cred_req": 0.88, "pay_req": 0.35, "deep_analysis": 0.50})

    # ─────────────────────────────────────────────────────────────
    # 12. Government, Tax & Legal Extortion (28 samples)
    # ─────────────────────────────────────────────────────────────
    gov_bodies = [
        ("Income Tax Department Notice: Your tax refund of Rs 28,450 is approved. Submit your bank account and PAN details at http://incometax-refund-portal.site to credit funds.", "government", 0.94, 0.85, 0.88, 0.20, 0.50),
        ("Traffic Police Department: Pending speed violation e-challan MH02-8921. Pay fine within 24 hours at http://echallan-parivahan-pay.site to avoid vehicle seizure and court warrant.", "government", 0.92, 0.80, 0.30, 0.90, 0.55),
        ("CBI Cyber Cell / Delhi Police: An FIR has been registered against your mobile number for illegal online activities. Call Deputy Commissioner immediately on WhatsApp +91-9821839201 to settle before arrest.", "extortion_legal", 0.95, 0.85, 0.40, 0.92, 0.75),
        ("Customs Border Control: Parcel intercepted at airport containing narcotics addressed to your Aadhaar ID. Pay penalty fine Rs 45,000 to clearance officer to stop legal prosecution.", "extortion_legal", 0.95, 0.80, 0.35, 0.95, 0.75),
    ]
    for i in range(28):
        template, cat, f_score, b_imp, c_req, p_req, d_req = gov_bodies[i % len(gov_bodies)]
        samples.append({
            "text": f"{template} (Ref #{10000 + i * 17})",
            "fraud": f_score,
            "category": cat,
            "brand_imp": b_imp,
            "cred_req": c_req,
            "pay_req": p_req,
            "deep_analysis": d_req
        })

    # ─────────────────────────────────────────────────────────────
    # 13. Benign / Legitimate Messages (~175 samples)
    # ─────────────────────────────────────────────────────────────
    # 13a. Legitimate Bank Transactions & Statements (35 samples)
    legit_banks = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "PNB", "Canara Bank", "Bank of Baroda"]
    merchants = ["AMAZON INDIA", "FLIPKART", "SWIGGY", "ZOMATO", "UBER INDIA", "BLINKIT", "APOLLO PHARMACY", "SHELL PETROL"]
    for i in range(35):
        b = legit_banks[i % len(legit_banks)]
        m = merchants[i % len(merchants)]
        amt = [240.0, 1450.50, 499.0, 3200.0, 85.0, 12500.0, 780.0, 55.0][i % 8]
        bal = [34500.20, 12890.0, 84320.10, 4210.50][i % 4]
        acct = 1000 + i * 13
        text = f"Dear {b} Customer, your A/c XX{acct} has been debited by Rs {amt:,.2f} on 12-Nov-2026. Ref: UPI/POS/{m}. Avail Bal: Rs {bal:,.2f}. If not done by you, visit {b.lower().replace(' ', '')}.com/dispute or call customer care."
        samples.append({"text": text, "fraud": 0.03, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.02, "deep_analysis": 0.05})

    # 13b. Legitimate OTP & Verification Notifications (35 samples - Hard Negatives)
    for i in range(35):
        otp = 100000 + i * 2713 % 900000
        service = ["Amazon login", "IRCTC tatkal ticket booking", "Swiggy food order", "NetBanking profile login", "HDFC card transaction", "ICICI iMobile", "Flipkart checkout"][i % 7]
        text = f"{otp} is your secret One Time Password (OTP) for {service}. Valid for 5 minutes. NEVER share your OTP, PIN or password with anyone, even bank officials. Cyber vigilance pays."
        samples.append({"text": text, "fraud": 0.04, "category": "none", "brand_imp": 0.02, "cred_req": 0.02, "pay_req": 0.02, "deep_analysis": 0.05})

    # 13c. Legitimate Telecom Alerts from Jio, Airtel, Vi, BSNL (35 samples - Crucial for zero brand bias)
    telco_legit = [
        "Jio: Your daily 1.5 GB high-speed data quota is 50% consumed. Renew or recharge via MyJio app.",
        "Airtel: Your unlimited pack of Rs 299 expires in 3 days. Recharge on Airtel Thanks app to enjoy uninterrupted data and calls.",
        "Vi: Your postpaid bill of Rs 499 for mobile number 98XXXX1234 is generated. Due date is 25-Nov. Pay via Vi App.",
        "BSNL: Plan validity extended till 31-Dec-2026. Thank you for choosing BSNL mobile services.",
        "Dear Jio customer, thank you for recharging with Rs 666. 1.5GB/day + unlimited 5G data is active for 84 days.",
        "Airtel Thanks: You have unlocked free Wynk Music subscription. Download Airtel Thanks app to activate.",
        "Jio: 100% of your daily high-speed internet data has been exhausted. Speed reduced to 64Kbps."
    ]
    for i in range(35):
        text = telco_legit[i % len(telco_legit)]
        samples.append({"text": text, "fraud": 0.02, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.03})

    # 13d. Legitimate Utility Bills from BESCOM, Mahavitaran, Tata Power (35 samples - Crucial for zero bias)
    utility_legit = [
        "BESCOM: Dear consumer, your electricity bill of Rs 890 for Account ID 892019 is generated. Due date 20-Nov. Pay online at official bescom.org portal.",
        "Mahavitaran (MSEDCL): Bill of Rs 1,420 for Consumer No 0192819 generated. Due date 24-Nov. Avail prompt payment discount on msedcl.in",
        "Tata Power: Dear customer, payment of Rs 2,150 against bill #98218 received with thanks on 11-Nov-2026. Receipt is available in customer portal.",
        "Indane Gas: Your LPG cylinder refill booking is confirmed. Order #89281. Delivery will be attempted within 2 working days.",
        "Torrent Power: Dear Consumer, scheduled maintenance work in your area tomorrow between 10 AM to 1 PM. Power supply may be temporarily affected."
    ]
    for i in range(35):
        text = utility_legit[i % len(utility_legit)]
        samples.append({"text": text, "fraud": 0.02, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.04})

    # 13e. Legitimate Delivery & Courier Tracking (20 samples)
    c_names = ["BlueDart", "Delhivery", "Amazon", "Flipkart", "DTDC", "Shadowfax"]
    for i in range(20):
        cn = c_names[i % len(c_names)]
        pkg = f"PKG{918230 + i * 47}"
        pin = 1000 + i * 9
        text = f"Your shipment {pkg} from {cn} is out for delivery today. Delivery agent will arrive between 2 PM to 5 PM. Share delivery code {pin} with agent at doorstep."
        samples.append({"text": text, "fraud": 0.03, "category": "none", "brand_imp": 0.02, "cred_req": 0.01, "pay_req": 0.02, "deep_analysis": 0.05})

    # 13f. Everyday Conversational, Work & Meeting Messages (35 samples)
    convos = [
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
    for i in range(35):
        text = convos[i % len(convos)]
        samples.append({"text": text, "fraud": 0.01, "category": "none", "brand_imp": 0.01, "cred_req": 0.01, "pay_req": 0.01, "deep_analysis": 0.02})

    return samples

if __name__ == "__main__":
    data = build_500_samples()
    output_path = os.path.join(os.path.dirname(__file__), "laya_training_corpus.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Generated {len(data)} high-quality samples at {output_path}")
