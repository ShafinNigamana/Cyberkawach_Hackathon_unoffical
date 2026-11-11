"""
Script to generate the comprehensive 200-message benchmark corpus for CyberKawach.
Covers real-world Indian cyber fraud patterns, authentic legitimate communications,
ambiguous edge cases, and adversarial evasion techniques.
"""

import json
from pathlib import Path

def create_benchmark_corpus():
    corpus = []
    
    # ─────────────────────────────────────────────────────────────
    # CATEGORY 1: Fraud - Banking & Financial Phishing (25 cases)
    # ─────────────────────────────────────────────────────────────
    banking_scams = [
        ("SBI NetBanking PAN Block", "Dear SBI Customer, your NetBanking access is BLOCKED due to expired PAN card. Update PAN immediately to avoid permanent suspension: https://sbi-pan-kyc.top/portal -SBI", "VM-SBINB"),
        ("HDFC Reward Points Expiring", "Dear HDFC User, your 9,850 reward points worth Rs 4,925 expire tonight! Redeem directly into your bank account now: https://hdfc-rewards-cash.xyz/claim -HDFC Bank", "AD-HDFCBK"),
        ("ICICI Account Suspended KYC", "URGENT ICICI Alert: Your bank account has been suspended today. Submit AADHAAR verification within 24 hours at https://icici-kyc-update.online or visit nearest branch.", "+919876543210"),
        ("Axis Bank Debit Card Blocked", "Your Axis Bank Debit Card ending 8812 has been blocked due to suspicious activity. Unblock your card online immediately: https://axis-card-unblock.cc/auth", "+919123456789"),
        ("PNB Yono Update APK Lure", "Punjab National Bank: New security mandatory update released. Download PNB One Update APK to continue netbanking: https://pnb-secure-update.club/pnb_one.apk", "+918877665544"),
        ("Kotak 811 KYC Pending", "Dear Kotak 811 user, your full KYC is pending. Your account will be deactivated within 12 hours. Complete KYC: https://kotak-kyc-verify.vip/login", "+917766554433"),
        ("Canara Bank Account Freeze", "Canara Bank Notice: Your savings account has been frozen by order. To unfreeze contact customer care or click: https://canara-helpdesk.top/unfreeze", "+916655443322"),
        ("Bank of Baroda NetBanking Alert", "Bank of Baroda: Dear Customer your BOB netbanking account will be closed today. Click here https://bob-kyc-portal.net/login to update details.", "+919988771122"),
        ("IndusInd Credit Limit Increase", "Congratulations! Your IndusInd Bank credit limit has been enhanced to Rs 5,00,000. Accept offer with zero charges: https://indusind-limit-enhance.biz/apply", "+919012345678"),
        ("Union Bank Document Verification", "Union Bank Alert: Mandatory document re-verification required as per RBI guidelines. Failure leads to debit freeze: https://unionbank-doc-verify.org/portal", "+918123456789"),
        ("Yes Bank Security Alert", "Yes Bank: Unauthorized login attempt detected from IP 185.220.101.5. If not you, secure your account instantly: https://yesbank-secure-auth.info/guard", "+917123456789"),
        ("RBL Bank Card Protection Plan", "Dear RBL Cardholder, avoid Rs 2,999 auto-debit for Card Protection Plan. Click to cancel within 2 hours: https://rbl-cpp-cancel.site/deactivate", "+918234567890"),
        ("Federal Bank KYC Expiry", "Federal Bank: Your KYC has expired. Outward transactions disabled. Restore services now: https://fednet-kyc-restore.xyz/auth", "+919345678901"),
        ("IDFC First Bank Cash Refund", "IDFC First Bank: Erroneous debit of Rs 3,490 detected on card ending 4410. Click to claim instant refund: https://idfc-refund-portal.top/claim", "+918456789012"),
        ("SBI Yono Rewards Claim", "SBI Yono Gift: You have won Rs 7,500 festive gift voucher from SBI. Claim directly into bank: https://sbi-yono-gift.live/claim", "+917567890123"),
        ("HDFC NetBanking Block Notice", "HDFC Alert: Your NetBanking password will expire in 2 hours. Update password to retain access: https://hdfc-netbank-pass.click/reset", "+918678901234"),
        ("ICICI iMobile Mandate Upgrade", "ICICI Bank: Important advisory to re-authenticate your iMobile app to enable international transactions: https://icici-imobile-auth.link/setup", "+919789012345"),
        ("Axis Bank PAN Inoperative", "Dear Customer, your Axis savings account is inoperative due to PAN-Aadhaar de-linking. Link now: https://axis-pan-link.top/submit", "+917890123456"),
        ("Central Bank KYC Deactivation", "Central Bank of India: Your account KYC deactivated. Please submit details online: https://centralbank-kyc-form.site/submit", "+918901234567"),
        ("Bandhan Bank Balance Alert Fake", "Bandhan Bank: Rs 50,000 credited to account XX9012. If transaction failed, dispute immediately: https://bandhan-dispute-cell.online/dispute", "+919012345671"),
        ("Standard Chartered KYC Urgency", "Standard Chartered: Regulatory KYC update mandatory. Click to verify: https://sc-kyc-india.top/verify", "+918012345672"),
        ("Paytm Bank Wallet Block", "Paytm Payments Bank: Your wallet has been suspended. Withdraw remaining balance Rs 8,420: https://paytm-wallet-withdraw.vip/claim", "+917012345673"),
        ("Airtel Payments Bank KYC", "Airtel Payments Bank: Full KYC required to continue UPI payments. Update: https://airtel-bank-kyc.site/kyc", "+916012345674"),
        ("SBI YONO Maintenance Scam", "SBI Notice: Yono server maintenance scheduled. Migrate your profile credentials now to prevent downtime: https://yono-sbi-server-migration.xyz/migrate", "+919123987654"),
        ("Indian Overseas Bank KYC", "IOB Bank: Your A/C is locked. Update KYC details at https://iob-customer-verification.top/kyc to unlock immediately.", "+918123987654")
    ]
    for idx, (name, msg, snd) in enumerate(banking_scams, 1):
        corpus.append({
            "id": f"bench-fraud-bank-{idx:03d}",
            "name": name,
            "category": "fraud_banking_kyc",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["banking", "phishing", "kyc"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 2: Fraud - Utility & Electricity Cutoff Scams (12 cases)
    # ─────────────────────────────────────────────────────────────
    utility_scams = [
        ("BESCOM Power Disconnection Tonight", "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM from the electric office because your previous month bill was not updated. Please immediately contact our electricity officer at 9876543210. -Electricity Office", "+919876543210"),
        ("MSEDCL Bill Payment Disconnect", "MSEDCL Alert: Bill Rs 2,450 unpaid for consumer 04928172910. Power will be cut at 10:00 PM. Call power officer Mr. Sharma at 8765432109 or pay via https://msedcl-bill-pay.xyz", "+918765432109"),
        ("Tata Power Urgent Meter Disconnection", "Tata Power: Your smart meter shows zero balance. Power will be disconnected in 1 hour. Contact helpline 7654321098 immediately to restore connection.", "+917654321098"),
        ("DHBVN Electricity Cut Notice", "DHBVN Notice: Your electricity connection 89201928 will be suspended tonight at 9:00 PM. Call bill manager on 9812345678 to update payment receipt.", "+919812345678"),
        ("BSES Delhi Power Cut Urgent", "BSES Yamuna: Power disconnection order issued for CA 102938475. To avoid line cut contact electricity officer immediately on 9955443322.", "+919955443322"),
        ("Torrent Power Line Disconnection", "Torrent Power: Dear customer your power supply is being disconnected due to non-payment. Call sub-station officer at 9345678901.", "+919345678901"),
        ("Indane Gas Subsidy Discontinuation", "Indane LPG: Your gas cylinder subsidy has been stopped due to outdated Aadhaar linking. Click to update Aadhaar: https://indane-lpg-subsidy.top/kyc", "+918234567812"),
        ("Bharat Gas KYC Suspension", "Bharat Gas Alert: Your LPG connection will be terminated due to pending e-KYC. Call customer care 7890123456 or visit https://bharatgas-kyc.vip", "+917890123456"),
        ("Mahanagar Gas Pipeline Cut", "MGL Notice: Pipeline PNG supply to consumer 8920192 will be disconnected today. Clear outstanding dues via link: https://mgl-billpay-fast.site/pay", "+918901234512"),
        ("UPPCL Power Cut Notice", "UPPCL Electricity Alert: Your connection will be cut today at 9:30 PM. Contact electricity executive at 9456789012 to stop power cut.", "+919456789012"),
        ("Adani Electricity Smart Meter Alert", "Adani Electricity: Smart meter replacement fee of Rs 499 unpaid. Connection disconnection pending. Pay via https://adani-meter-dues.top/bill", "+919567890123"),
        ("PSPCL Punjab Power Disconnect", "PSPCL Alert: Consumer 3002910291 bill pending. Power will be disconnected at 8:00 PM. Call line officer on 9678901234.", "+919678901234")
    ]
    for idx, (name, msg, snd) in enumerate(utility_scams, 1):
        corpus.append({
            "id": f"bench-fraud-utility-{idx:03d}",
            "name": name,
            "category": "fraud_electricity_utility",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["utility", "electricity", "disconnection", "social_engineering"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 3: Fraud - Digital Arrest & Legal Impersonation (10 cases)
    # ─────────────────────────────────────────────────────────────
    legal_scams = [
        ("Mumbai Cyber Cell Digital Arrest", "MUMBAI POLICE CYBER CRIME CELL: Notice of Digital Arrest issued against Aadhaar ending 9812. An illegal parcel containing 200g MDMA was seized at Mumbai airport under your name. Connect immediately on Skype id: mumbai_police_investigation to record statement or face physical arrest.", "+919988112233"),
        ("CBI Court Summons Notice", "CENTRAL BUREAU OF INVESTIGATION (CBI): Legal Summons Case #CBI/2026/8920. Money laundering charges under PMLA Act filed. Join virtual interrogation room within 30 mins: https://cbi-court-virtual.top/case8920", "+918877223344"),
        ("TRAI Mobile Disconnection Order", "TRAI Legal Department: Your mobile number +91-9876543210 is involved in sending 1,200 illegal harassment messages. All telecom identifiers registered with your Aadhaar will be disconnected in 2 hours. Press 9 or call 9123456789.", "+919123456789"),
        ("Supreme Court E-Challan Warrant", "Supreme Court of India E-Committee: Non-bailable arrest warrant issued against you for contempt of court. View case summary and post bail online: https://sci-bail-portal.xyz/warrant", "+917766334455"),
        ("Customs Department Narcotic Parcel", "Indian Customs Department - IGI Airport: Consignment AW-892019 contains unauthorized foreign currency ($50,000) and illegal narcotics. Contact customs officer Mr. R.K. Verma on WhatsApp 9876540123 to resolve penalty.", "+919876540123"),
        ("ED Money Laundering Notice", "Enforcement Directorate (ED): Freezing order issued on all bank accounts under your PAN. Report to video interrogation room immediately: https://ed-investigation-india.top/summons", "+918765430123"),
        ("Delhi Police Cyber Cell Arrest", "Delhi Police Cyber Cell: FIR #492/2026 registered for child sexual abuse material downloading. Digital surveillance active on your IP. Connect to officer via WhatsApp call at 9765430123.", "+919765430123"),
        ("Interpol Red Notice Impersonation", "INTERPOL National Central Bureau New Delhi: Red Notice Alert issued for international wire fraud. Surrender to nearest embassy or contact compliance officer on +919654320123.", "+919654320123"),
        ("Telecom Ministry SIM Block Threat", "Department of Telecommunications (DoT): Final warning. 9 SIM cards issued illegally on your Aadhaar. Call 9543210987 immediately to verify your identity.", "+919543210987"),
        ("Narcotics Control Bureau Summons", "NCB India: Seizure of contraband package destined to your residential address. Connect with investigating inspector on WhatsApp 9432109876 to verify credentials.", "+919432109876")
    ]
    for idx, (name, msg, snd) in enumerate(legal_scams, 1):
        corpus.append({
            "id": f"bench-fraud-legal-{idx:03d}",
            "name": name,
            "category": "fraud_digital_arrest",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["digital_arrest", "police_impersonation", "coercion"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 4: Fraud - Delivery & Courier Customs Scams (10 cases)
    # ─────────────────────────────────────────────────────────────
    courier_scams = [
        ("India Post Address Incomplete Customs", "India Post: Your package #IN982019283 could not be delivered due to incomplete home address. Update address and pay Rs 32 re-delivery fee within 24h: https://indiapost-parcels-update.top/track", "+919811223344"),
        ("Delhivery Customs Clearance Unpaid", "Delhivery: Consignment AWB782910 has arrived at hub with pending customs duty of Rs 48.00. Clear payment now to dispatch out for delivery: https://delhivery-customs-pay.site/clear", "+918822334455"),
        ("Blue Dart Parcel Reschedule Fee", "Blue Dart Express: Delivery failed. Consignee unavailable. Reschedule your delivery slot and confirm delivery PIN: https://bluedart-reschedule-portal.xyz/track", "+917733445566"),
        ("Amazon Delivery Address Verification", "Amazon India: Your order #402-9182918-192810 could not be delivered. Please update your delivery address to avoid return: https://amazon-delivery-update.top/address", "+916644556677"),
        ("DHL Express Duty Tax Pending", "DHL Express: Package #928371928 has duty tax unpaid Rs 120. Pay customs online to avoid package destruction: https://dhl-express-customs.cc/pay", "+919955667788"),
        ("DTDC Tracking Address Missing", "DTDC Courier: Incomplete delivery address for consignment D92810291. Reschedule delivery: https://dtdc-express-track.info/update", "+918866778899"),
        ("FedEx Package On Hold", "FedEx India: Your shipment #829102918 is held at regional transit facility. Pay import surcharge Rs 99: https://fedex-clearance-online.site/pay", "+917777889900"),
        ("Ekart Logistics Address Confirmation", "Ekart Logistics: Delivery partner unable to locate street address. Update GPS coordinates and pay Rs 10 verification charge: https://ekart-address-update.xyz/locate", "+916688990011"),
        ("Shadowfax Delivery Attempt Failed", "Shadowfax: 2nd delivery attempt failed for order. Click here to confirm alternate address: https://shadowfax-delivery-reschedule.top/confirm", "+919999001122"),
        ("India Post Registered Letter Notice", "India Post Alert: Important registered legal notice awaiting delivery. Verify identification proof to release letter: https://indiapost-speedpost-notice.top/verify", "+918888112233")
    ]
    for idx, (name, msg, snd) in enumerate(courier_scams, 1):
        corpus.append({
            "id": f"bench-fraud-courier-{idx:03d}",
            "name": name,
            "category": "fraud_fake_delivery",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["courier", "delivery", "fake_fee"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 5: Fraud - Job, Task & Work From Home Scams (10 cases)
    # ─────────────────────────────────────────────────────────────
    job_scams = [
        ("Part-time YouTube Video Liking Job", "Hi! Earn Rs 2,500 to Rs 8,000 daily by simply liking YouTube videos and rating hotels on Google Maps. No skills required. Daily payout via UPI. Contact manager on Telegram: https://t.me/GlobalTaskHR2026 or WhatsApp +919876501234", "+919876501234"),
        ("Amazon Data Entry Work From Home", "Amazon India Hiring: Part time data entry jobs. Earn Rs 35,000/month working 2 hours/day. Laptop provided. Registration fee Rs 499 only. Pay via PhonePe: hr_recruitment@upi. Contact on WhatsApp 9123450987.", "+919123450987"),
        ("Telegram VIP Investment Task Group", "Earn 300% profit in 15 minutes! Deposit Rs 1,000 and get Rs 3,000 back guaranteed through our crypto trading algorithm. Join VIP channel now: https://t.me/CryptoProfitIndiaVIP", "+918811229900"),
        ("Google Review Rating Part Time Job", "Earn Rs 150 per review! Work from home for Google Partners. Complete 10 reviews daily and earn Rs 1,500. Message HR on WhatsApp: https://wa.me/919988776655?text=JobDetails", "+919988776655"),
        ("Flipkart Merchant Affiliate Task", "Flipkart Merchant Task: Help merchants boost product ratings. Complete prepaid task to receive 30% commission instantly. Join task group: https://chat-invite.top/flipkart_tasks", "+917711228899"),
        ("Typing Job with Registration Fee", "Urgent requirement for offline PDF to Word typing. Rs 250 per page. Earn Rs 45,000 monthly. Security deposit Rs 999 refundable with first salary. Register: https://typing-jobs-india.xyz/apply", "+916611227788"),
        ("Instagram Influencer Assistant Hiring", "Wanted: Instagram Page Assistant. Reply to comments and earn Rs 25,000/month. Only 20 slots left! Contact HR coordinator on Telegram @InstaWorkIndia", "+919922338877"),
        ("Hotel Booking Review Commission", "Make money traveling! Rate luxury hotels on TripAdvisor and earn Rs 3,000/day. Instant withdrawal to bank account. Message coordinator on WhatsApp +918833447766.", "+918833447766"),
        ("Online Captcha Typing Job", "Work from mobile. Solve 100 captchas = Rs 500. Work anytime anywhere. Pay Rs 299 activation fee to start: https://captcha-work-portal.top/register", "+917733446655"),
        ("Overseas Work Visa Job Offer", "Canada Work Permit guaranteed without IELTS! Construction and hospitality vacancies with free food and accommodation. Pay processing fee Rs 5,500 to secure slot: https://canada-visa-express.xyz/apply", "+916633445544")
    ]
    for idx, (name, msg, snd) in enumerate(job_scams, 1):
        corpus.append({
            "id": f"bench-fraud-job-{idx:03d}",
            "name": name,
            "category": "fraud_job_task",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["job_scam", "telegram_task", "advance_fee"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 6: Fraud - Lottery, Prize & UPI Collect Tricks (13 cases)
    # ─────────────────────────────────────────────────────────────
    lottery_upi_scams = [
        ("KBC Lucky Draw 25 Lakhs Prize", "CONGRATULATIONS! Your mobile number has won Rs 25,00,000 in Kaun Banega Crorepati (KBC) Sim Card Lucky Draw 2026. File #KBC-8890. To claim prize money, contact KBC Manager Rana Pratap Singh on WhatsApp: +919876541230. Do not delete message.", "+919876541230"),
        ("Google Pay Anniversary Scratch Card", "🎉 You have won a Google Pay Cash Reward of Rs 1,999! Click link to claim directly into your bank account: https://gpay-festive-reward.site/claim?id=92810", "+919123451230"),
        ("WhatsApp International Lottery Award", "Dear WhatsApp User, your number selected in WhatsApp Global Mega Lottery 2026 for prize of 500,000 USD. Send passport copy and registration fee $100 to claims@whatsapp-lottery.org", "+918823451230"),
        ("Fake PhonePe Cashback Collect Request", "PhonePe: You received a cashback of Rs 2,500 on your recent payment! Enter your UPI PIN on the next screen to accept credit into your account: https://phonepe-cashback-accept.top/claim", "+917723451230"),
        ("UPI Refund Reversal PIN Trick", "Merchant refund of Rs 1,499 approved for failed order. To receive refund, approve collect request in your GPay app and enter UPI PIN: https://upi-merchant-refund.xyz/approve", "+916623451230"),
        ("Car Lucky Draw Winner Notice", "Congratulations! You won a brand new Mahindra Thar in Big Bazaar 25th Anniversary Draw. Pay RTO registration fee Rs 8,500 to dispatch vehicle: https://bigbazaar-car-lucky.top/claim", "+919934561230"),
        ("Govt PM Mudra Loan Instant Approval", "PM Mudra Yojana: Loan of Rs 5,00,000 approved at 2% annual interest with 50% subsidy. No collateral needed. Pay file charge Rs 1,999: https://pm-mudra-loan-portal.site/apply", "+918834561230"),
        ("PM Kisan Samman Nidhi 16th Installment", "PM-KISAN Alert: Your 16th installment of Rs 2,000 is on hold due to missing Aadhaar biometric verification. Complete e-KYC: https://pmkisan-ekyc-portal.top/verify", "+917734561230"),
        ("Income Tax Refund Rs 24,500 Pending", "Income Tax Department: Refund of Rs 24,500 calculated for Assessment Year 2025-26. Submit bank account and NetBanking credentials to disburse: https://incometax-refund-gov.top/claim", "+916634561230"),
        ("Instant 7-Day Loan Blackmail Lure", "Instant Cash in 5 mins! Get Rs 50,000 without CIBIL score. Download RupeeLoan Pro APK: https://instant-rupee-loan.club/rupee.apk. 100% approval.", "+919945671230"),
        ("Electricity Bill Cashback Voucher", "Get 100% cashback on your electricity bill payment! Click to activate your discount coupon: https://bill-cashback-voucher.xyz/activate", "+918845671230"),
        ("Jio 5G Free 1 Year Recharge", "Ambani Family Wedding Gift: Jio offering 1 year free 5G unlimited recharge to all users! Recharge now before offer expires: https://jio-free-recharge-offer.top/claim", "+917745671230"),
        ("Airtel Free 84 Days Data Lure", "Airtel Anniversary Offer: Free 84 days 2GB/day recharge for all prepaid users. Claim your gift: https://airtel-free-recharge.live/gift", "+916645671230")
    ]
    for idx, (name, msg, snd) in enumerate(lottery_upi_scams, 1):
        corpus.append({
            "id": f"bench-fraud-lottery-{idx:03d}",
            "name": name,
            "category": "fraud_lottery_prize",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["lottery", "cashback", "upi_fraud", "advance_fee"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 7: Legitimate - Authentic Indian Banking Alerts (30 cases)
    # ─────────────────────────────────────────────────────────────
    legit_banking = [
        ("SBI UPI Debit Alert", "Dear SBI Customer, your A/C ending in 4921 has been debited by Rs 1,450.00 on 26-Sep-2026. Ref: UPI/626918291048. Avail Bal: Rs 34,820.00. For disputes, visit https://www.onlinesbi.sbi or call 18001234. -State Bank of India", "VM-SBINB"),
        ("HDFC Card Transaction OTP", "481920 is your secret OTP for transaction of Rs 3,200.00 at AMAZON INDIA with HDFC Bank Card ending 1042. OTP valid for 10 mins. Never share OTP or password with anyone, including bank officials.", "AD-HDFCBK"),
        ("ICICI Salary Credit Notification", "Your ICICI Bank A/c XX4019 is credited with Rs 85,000.00 on 30-Sep-2026 towards Salary. Clear Bal: Rs 1,42,850.25. Download statement in iMobile app. -ICICI Bank", "VK-ICICIB"),
        ("Axis Bank ATM Withdrawal Alert", "Rs 5,000.00 withdrawn from Axis Bank ATM at MG Road Bangalore on Card ending 9012. Avail Bal: Rs 42,100.50. If not done by you, SMS BLOCK to 56161600. -Axis Bank", "BZ-AXISBK"),
        ("Kotak Bank UPI Payment Alert", "Paid Rs 350.00 to Starbucks India from Kotak Bank A/C XX8819. UPI Ref: 429102910291. Avail Bal: Rs 18,400.00. Kotak Bank.", "AD-KOTAKB"),
        ("PNB NEFT Credit Alert", "Dear Customer, your PNB Account XX1029 is credited with Rs 12,000.00 through NEFT from MOHAN LAL. Ref: PNBNEFT202609281. -Punjab National Bank", "BP-PNBSMS"),
        ("Canara Bank IMPS Outward", "Dear Customer, Rs 7,500.00 debited from Canara Bank A/C XX5544 via IMPS to RAMESH on 28-Sep-2026. Ref: 427102918291. Avail Bal Rs 29,100. -Canara Bank", "BW-CANBNK"),
        ("Bank of Baroda Card Swipe", "Dear BOB Customer, your Debit Card ending 3321 was swiped for Rs 1,890.00 at D-MART. Available balance: Rs 15,400.00. -Bank of Baroda", "BP-BOBSMS"),
        ("IndusInd NetBanking Login Alert", "IndusInd Bank: Login to NetBanking detected on 28-Sep-2026 at 14:32 IST from Chrome browser. If not done by you, call 18602677777 immediately.", "AD-INDUSB"),
        ("Union Bank Bill Payment Alert", "Union Bank: Payment of Rs 1,200.00 made to BESCOM towards electricity bill. Ref: UBI42819201. Available balance: Rs 22,400. -Union Bank", "BP-UBISMS"),
        ("SBI Cheque Clearing Credit", "SBI: Cheque #891029 for Rs 45,000.00 has been cleared and credited to your A/c XX3344. Total Avail Bal: Rs 88,200.00. -SBI", "VM-SBINB"),
        ("HDFC Auto Debit EMI Deducted", "HDFC Bank Alert: Rs 14,500.00 debited towards Car Loan EMI #LN892019 from A/c ending 2041 on 05-Sep-2026. Bal: Rs 55,200. -HDFC Bank", "AD-HDFCBK"),
        ("ICICI FD Interest Credited", "Dear Customer, interest of Rs 3,420.00 on Fixed Deposit #FD98201 has been credited to your linked Savings Account XX8910. -ICICI Bank", "VK-ICICIB"),
        ("Axis Bank Credit Card Bill Generated", "Axis Bank: Your Credit Card ending 7741 statement for Sep 2026 is generated. Total Dues: Rs 8,420.00, Min Due: Rs 500.00, Due Date: 18-Oct-2026. Pay via Axis Mobile App.", "BZ-AXISBK"),
        ("Kotak 811 Zero Balance Alert", "Your Kotak 811 Account ending 1122 has an available balance of Rs 5,420.00 as on 28-Sep-2026. No minimum balance required. Kotak Mahindra Bank.", "AD-KOTAKB"),
        ("IDFC First Interest Credit", "IDFC FIRST Bank: Monthly interest of Rs 480.00 for your savings account XX9912 has been credited. High interest credited every month! -IDFC First", "AD-IDFCFB"),
        ("RBL Bank Card International Disabled", "RBL Bank: International usage on your Credit Card ending 4410 has been disabled as requested. Manage card limits in RBL MyCard App.", "AD-RBLBNK"),
        ("Federal Bank Fund Transfer Confirmation", "Federal Bank: Transferred Rs 2,000.00 to SURESH via FedMobile on 28-Sep-2026. Txn ID: FT2627182910. Balance: Rs 14,200.00.", "AD-FEDBNK"),
        ("SBI Inward Remittance Alert", "SBI: Inward remittance of EUR 250.00 processed for your A/c XX7722. Equivalent INR 22,450.00 credited after forex conversion. -SBI", "VM-SBINB"),
        ("HDFC Debit Card Block Confirmation", "HDFC Bank: Your Debit Card ending 5512 has been permanently BLOCKED as per your phone banking request. New card will be delivered in 5 working days.", "AD-HDFCBK"),
        ("Standard Chartered Statement Link", "Dear Client, your SCB account e-statement for Aug 2026 has been sent to your registered email address. For queries call priority helpline. -StanChart", "AD-SCBANK"),
        ("Paytm Wallet Add Money", "Rs 1,000.00 added to your Paytm Wallet from HDFC Bank A/C ending 4019. Updated wallet balance: Rs 1,450.00. UPI Ref: 428190291029.", "AD-PAYTMB"),
        ("Aadhaar OTP Authentication", "291048 is your Aadhaar verification OTP for authentication at UIDAI e-Gov portal. Valid for 10 minutes. Do not share OTP with anyone. -UIDAI", "AD-UIDAI"),
        ("IRCTC Ticket Booking OTP", "892019 is OTP for IRCTC login. Never share your IRCTC password or OTP with anyone. -IRCTC", "AD-IRCTC"),
        ("CoWIN Vaccine Registration OTP", "Your OTP for CoWIN registration is 492019. Valid for 3 minutes. -National Health Authority, Govt of India", "AD-NHAGOV"),
        ("Amazon Delivery OTP Verification", "4829 is your Amazon delivery verification code for package #402-9182918. Share this OTP with the delivery associate only upon receiving package.", "AD-AMAZON"),
        ("Zomato Order Confirmation Alert", "Order #982918 for Rs 420.00 confirmed at Biryani Blues. Track live order status in Zomato app. Enjoy your meal!", "AD-ZOMATO"),
        ("Swiggy Instamart Order Out for Delivery", "Your Swiggy Instamart order is out for delivery with partner Ramesh! Track your delivery partner in app.", "AD-SWIGGY"),
        ("Flipkart Delivery PIN Code", "Your Flipkart delivery agent is arriving today with package FMPC892019. Delivery PIN is 9182. Share only when receiving parcel.", "AD-FLIPKT"),
        ("JioFiber Bill Payment Receipt", "JioFiber: Received Rs 824.82 for Service ID 08049281928 via AutoPay on 26-Sep-2026. View invoice in MyJio app. -Reliance Jio", "AD-JIOFBR"),
        ("FASTag Low Balance Alert", "NHAI FASTag: Low balance warning for tag on KA04ME1234. Available balance Rs 65.00. Minimum threshold is Rs 100. Recharge tag at https://fastag.ihmcl.com or bank app.", "AD-FASTAG"),
        ("IRCTC Cancellation Refund Credited", "IRCTC Refund: Rs 1,840.00 for cancelled PNR 4291029102 credited back to your original payment mode on 26-Sep-2026. Txn ID: REF26102910. -IRCTC", "AD-IRCTC"),
        ("SBI Fixed Deposit Auto-Renewal", "SBI: Your Term Deposit #3920192810 for Rs 1,00,000.00 has matured and auto-renewed for 1 year at 6.80% p.a. Maturity date: 28-Sep-2027. -State Bank of India", "VM-SBINB"),
        ("ICICI Credit Card Online OTP", "749201 is your OTP for payment of Rs 1,499.00 at BOOKMYSHOW with ICICI Bank Card ending 4019. Valid for 5 mins. Do not share OTP with anyone.", "VK-ICICIB"),
        ("Axis Bank E-Mandate Registration", "Axis Bank: E-Mandate #MN892019 for Netflix Entertainment Rs 649/month successfully registered on Debit Card ending 9012. Manage mandates in Axis Mobile app.", "BZ-AXISBK"),
        ("HDFC Mutual Fund SIP Debit", "HDFC Bank: Rs 5,000.00 debited towards Mutual Fund SIP for HDFC Top 100 Fund from A/C XX4019 on 25-Sep-2026. Available balance: Rs 48,200.00. -HDFC Bank", "AD-HDFCBK"),
        ("Canara Bank Pension Credit", "Canara Bank: Central Pension of Rs 32,450.00 for Sep 2026 credited to Pension Account ending 5544 on 28-Sep-2026. Avail Bal Rs 52,100. -Canara Bank", "BW-CANBNK"),
        ("Kotak Cheque Book Dispatched", "Kotak Bank: Cheque book containing 25 leaves dispatched via Blue Dart AWB 429102910 for A/C XX8819. Deliverable in 3 working days. Kotak Mahindra Bank.", "AD-KOTAKB"),
        ("PNB Kisan Credit Card Subsidy", "PNB: Interest subvention subsidy of Rs 4,200.00 credited to your KCC Account XX1029 under Govt scheme on 24-Sep-2026. -Punjab National Bank", "BP-PNBSMS"),
        ("Bank of Baroda Passbook Summary", "BOB: Summary for A/C XX3321. Total Credits this month: Rs 64,000.00, Total Debits: Rs 28,450.00. Current Bal: Rs 45,950.00. -Bank of Baroda", "BP-BOBSMS")
    ]
    for idx, (name, msg, snd) in enumerate(legit_banking, 1):
        corpus.append({
            "id": f"bench-legit-bank-{idx:03d}",
            "name": name,
            "category": "legitimate_banking_alerts",
            "ground_truth": "BENIGN",
            "expected_risk": ["LOW", "UNKNOWN"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["banking", "legitimate", "otp", "debit_alert"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 8: Legitimate - Utilities, Courier & Telecom (25 cases)
    # ─────────────────────────────────────────────────────────────
    legit_utilities = [
        ("India Post Authentic Tracking", "Your India Post consignment EK928371928IN has reached Bangalore NSH. Expected delivery by 27-Sep-2026. Track your consignment at https://www.indiapost.gov.in/_layouts/15/dpt/track.aspx", "AD-POSTIN"),
        ("BESCOM Official Payment Receipt", "Dear Consumer, payment of Rs 1,840 for BESCOM Account ID 8920192810 received successfully on 25-Sep-2026 via BBPS. Download official receipt from https://bescom.karnataka.gov.in -BESCOM", "AD-BESCOM"),
        ("Delhivery Out For Delivery", "Delhivery: Shipment 78392019281 from Nykaa is out for delivery with courier partner Sunil (9876500000). Track: https://www.delhivery.com/track/package/78392019281", "AD-DLHVRY"),
        ("Blue Dart Shipment Delivered", "Blue Dart: Consignment 429182910 delivered on 27-Sep-2026 at 16:45 to SECURITY. Thank you for choosing Blue Dart. Track: https://www.bluedart.com", "AD-BLUDART"),
        ("Tata Power Monthly Bill Reminder", "Tata Power-DDL: Bill for CA 60019281029 of Rs 2,140.00 generated. Due date: 08-Oct-2026. Pay online to avail 1% rebate at https://www.tatapower-ddl.com", "AD-TPDDL"),
        ("BSES Rajdhani Bill Notification", "BSES Rajdhani: Electricity bill for CA 100291029 of Rs 1,420.00 is due on 05-Oct-2026. Pay seamlessly via official BSES mobile app.", "AD-BSESDEL"),
        ("Mahanagar Gas Invoice Receipt", "MGL: Received Rs 680.00 towards PNG bill for Consumer #20192810 on 24-Sep-2026. Invoice available at https://www.mahanagargas.com", "AD-MGLGAS"),
        ("Indane Refill Booking Confirmation", "Your Indane LPG cylinder refill booking #92810291 is confirmed for Consumer #89201. Expected delivery in 2 working days. -Indian Oil", "AD-IOCLPG"),
        ("Bharat Gas Subsidy Credit Alert", "LPG Subsidy of Rs 200.00 for booking ref #892019 has been credited to your Aadhaar linked bank account on 22-Sep-2026. -BPCL", "AD-BPCLPG"),
        ("HP Gas Cash Memo Notification", "HP Gas: Cash memo #CM892019 for Rs 853.00 generated for order #892019. Track refill delivery in HP Pay app. -HPCL", "AD-HPCLPG"),
        ("Jio Prepaid Plan Expiry Reminder", "Dear Jio user, your daily 1.5GB plan on 9876543210 expires in 3 days on 01-Oct-2026. Recharge with Rs 299 to continue unlimited 5G in MyJio app.", "AD-JIOSMS"),
        ("Airtel Unlimited Pack Activated", "Airtel: Recharge of Rs 719 successful for 9812345678. Unlimited calls, 1.5GB/day, 84 days validity activated. Manage pack in Airtel Thanks app.", "AD-AIRTEL"),
        ("Vodafone Idea Bill Receipt", "Vi: Payment of Rs 599.00 received towards postpaid bill for 9922334455 on 25-Sep-2026. Next bill date 20-Oct-2026. Vi App.", "AD-VISMS"),
        ("ACT Fibernet Bill Due Notice", "ACT Fibernet: Monthly broadband bill for Account #10492810 of Rs 1,178.82 generated. Pay before 04-Oct-2026 at https://www.actcorp.in to avoid interruption.", "AD-ACTFBR"),
        ("Tata Play DTH Balance Notification", "Tata Play: Your subscriber account 1092810291 balance is Rs 45.00. Recharge by 30-Sep-2026 to ensure uninterrupted TV entertainment. Tata Play App.", "AD-TATAPLY"),
        ("Airtel DTH Recharge Successful", "Airtel Digital TV: Customer ID 3009281920 recharged with Rs 350.00. Next recharge due on 28-Oct-2026. Thank you for choosing Airtel.", "AD-AIRDTH"),
        ("NDMA Earthquake Disaster Alert", "NDMA Severe Weather Warning: Heavy rainfall and thunderstorm expected in Coastal Karnataka for next 24 hours. Stay indoors, avoid waterlogged areas. Helpline: 1077. -National Disaster Management Authority", "ND-DISAST"),
        ("Election Commission Voter Information", "Election Commission of India: National Voter Service Portal enables voters to search name in electoral roll and download digital e-EPIC card from https://voters.eci.gov.in -ECI", "AD-ECISMS"),
        ("Har Ghar Tiranga Official Campaign", "JG-REGINF-G\nThis Independence Day, celebrate 150 years of Vande Mataram with Har Ghar Tiranga. Hoist Tiranga at home & upload your selfie on https://harghartiranga.com/\nAdvisory as per the Telecommunications Act 2023. Acquiring SIMs or telecom identifiers by fraud, cheating or personation is a punishable offence under the Telecommunications Act, 2023 with imprisonment up to 3 years, a fine up to Rs. 50 lakhs or both.", "JG-REGINF-G"),
        ("Income Tax Official Return Processed", "Income Tax Department: Intimation under Section 143(1) for PAN ABCDE1234F for AY 2025-26 has been processed. Download intimation notice from official e-filing portal https://www.incometax.gov.in", "AD-INCOMT"),
        ("EPFO Provident Fund Balance", "Dear Member, your EPF balance for UAN 100928192019 is Rs 3,42,850.00. Contribution of Rs 6,800.00 for Aug 2026 received from employer. -EPFO", "AD-EPFOHO"),
        ("Passport Seva Kendra Appointment", "Passport Seva: Appointment confirmed for Application ARN 26-1029384750 at PSK Lalbagh Bangalore on 04-Oct-2026 at 10:15 AM. Carry original documents. -Govt of India", "AD-PASSPT"),
        ("FASTag Toll Deduction Alert", "NHAI FASTag: Toll of Rs 85.00 deducted at Devanahalli Plaza for vehicle KA-04-ME-1234 on 28-Sep-2026 at 09:12. Balance: Rs 420.00. -IHMCL", "AD-FASTAG"),
        ("IRCTC Train Charting Notification", "IRCTC: Charting done for Train 12658 Chennai Express for journey on 29-Sep-2026. PNR: 4291029102. Coach: B3, Berth: 42 (MB). -IRCTC", "AD-IRCTC"),
        ("Swiggy Grocery Delivered", "Your Instamart order has been delivered! Rate your delivery partner Ramesh in the Swiggy app. Need help? Visit Help Center in app.", "AD-SWIGGY"),
        ("DigiLocker Driving License Issued", "DigiLocker: Transport Dept Karnataka has issued your Driving License #DL042019281 to your DigiLocker. Access verified document at https://digilocker.gov.in", "AD-DGLCKR"),
        ("Indane LPG Delivered Successfully", "Your Indane 14.2 kg LPG cylinder refill has been delivered today to Consumer #89201. For complaints or refill booking visit https://cx.indianoil.in", "AD-IOCLPG"),
        ("Indian Railways PNR Confirmed", "IRCTC PNR Alert: PNR 4291029102 for Train 12008 Shatabdi Express is now CONFIRMED. Coach C2, Seat 45. Download ticket from https://www.irctc.co.in", "AD-IRCTC"),
        ("CoWIN Precaution Dose Reminder", "CoWIN: Precaution dose of COVID-19 vaccine is now due for Beneficiary ID 892019281. Book slot on https://cowin.gov.in -Ministry of Health", "AD-NHAGOV"),
        ("BESCOM Scheduled Maintenance Notice", "BESCOM Advisory: Scheduled grid maintenance on 02-Oct-2026 from 10 AM to 2 PM in Indiranagar feeder area. Power supply will be interrupted. For queries call 1912.", "AD-BESCOM")
    ]
    for idx, (name, msg, snd) in enumerate(legit_utilities, 1):
        corpus.append({
            "id": f"bench-legit-util-{idx:03d}",
            "name": name,
            "category": "legitimate_utilities_courier",
            "ground_truth": "BENIGN",
            "expected_risk": ["LOW", "UNKNOWN"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["utility", "courier", "telecom", "gov", "legitimate"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 9: Edge Cases & Ambiguous Messages (30 cases)
    # ─────────────────────────────────────────────────────────────
    edge_cases = [
        ("Pre-Approved Bank Personal Loan Offer", "Dear Customer, you are pre-approved for an HDFC Bank Personal Loan up to Rs 10 Lakhs with attractive interest rates. To apply, visit your nearest HDFC branch or login to netbanking at https://www.hdfcbank.com. T&C apply.", "AD-HDFCBK"),
        ("Amazon Great Indian Festival Sale Alert", "Great Indian Festival starts midnight! Up to 80% off on electronics, mobiles and home appliances. Add your wishlist items to cart now on Amazon app. Shop early before stocks run out!", "AD-AMAZON"),
        ("Dominos Weekend Pizza BOGO Offer", "Weekend Special! Buy 1 Medium Pizza and get 1 Free today. Use code BOGO at checkout on Dominos App. Offer valid till 11 PM tonight. Order now!", "AD-DOMINO"),
        ("School Monthly Fee Reminder", "DPS Bangalore South: Dear Parent, tuition fee for Quarter 3 for student Aditi Sharma (Class 8-B) is due on 10-Oct-2026. Kindly pay via the official parent school portal.", "AD-DPSBLR"),
        ("Insurance Renewal Reminder", "HDFC Life: Your Life Insurance Policy #18291029 is due for renewal premium Rs 24,000 on 15-Oct-2026. Pay online at https://www.hdfclife.com or visit branch.", "AD-HDFCLI"),
        ("Hospital Dental Checkup Appointment", "Manipal Hospital: Your dental checkup with Dr. Sneha Rao is scheduled for tomorrow 29-Sep-2026 at 4:30 PM. For rescheduling call 080-22221111.", "AD-MANIPL"),
        ("Gym Membership Expiry Alert", "Cult.fit: Your CultPass Elite membership expires in 7 days on 05-Oct-2026. Renew early to lock in your existing subscription rate. Open Cult app.", "AD-CULTFT"),
        ("BookMyShow Movie Ticket Confirmed", "Booking confirmed! 2 tickets for Avengers at PVR Forum Koramangala on 30-Sep-2026 at 7:15 PM. Show your booking QR code at entrance.", "AD-BMSHOW"),
        ("Uber Ride Receipt", "Your Tuesday evening trip with Uber was Rs 284.50. We hope you enjoyed your ride. View your trip receipt in the Uber app.", "AD-UBERIN"),
        ("Ola Auto Booking OTP", "4820 is your Ola Auto OTP for ride with driver Suresh (Auto KA-01-AB-1234). Share OTP with driver when boarding auto.", "AD-OLACAB"),
        ("Lenskart Eyewear Buy 1 Get 1", "Lenskart Gold Member Exclusive: Buy 1 Get 1 Free on all eyeglasses & sunglasses! Visit nearest store or shop on lenskart.com with code GOLD.", "AD-LENSKT"),
        ("Apollo Pharmacy Order Dispatched", "Apollo 24|7: Your medicine order #MED982019 is dispatched and will be delivered within 2 hours. Delivery partner assigned. Apollo Pharmacy.", "AD-APOLLO"),
        ("Myntra End of Reason Sale Lure", "Myntra EORS: Flat 50-80% off on top fashion brands! Extra 10% instant discount on ICICI Bank cards. Shop now on Myntra app.", "AD-MYNTRA"),
        ("MakeMyTrip Flight Web Check-in", "MakeMyTrip: Web check-in is now open for IndiGo flight 6E-452 from BLR to DEL departing tomorrow at 06:15 AM. Check-in on IndiGo website.", "AD-MMTRIP"),
        ("Urban Company Service Partner Assigned", "Urban Company: Professional AC Service scheduled for today between 11 AM - 1 PM. Partner Manoj will reach your location shortly.", "AD-URBANP"),
        ("Feedback Survey Request with Shortlink", "Thank you for shopping at Lifestyle! How was your experience today? Rate us in this 30-second survey: https://feedback-lifestyle.in/s/98201", "AD-LFSTYL"),
        ("Bank Branch Visit KYC Reminder", "Dear Customer, RBI mandates periodic KYC update. Please visit your home branch SBI MG Road with original Aadhaar and PAN before 30-Nov-2026. -SBI", "VM-SBINB"),
        ("Car Service Service Due Reminder", "Maruti Suzuki Service: Your Swift Dzire KA05MB1234 is due for periodic maintenance service. Book appointment at Mandovi Motors: 080-49201928.", "AD-MARUTI"),
        ("Credit Card Upgrade Offer Official", "ICICI Bank: You are eligible to upgrade your existing card to Sapphiro Credit Card with airport lounge access. Check eligibility in iMobile app.", "VK-ICICIB"),
        ("Society Maintenance Bill Notice", "Prestige Shantiniketan RWA: Maintenance dues of Rs 6,800 for Flat 402 for Oct 2026 generated. Pay via MyGate app before 10th to avoid late fee.", "AD-MYGATE"),
        ("Airtel Thanks Gold Benefit", "Airtel Thanks: Claim your complimentary Disney+ Hotstar 3-month subscription today through the Rewards section of Airtel Thanks app.", "AD-AIRTEL"),
        ("Google Security Verification Code", "G-892019 is your Google verification code. Never share your code with anyone.", "Google"),
        ("GitHub Password Reset Verification", "Use verification code 492810 to reset your GitHub account password. This code expires in 15 minutes.", "GitHub"),
        ("Microsoft Account Security Code", "Microsoft account security code: 829104. If you didn't request this code, you can safely ignore this message.", "Microsoft"),
        ("LinkedIn Two-Factor Authentication", "Your LinkedIn verification code is 281920. Do not share this code with anyone.", "LinkedIn"),
        ("Cred Credit Card Bill Due Reminder", "CRED Alert: Your Axis Bank Credit Card bill of Rs 14,290 is due in 3 days. Pay on CRED to earn cashback and avoid late fees.", "AD-CRED"),
        ("PolicyBazaar Term Insurance Quote", "PolicyBazaar: 1 Crore Term Life Insurance at Rs 490/month for 30-year non-smoker. Compare quotes from 15 top insurers at policybazaar.com", "AD-POLBZR"),
        ("Zerodha Quarterly Settlement Payout", "Zerodha: Quarterly funds settlement of unutilized trading balance Rs 12,450.00 initiated to your primary bank account XX4019 on 26-Sep-2026.", "AD-ZERODH"),
        ("Groww Mutual Fund NAV Allotment", "Groww: Your order for Nippon India Small Cap Fund executed. Units allotted at NAV Rs 142.85. Check your portfolio on Groww app.", "AD-GROWW"),
        ("Netmeds Medicine Refill Alert", "Netmeds: Time to refill your monthly diabetes medication prescription. Flat 20% off on your repeat order with code REFILL20 on Netmeds.", "AD-NTMEDS")
    ]
    for idx, (name, msg, snd) in enumerate(edge_cases, 1):
        corpus.append({
            "id": f"bench-edge-ambig-{idx:03d}",
            "name": name,
            "category": "edge_cases_ambiguous",
            "ground_truth": "AMBIGUOUS",
            "expected_risk": ["LOW", "MEDIUM"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["promotional", "commercial", "edge_case", "otp"]
        })

    # ─────────────────────────────────────────────────────────────
    # CATEGORY 10: Adversarial Evasion & Anti-Analysis (20 cases)
    # ─────────────────────────────────────────────────────────────
    adversarial_cases = [
        ("Zero-Width Smuggled Banking KYC", "Dear SBI\u200bCustomer, your\u200ca/c\u200dis\u200bblocked. Update\u200bKYC\u200bnow: https://sbi-verify.top/portal", "+919876543210"),
        ("Cyrillic Homoglyph Brand SBI Domain", "Dear Customer, update your profile at https://www.sb\u0456.com/verify to avoid account closure.", "+919123456789"), # Cyrillic small 'i' (U+0456)
        ("Leetspeak K-Y-C Urgency Bypass", "URGENT: Your A-C-C-O-U-N-T is bl0cked. Submit K_Y_C immediately to unbl0ck: https://bank-safety-fix.xyz", "+918877665544"),
        ("Anchor Mismatch Hyperlink Lure", "Click <a href='https://malicious-harvesting.site/login'>https://www.onlinesbi.sbi</a> to secure your banking profile.", "+917766554433"),
        ("Zero-Width Smuggled Electricity Threat", "BESCOM\u200cElectricity\u200bPower will be\u200ddisconnected at 9:30 PM. Call officer\u200b9876543210 immediately.", "+919876543210"),
        ("Homoglyph Google Typosquat", "Congratulations from G\u043e\u043egle! You won Rs 10,00,000. Claim at https://g\u043e\u043egle-reward.top/win", "+916655443322"), # Cyrillic 'о' (U+043E)
        ("Space-Padded Phishing Keyword Evasion", "D e a r  C u s t o m e r, y o u r  P A N  c a r d  h a s  e x p i r e d. U p d a t e: https://pan-kyc-verify.top/id", "+919988771122"),
        ("Punycode Encoded Phishing Domain", "Verify your HDFC NetBanking session: https://xn--hdfcbnk-9va.com/login now to avoid lockout.", "+919012345678"),
        ("Double Slash URL Redirection Trick", "Your package is held. View details: https://www.indiapost.gov.in@track-customs-duty.top/verify", "+918123456789"),
        ("Hex Encoded IP Address Phishing", "SBI Alert: Immediate action required. Connect to security host: http://0x7F000001/sbi/auth", "+917123456789"),
        ("Zero-Width Space OTP Smuggling", "Never\u200bshare\u200byour\u200bOTP. To cancel fraudulent charge of Rs 9,999 click: https://cancel-charge-refund.top/auth", "+918234567890"),
        ("Full-Width Unicode Character Lure", "Ｄｅａｒ Ｃｕｓｔｏｍｅｒ， ｙｏｕｒ ｂａｎｋ ａｃｃｏｕｎｔ ｉｓ ｆｒｏｚｅｎ． Ｃｌｉｃｋ https://bank-unfreeze.top", "+919345678901"),
        ("Disguised IP Octal Phishing URL", "NetBanking Security Alert: Update your profile at http://0177.0.0.1/verify before midnight.", "+918456789012"),
        ("Homoglyph Amazon Impersonation", "Your Am\u0430zon parcel could not be delivered. Pay Rs 25 redelivery at https://am\u0430zon-parcel.top/track", "+917567890123"), # Cyrillic 'а' (U+0430)
        ("Subdomain Brand Masking Evasion", "Legitimate portal access: https://www.onlinesbi.sbi.banking-portal-secure-update.top/login", "+918678901234"),
        ("Mixed Character Script Smuggling", "ICICI B\u0430nk: Account debited Rs 49,000. If unauthorized, dispute at https://icici-fraud-dispute.cc", "+919789012345"),
        ("Right-to-Left Override Character Smuggling", "Important bank document: statement_\u202Ecod.exe uploaded for your review.", "+917890123456"),
        ("Soft Hyphen Word Fragmentation", "Up\xaddate your K\xadY\xadC now at https://kyc-direct-update.top/sbi to avoid account closure.", "+918901234567"),
        ("Zero-Width Non-Joiner Injection", "Your account is s\u200ct\u200co\u200cp\u200cp\u200ce\u200cd. Complete KYC: https://unblock-account-fast.top/sbi", "+919012345671"),
        ("Encoded Shortlink Redirection Evasion", "Dear user, claim your cash reward: http://bit.ly/3xSecFake -> https://malicious-credential-stealer.top", "+918012345672")
    ]
    for idx, (name, msg, snd) in enumerate(adversarial_cases, 1):
        corpus.append({
            "id": f"bench-adv-evasion-{idx:03d}",
            "name": name,
            "category": "adversarial_evasion",
            "ground_truth": "MALICIOUS",
            "expected_risk": ["HIGH", "CRITICAL"],
            "message": msg,
            "sender": snd,
            "user_state": "received",
            "tags": ["adversarial", "homoglyph", "zero_width", "evasion", "phishing"]
        })

    return corpus

if __name__ == "__main__":
    cases = create_benchmark_corpus()
    out_path = Path(__file__).resolve().parent.parent / "fixtures" / "benchmark_dataset_200.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(cases, f, indent=2, ensure_ascii=False)
    print(f"Generated {len(cases)} benchmark cases saved to {out_path}")
