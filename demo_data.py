"""
demo_data.py - Curated Vishing & Legitimate Sample Conversations
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

Provides pre-loaded, realistic phone conversation transcripts representing
different risk profiles (Normal, Suspicious, Critical Vishing).
Enables instant demonstration without needing live audio or Whisper execution.
"""

from typing import List, Dict, Any

DEMO_CONVERSATIONS: List[Dict[str, Any]] = [
    {
        "id": "demo_normal",
        "title": "Sample 1: Legitimate Logistics Delivery Confirmation",
        "expected_risk": "LOW",
        "expected_score_range": "0 - 20",
        "simulated_caller_id": "+91 98230-11234 (BlueDart Courier Partner)",
        "duration": "1m 15s",
        "description": (
            "A standard polite call from a verified delivery associate confirming recipient availability "
            "for an online shopping order. No credentials, PINs, or urgent payments are requested."
        ),
        "transcript": (
            "Agent: Hello, good afternoon. Am I speaking with Mr. Sharma?\n"
            "Customer: Yes, speaking. Who is this?\n"
            "Agent: Sir, I am calling from BlueDart Express delivery. I have a package from Amazon "
            "scheduled for delivery at Flat 402, Green Valley Apartments today.\n"
            "Customer: Oh yes, I ordered a book and some stationary.\n"
            "Agent: Yes sir. Are you currently available at home to receive the parcel, or should I leave "
            "it with your building security guard?\n"
            "Customer: I will be home for the next two hours, so you can deliver it directly.\n"
            "Agent: Perfect, sir. Our delivery associate Rohan will reach your address in about 25 minutes. "
            "No signature or payment is required as this was already pre-paid online. Thank you and have a good day!\n"
            "Customer: Thank you, see you soon."
        ),
        "key_characteristics": [
            "Polite, respectful tone with no high-pressure coercion",
            "Confirms pre-existing business interaction initiated by customer",
            "Zero requests for financial data, passwords, OTPs, or remote software",
            "Accepts flexible customer instructions without panic or ultimatums"
        ]
    },
    {
        "id": "demo_suspicious",
        "title": "Sample 2: Suspicious Credit Card Cashback & Processing Fee Lure",
        "expected_risk": "MEDIUM",
        "expected_score_range": "40 - 65",
        "simulated_caller_id": "+91 80112-99881 (Unverified Telemarketing / Rewards Desk)",
        "duration": "1m 40s",
        "description": (
            "Caller claims victim has won an unredeemed cashback reward of Rs 8,000 expiring today. "
            "Demands a refundable processing fee of Rs 199 and imposes artificial urgency to rush payment."
        ),
        "transcript": (
            "Caller: Good afternoon, am I speaking with the cardholder? I am calling from the Customer Loyalty Rewards Desk.\n"
            "Customer: Yes, who is this?\n"
            "Caller: Sir, congratulations! You have been selected for an exclusive cashback reward of 8,000 rupees on your credit card reward points.\n"
            "Customer: Really? I don't remember applying for any contest.\n"
            "Caller: You did not have to apply, sir. This is accumulated reward points redemption. However, these points are expiring in the next few minutes.\n"
            "Customer: Okay, can you just credit it to my account directly?\n"
            "Caller: Yes sir, but according to portal regulations, to process this credit card cashback reward, there is a small refundable deposit processing charge of 199 rupees.\n"
            "Customer: Why should I pay a fee to receive cashback? That sounds odd.\n"
            "Caller: Sir, the 199 rupees is completely refundable and will be added back into your 8,000 rupees deposit. You must complete this within 30 minutes before the limited time window closes today.\n"
            "Customer: Can I check this on my mobile banking app first?\n"
            "Caller: No sir, this desk offer will expire. You must act now without delay, otherwise your unclaimed reward points will be permanently cancelled."
        ),
        "key_characteristics": [
            "Unsolicited Financial Lure: Unearned cashback and credit card reward points",
            "Advance Fee Demand: Demands upfront 'refundable processing deposit' of Rs 199",
            "Artificial Urgency: 'Within 30 minutes', 'Act now without delay', 'Expiring today'",
            "Absence of overt coercion: No fake police threats or AnyDesk demands, placing it squarely in Medium Risk"
        ]
    },
    {
        "id": "demo_phishing",
        "title": "Sample 3: Critical Vishing - Bank Fraud Impersonation & Remote Access",
        "expected_risk": "HIGH",
        "expected_score_range": "75 - 100",
        "simulated_caller_id": "+91 22 4567 8900 (Spoofed: SBI Fraud Prevention Dept)",
        "duration": "2m 30s",
        "description": (
            "High-severity social engineering attack. Attacker impersonates bank fraud vigilance officer, "
            "fabricates an unauthorized Rs 85,000 debit, threatens police FIR and account seizure, instructs "
            "victim to install AnyDesk for remote control, demands immediate 6-digit OTP, and enforces secrecy."
        ),
        "transcript": (
            "Attacker: Urgent call from State Bank of India Head Office Fraud Prevention Department! "
            "I am Officer Rajesh Kumar from the Anti-Fraud Vigilance Cell speaking. Is this the registered cardholder?\n"
            "Victim: Yes, this is he! What happened? Is something wrong?\n"
            "Attacker: Sir, an unauthorized international transaction of 85,000 rupees was just attempted on your credit card "
            "from Mumbai for purchasing overseas foreign exchange! Did you authorize this transaction?\n"
            "Victim: No! Absolutely not! I am in Delhi right now. Please stop it immediately!\n"
            "Attacker: Do not panic sir, but you must act right now without delay! If we do not cancel this transaction within 10 minutes, "
            "the money will leave the country, your account will be blocked and frozen, and a police FIR will be filed against your name "
            "for suspicious money laundering under the Cyber Crime Cell!\n"
            "Victim: Oh my god, please tell me what I have to do. Please help me cancel it!\n"
            "Attacker: Listen very carefully. Go to your mobile Google Play Store immediately and install AnyDesk Remote Support application. "
            "Do not hang up! Stay on the line! This is a confidential investigation so do not inform anyone or talk to your local branch manager.\n"
            "Victim: Okay, I am downloading AnyDesk. It shows a 9-digit code.\n"
            "Attacker: Tell me the 9-digit code and grant permission so our security department can reverse the charge. "
            "Also, we are generating an emergency cancellation token. You will receive an SMS containing a 6-digit OTP verification code. "
            "Read out the OTP to me immediately as soon as you receive it so I can abort the illegal transaction!\n"
            "Victim: The SMS says 'Do not share this OTP with anyone, not even bank employees'...\n"
            "Attacker: Sir, that is an automated robot message! I am the senior security officer handling your emergency case! "
            "Share the OTP right now or your account will be permanently terminated and you will face legal consequences!"
        ),
        "key_characteristics": [
            "Authority Impersonation: Claims to be Bank Anti-Fraud Vigilance Officer",
            "Psychological Intimidation: Threatens police FIR, money laundering charges, account freezing",
            "Extreme Time Pressure: 'Within 10 minutes', 'Act right now without delay'",
            "Remote Access Hijacking: Coerces victim to install AnyDesk screen-sharing tool",
            "Direct Credential Harvesting: Demands victim read out the 6-digit SMS OTP",
            "Victim Isolation: Enforces confidentiality ('do not inform branch manager or anyone')"
        ]
    }
]


def get_demo_by_id(demo_id: str) -> Dict[str, Any]:
    """Retrieves a specific demo conversation by ID."""
    for demo in DEMO_CONVERSATIONS:
        if demo["id"] == demo_id:
            return demo
    return DEMO_CONVERSATIONS[0]
