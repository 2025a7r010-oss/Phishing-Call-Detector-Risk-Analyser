"""
analyzer.py - Rule-Based Phishing Call & Risk Analysis Engine
AI-Based Phishing Call Detection and Risk Analyzer
2nd-Year B.Tech CSE Cyber Security Mini-Project

This module implements a transparent, explainable, rule-based risk analysis
engine designed to evaluate call transcripts for social engineering and vishing patterns.
"""

import re
from typing import Dict, List, Any, Tuple


class PhishingAnalyzer:
    """
    Transparent rule-based risk analysis engine for voice phishing (vishing).
    
    Evaluates call transcripts against weighted contextual indicators across
    multiple cybersecurity attack categories:
    - Credential & Authentication Theft (OTP, PIN, Password, CVV)
    - Financial Extortion & Unauthorized Payment Demands
    - Authority & Institution Impersonation (Banks, Police, Telecom, Government)
    - Psychological Coercion & Intimidation (Legal action, Account blockage)
    - Artificial Urgency & Time Pressure
    - Remote Access Trojan (RAT) & Malicious Software Coercion
    - Social Engineering Isolation & Secrecy Demands
    - Unsolicited Financial Lures & Fake Refunds
    """

    # Risk Level Thresholds
    LOW_THRESHOLD_MAX = 30
    MEDIUM_THRESHOLD_MAX = 70
    HIGH_THRESHOLD_MIN = 71

    # Definition of attack categories and contextual pattern rules
    # Weight corresponds to severity score contribution (0-100 scale)
    INDICATOR_RULES = [
        {
            "id": "CRED_OTP_PIN",
            "name": "Credential Harvesting (OTP / PIN / CVV)",
            "category": "Credential Theft",
            "severity": "CRITICAL",
            "weight": 35,
            "patterns": [
                r"\b(share|tell|verify|enter|read|provide|give)\b.{0,30}\b(otp|one[\s-]time\s*password|verification\s*code|security\s*code)\b",
                r"\b(otp|one[\s-]time\s*password|verification\s*code)\b.{0,25}\b(sent|received|mobile|phone|sms|message)\b",
                r"\b(upi[\s-]pin|atm[\s-]pin|secret\s*pin|security\s*pin|card\s*pin)\b",
                r"\b(cvv|cvv2|card\s*verification\s*value|3[\s-]digit\s*(code|number))\b",
                r"\b(net\s*banking|mobile\s*banking)\s*(password|login|credential)",
                r"\b(card\s*number|debit\s*card|credit\s*card)\b.{0,25}\b(16[\s-]digit|expiry|valid\s*thru)\b"
            ],
            "why_dangerous": (
                "Legitimate organizations, banks, and telecom providers NEVER ask for OTPs, PINs, or CVVs over the phone. "
                "Harvesting these credentials gives attackers immediate unauthorized access to your funds or accounts."
            ),
            "recommendation": (
                "NEVER disclose any 4-digit or 6-digit OTP, UPI PIN, or CVV. "
                "Disconnect the call immediately and inform your bank's fraud reporting team."
            )
        },
        {
            "id": "REMOTE_ACCESS",
            "name": "Remote Access Tool / Malicious App Coercion",
            "category": "Malware & Device Hijacking",
            "severity": "CRITICAL",
            "weight": 30,
            "patterns": [
                r"\b(install|download|open)\b.{0,30}\b(anydesk|teamviewer|rustdesk|quicksupport|zoho\s*assist|airdroid)\b",
                r"\b(screen\s*share|share\s*your\s*screen|remote\s*access|remote\s*control)\b",
                r"\b(download|install)\b.{0,25}\b(\.apk|apk\s*file|app\s*from\s*link|support\s*application)\b",
                r"\b(grant|allow)\b.{0,20}\b(permission|accessibility\s*service|device\s*admin)\b"
            ],
            "why_dangerous": (
                "Attackers use remote desktop applications to view your screen in real time, capture SMS OTPs as they arrive, "
                "and take over your device to execute fraudulent banking transfers without your awareness."
            ),
            "recommendation": (
                "Do NOT install AnyDesk, TeamViewer, QuickSupport, or any unknown application on the caller's advice. "
                "If already installed, turn off Wi-Fi/Mobile Data immediately and uninstall the application."
            )
        },
        {
            "id": "COERCION_THREATS",
            "name": "Psychological Coercion & Threat of Legal / Financial Action",
            "category": "Intimidation Tactics",
            "severity": "HIGH",
            "weight": 25,
            "patterns": [
                r"\b(account|card|sim|connection)\b.{0,25}\b(block|suspend|freeze|deactivate|terminate|locked|cancelled)\b",
                r"\b(arrest|police|fir|warrant|cbi|ed|court|legal\s*action|custody)\b",
                r"\b(electricity|power)\b.{0,25}\b(cut\s*off|disconnect|stopped\s*tonight)\b",
                r"\b(illegal\s*transaction|money\s*laundering|narcotics|customs\s*seizure|parcel\s*confiscated)\b",
                r"\b(penalty|hefty\s*fine|legal\s*consequences|face\s*charges)\b"
            ],
            "why_dangerous": (
                "Attackers fabricate legal troubles, sudden account freezes, or power disconnection threats to instill panic. "
                "Fear suppresses rational thinking, prompting victims to comply with abnormal demands."
            ),
            "recommendation": (
                "Government agencies and law enforcement do NOT summon individuals or issue arrest warrants via phone calls. "
                "Remain calm, do not panic, and verify claims through official physical branch offices."
            )
        },
        {
            "id": "AUTHORITY_IMPERSONATION",
            "name": "Authority & Institutional Impersonation",
            "category": "Social Engineering",
            "severity": "HIGH",
            "weight": 20,
            "patterns": [
                r"\b(calling\s*from|i\s*am\s*from|speaking\s*from)\b.{0,30}\b(reserve\s*bank|rbi|state\s*bank|sbi|hdfc|icici|axis|punjab\s*national)\b",
                r"\b(fraud\s*prevention|security\s*department|vigilance\s*cell|anti[\s-]fraud\s*unit|head\s*office)\b",
                r"\b(telecom\s*regulatory|trai|department\s*of\s*telecom|dot|cyber\s*crime\s*cell|delhi\s*police|mumbai\s*police)\b",
                r"\b(income\s*tax\s*department|customs\s*officer|courier\s*investigation|interpol)\b",
                r"\b(customer\s*care\s*executive|technical\s*support\s*specialist|microsoft\s*support)\b"
            ],
            "why_dangerous": (
                "Impersonating trusted authorities (banks, cyber police, regulatory bodies) exploits public trust in institutions "
                "to artificially legitimize fraudulent inquiries and requests."
            ),
            "recommendation": (
                "Caller ID and names can be easily spoofed via VoIP tools. "
                "Hang up and independently dial the verified telephone number printed on your physical debit card or official website."
            )
        },
        {
            "id": "FINANCIAL_DEMAND",
            "name": "Urgent Fund Transfer & Advance Fee Demand",
            "category": "Financial Extraction",
            "severity": "HIGH",
            "weight": 25,
            "patterns": [
                r"\b(transfer|send|deposit|pay)\b.{0,30}\b(safe\s*account|verification\s*account|holding\s*account|rbi\s*account)\b",
                r"\b(advance\s*fee|processing\s*charge|refundable\s*deposit|customs\s*duty|clearance\s*charge)\b",
                r"\b(gift\s*card|google\s*play\s*card|apple\s*gift\s*card|crypto|bitcoin|usdt)\b",
                r"\b(scan\s*(this|the)?\s*qr\s*code|paytm\s*transfer|phonepe|gpay|google\s*pay)\b.{0,25}\b(immediately|to\s*receive|refund)\b"
            ],
            "why_dangerous": (
                "No legitimate bank has a 'safe holding account' to transfer customer money to. "
                "Demanding untraceable payments (QR scans, gift cards, crypto) ensures stolen funds cannot be reversed."
            ),
            "recommendation": (
                "Never transfer funds to any 'safe account' or scan a QR code to 'receive' money. "
                "Remember: Scanning a QR code or entering a UPI PIN always DEDUCTS money from your bank account."
            )
        },
        {
            "id": "ARTIFICIAL_URGENCY",
            "name": "Artificial Urgency & Extreme Time Pressure",
            "category": "Psychological Manipulation",
            "severity": "MEDIUM",
            "weight": 15,
            "patterns": [
                r"\b(within\s*(5|10|15|30)\s*minutes|in\s*the\s*next\s*few\s*minutes)\b",
                r"\b(act\s*now|right\s*now|immediately|without\s*delay|urgent\s*basis|time\s*is\s*running\s*out)\b",
                r"\b(before\s*it\s*is\s*too\s*late|last\s*and\s*final\s*warning|immediately\s*or\s*else)\b",
                r"\b(only\s*today|offer\s*expires\s*in|limited\s*time\s*window)\b"
            ],
            "why_dangerous": (
                "Urgency is a core social engineering tactic designed to induce stress, preempting the victim from taking time "
                "to consult friends, family, or official customer support channels."
            ),
            "recommendation": (
                "Take a deliberate pause. Legitimate emergencies are never resolved through high-pressure phone ultimatums. "
                "Refuse to be rushed into taking financial actions."
            )
        },
        {
            "id": "ISOLATION_SECRECY",
            "name": "Victim Isolation & Secrecy Demands",
            "category": "Behavioral Manipulation",
            "severity": "MEDIUM",
            "weight": 20,
            "patterns": [
                r"\b(do\s*not\s*disconnect|stay\s*on\s*the\s*line|keep\s*the\s*call\s*connected)\b",
                r"\b(do\s*not\s*(tell|inform|share\s*with)\s*(anyone|family|bank|branch\s*manager|police))\b",
                r"\b(this\s*is\s*(confidential|secret|classified|restricted)\s*investigation)\b",
                r"\b(go\s*to\s*a\s*quiet\s*room|isolate\s*yourself|do\s*not\s*speak\s*to\s*anyone\s*around\s*you)\b"
            ],
            "why_dangerous": (
                "Scammers actively prevent victims from seeking second opinions or advice from relatives, branch staff, or colleagues, "
                "maintaining complete psychological domination over the victim."
            ),
            "recommendation": (
                "If a caller instructs you to conceal the conversation from family or bank staff, it is an unequivocal red flag. "
                "Break contact immediately and talk to someone you trust."
            )
        },
        {
            "id": "UNSOLICITED_LURE",
            "name": "Unsolicited Financial Lures & Lottery / Cashback Scams",
            "category": "Lure & Enticement",
            "severity": "MEDIUM",
            "weight": 15,
            "patterns": [
                r"\b(won|winner|selected\s*for)\b.{0,30}\b(lottery|lucky\s*draw|cash\s*prize|crorepati|contest)\b",
                r"\b(cashback|reward\s*points|credit\s*card\s*points\s*redemption|unclaimed\s*bonus)\b",
                r"\b(accidental\s*refund|tax\s*rebate|overpaid\s*amount|claim\s*your\s*money)\b"
            ],
            "why_dangerous": (
                "Promising unearned wealth or bogus cashback tricks individuals into letting their guard down, "
                "ultimately requiring upfront 'registration fees' or card credential entry on phishing pages."
            ),
            "recommendation": (
                "You cannot win a lottery or contest you never entered. "
                "Legitimate organizations never ask you to pay processing fees to claim legitimate cashback."
            )
        }
    ]

    def __init__(self):
        # Compile regular expressions for performance and safety
        self.compiled_rules = []
        for rule in self.INDICATOR_RULES:
            compiled_patterns = [re.compile(p, re.IGNORECASE) for p in rule["patterns"]]
            self.compiled_rules.append({
                "rule": rule,
                "compiled_patterns": compiled_patterns
            })

    def analyze(self, transcript: str) -> Dict[str, Any]:
        """
        Analyzes the call transcript and produces a structured risk report.
        
        Args:
            transcript: Plain text transcription of the telephone call.
            
        Returns:
            Dictionary containing:
            - risk_score: Int (0-100)
            - risk_level: 'LOW', 'MEDIUM', or 'HIGH'
            - indicators_detected: List of matched indicator summaries with quotes
            - synergy_bonus: Synergy points applied
            - synergy_explanation: Reason for synergy points
            - score_breakdown: Transparent calculation breakdown
            - safety_recommendations: Tailored actionable defense recommendations
            - limitations_disclaimer: Rule-based heuristic statement
        """
        if not transcript or not transcript.strip():
            return self._empty_analysis()

        normalized_text = self._normalize_text(transcript)
        sentences = self._split_sentences(transcript)

        detected_indicators = []
        total_raw_weight = 0

        # Evaluate each rule category
        for entry in self.compiled_rules:
            rule = entry["rule"]
            patterns = entry["compiled_patterns"]
            matched_excerpts = []

            for pattern in patterns:
                # Check for pattern match in full normalized text
                matches = pattern.finditer(normalized_text)
                for match in matches:
                    matched_str = match.group(0).strip()
                    # Find surrounding contextual sentence for explainability
                    context_excerpt = self._extract_context(match.start(), match.end(), normalized_text, sentences)
                    if context_excerpt and context_excerpt not in matched_excerpts:
                        matched_excerpts.append(context_excerpt)

            # If any pattern matched, record this indicator once (no duplicate counting)
            if matched_excerpts:
                weight = rule["weight"]
                total_raw_weight += weight
                detected_indicators.append({
                    "id": rule["id"],
                    "name": rule["name"],
                    "category": rule["category"],
                    "severity": rule["severity"],
                    "weight": weight,
                    "excerpts": matched_excerpts[:3],  # Limit to top 3 representative excerpts
                    "why_dangerous": rule["why_dangerous"],
                    "recommendation": rule["recommendation"]
                })

        # Calculate Synergy Bonus (compounding social engineering tactic detection)
        synergy_bonus, synergy_explanation = self._calculate_synergy(detected_indicators)

        # Final Score calculation capped strictly at 100
        final_score = min(100, total_raw_weight + synergy_bonus)
        
        # Determine Risk Level Category
        if final_score <= self.LOW_THRESHOLD_MAX:
            risk_level = "LOW"
            color = "#10b981"  # Emerald Green
        elif final_score <= self.MEDIUM_THRESHOLD_MAX:
            risk_level = "MEDIUM"
            color = "#f59e0b"  # Amber Orange
        else:
            risk_level = "HIGH"
            color = "#ef4444"  # Rose Red

        # Compile tailored actionable recommendations
        recommendations = self._compile_recommendations(detected_indicators, risk_level)

        # Transparent mathematical breakdown
        score_breakdown = {
            "base_indicator_weights": [
                {"name": ind["name"], "weight": ind["weight"], "severity": ind["severity"]}
                for ind in detected_indicators
            ],
            "raw_sum": total_raw_weight,
            "synergy_bonus": synergy_bonus,
            "synergy_explanation": synergy_explanation,
            "calculated_total": total_raw_weight + synergy_bonus,
            "final_score_capped": final_score,
            "threshold_low": f"0 - {self.LOW_THRESHOLD_MAX}",
            "threshold_medium": f"{self.LOW_THRESHOLD_MAX + 1} - {self.MEDIUM_THRESHOLD_MAX}",
            "threshold_high": f"{self.HIGH_THRESHOLD_MIN} - 100"
        }

        limitations_disclaimer = (
            "IMPORTANT SECURITY & FORENSIC NOTICE: "
            "This risk score is derived from a transparent, rule-based heuristic indicator model designed for preliminary screening "
            "and triage purposes. It highlights suspicious linguistic and social engineering patterns. "
            "It does NOT constitute legally binding proof of fraud, nor does it guarantee absence of threat in unflagged calls."
        )

        return {
            "risk_score": final_score,
            "risk_level": risk_level,
            "risk_color": color,
            "indicators_detected": detected_indicators,
            "indicator_count": len(detected_indicators),
            "synergy_bonus": synergy_bonus,
            "synergy_explanation": synergy_explanation,
            "score_breakdown": score_breakdown,
            "safety_recommendations": recommendations,
            "limitations_disclaimer": limitations_disclaimer
        }

    def _calculate_synergy(self, detected: List[Dict[str, Any]]) -> Tuple[int, str]:
        """
        Evaluates contextual synergy between detected indicators.
        In cyber security, a request for an OTP becomes exponentially more dangerous
        when paired with urgent threats or authority impersonation.
        """
        detected_ids = {item["id"] for item in detected}
        synergy_points = 0
        reasons = []

        # Synergy Case 1: Credential theft + Intimidation / Coercion
        if "CRED_OTP_PIN" in detected_ids and "COERCION_THREATS" in detected_ids:
            synergy_points += 15
            reasons.append("High-severity combination: Credential extraction under threat of legal/account penalty (+15 pts)")

        # Synergy Case 2: Remote Access + Any Credential/Financial Demand
        if "REMOTE_ACCESS" in detected_ids and ("CRED_OTP_PIN" in detected_ids or "FINANCIAL_DEMAND" in detected_ids):
            synergy_points += 15
            reasons.append("High-severity combination: Remote screen sharing combined with credential/fund transfer (+15 pts)")

        # Synergy Case 3: Authority Impersonation + Secrecy Demands
        if "AUTHORITY_IMPERSONATION" in detected_ids and "ISOLATION_SECRECY" in detected_ids:
            synergy_points += 10
            reasons.append("Social engineering synergy: Authority figure demanding secrecy and victim isolation (+10 pts)")

        # Synergy Case 4: Urgency + Financial Demand without Credential
        if "ARTIFICIAL_URGENCY" in detected_ids and "FINANCIAL_DEMAND" in detected_ids and "CRED_OTP_PIN" not in detected_ids:
            synergy_points += 10
            reasons.append("Urgency-driven payment pressure (+10 pts)")

        # Cap synergy addition at +25
        final_synergy = min(25, synergy_points)
        explanation = "; ".join(reasons) if reasons else "No tactical indicator synergy identified."
        return final_synergy, explanation

    def _compile_recommendations(self, indicators: List[Dict[str, Any]], risk_level: str) -> List[str]:
        """Compiles prioritized, non-redundant safety recommendations."""
        recommendations = []

        if risk_level == "HIGH":
            recommendations.append("🚨 IMMEDIATE ACTION: Terminate the call immediately. Do NOT press any numbers or follow instructions.")
        elif risk_level == "MEDIUM":
            recommendations.append("⚠️ CAUTION: Exercise high vigilance. Do not disclose personal or financial information without verification.")
        else:
            recommendations.append("✅ Standard Awareness: This conversation does not exhibit acute phishing patterns, but continue to safeguard sensitive information.")

        # Add indicator-specific recommendations
        for ind in indicators:
            rec = ind.get("recommendation")
            if rec and rec not in recommendations:
                recommendations.append(rec)

        # Always include cyber incident reporting information
        recommendations.append(
            "📞 Official Reporting Helpline: If you suspect fraudulent activity in India, immediately dial 1930 "
            "(National Cyber Crime Reporting Helpline) or register a complaint at https://cybercrime.gov.in. "
            "For international users, consult your local cyber emergency response team (e.g., IC3.gov / FTC.gov)."
        )

        return recommendations

    def _normalize_text(self, text: str) -> str:
        """Cleans and standardizes text for regex evaluation."""
        text = text.lower()
        # Normalize whitespace
        text = re.sub(r"\s+", " ", text)
        return text

    def _split_sentences(self, text: str) -> List[str]:
        """Splits transcript into sentences for contextual quotation."""
        sentences = re.split(r"(?<=[.!?\n])\s+", text)
        return [s.strip() for s in sentences if s.strip()]

    def _extract_context(self, start_pos: int, end_pos: int, text: str, sentences: List[str]) -> str:
        """Finds the most representative sentence or excerpt around a pattern match."""
        # Find sentence containing the match
        target_snippet = text[start_pos:end_pos]
        for s in sentences:
            if target_snippet in s.lower():
                return s.strip()
        
        # Fallback: grab surrounding 100 characters
        window_start = max(0, start_pos - 40)
        window_end = min(len(text), end_pos + 40)
        prefix = "..." if window_start > 0 else ""
        suffix = "..." if window_end < len(text) else ""
        return f"{prefix}{text[window_start:window_end].strip()}{suffix}"

    def _empty_analysis(self) -> Dict[str, Any]:
        """Returns safe default analysis for empty transcripts."""
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "risk_color": "#10b981",
            "indicators_detected": [],
            "indicator_count": 0,
            "synergy_bonus": 0,
            "synergy_explanation": "Empty transcript - no indicators evaluated.",
            "score_breakdown": {
                "base_indicator_weights": [],
                "raw_sum": 0,
                "synergy_bonus": 0,
                "synergy_explanation": "None",
                "calculated_total": 0,
                "final_score_capped": 0,
                "threshold_low": f"0 - {self.LOW_THRESHOLD_MAX}",
                "threshold_medium": f"{self.LOW_THRESHOLD_MAX + 1} - {self.MEDIUM_THRESHOLD_MAX}",
                "threshold_high": f"{self.HIGH_THRESHOLD_MIN} - 100"
            },
            "safety_recommendations": [
                "No call audio or transcript provided. Please upload an audio file or select a demo conversation."
            ],
            "limitations_disclaimer": "No transcript evaluated."
        }
