# ============================================================
# server.py (FINAL v6) — Enhanced Honeypot with Intelligent Probing
# ============================================================
# ✅ Intelligent follow-up questions based on scam type
# ✅ Red flag identification and extraction
# ✅ Nuanced victim personas with contextual responses
# ✅ Comprehensive documentation
# ✅ Robust error handling
# ✅ Intelligence extraction with confidence scoring
# ============================================================

from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any, Union
import re
import requests
from datetime import datetime
import json
import random
import logging
from enum import Enum
import traceback

# ============================================================
# Logging Setup
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# App Setup
# ============================================================

app = FastAPI(
    title="Agentic Honeypot API",
    version="v6-ENHANCED",
    description="Intelligent honeypot system with contextual probing and red flag detection",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# Required Intelligence Keys (Evaluator expects exactly these)
# ============================================================

DEFAULT_INTEL = {
    "phoneNumbers": [],
    "bankAccounts": [],
    "upiIds": [],
    "phishingLinks": [],
    "emailAddresses": []
}

# ============================================================
# Enums for Scam Types and Red Flags
# ============================================================

class ScamType(str, Enum):
    UNKNOWN = "unknown"
    LOTTERY = "lottery"
    BANK_PHISHING = "bank_phishing"
    TECH_SUPPORT = "tech_support"
    ROMANCE = "romance"
    INVESTMENT = "investment"
    JOB_OFFER = "job_offer"
    EMERGENCY = "emergency"
    OTP_SCAM = "otp_scam"
    GIFT_CARD = "gift_card"
    TAX_SCAM = "tax_scam"

class RedFlag(str, Enum):
    REQUEST_OTP = "request_otp"
    REQUEST_UPI = "request_upi"
    REQUEST_BANK_DETAILS = "request_bank_details"
    REQUEST_PERSONAL_INFO = "request_personal_info"
    URGENCY = "urgency"
    THREAT = "threat"
    PROMISE_REWARD = "promise_reward"
    REQUEST_PAYMENT = "request_payment"
    SUSPICIOUS_LINK = "suspicious_link"
    IMPERSONATION = "impersonation"
    REQUEST_REMOTE_ACCESS = "request_remote_access"
    GRAMMAR_MISTAKES = "grammar_mistakes"
    UNOFFICIAL_CHANNEL = "unofficial_channel"

# ============================================================
# Models
# ============================================================

class Message(BaseModel):
    sender: str
    text: str
    timestamp: Union[str, int]
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if isinstance(v, int) and v < 0:
            raise ValueError('Timestamp cannot be negative')
        return v

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

class RedFlagDetail(BaseModel):
    type: RedFlag
    description: str
    severity: float  # 0-1
    evidence: str

class ScamAnalysis(BaseModel):
    is_scam: bool
    scam_type: ScamType
    confidence: float
    red_flags: List[RedFlagDetail]
    found_keywords: List[str]
    risk_level: str

class IntelligenceItem(BaseModel):
    value: str
    confidence: float
    context: str
    extracted_at: str

class EnhancedIntelligence(BaseModel):
    phoneNumbers: List[IntelligenceItem] = []
    bankAccounts: List[IntelligenceItem] = []
    upiIds: List[IntelligenceItem] = []
    phishingLinks: List[IntelligenceItem] = []
    emailAddresses: List[IntelligenceItem] = []
    redFlags: List[RedFlagDetail] = []
    scamType: Optional[ScamType] = None

# ============================================================
# Timestamp Normalizer
# ============================================================

def normalize_timestamp(ts):
    """Normalize timestamp to ISO format"""
    try:
        if isinstance(ts, int):
            # Handle millisecond timestamps
            return datetime.utcfromtimestamp(ts / 1000).isoformat() + "Z"
        elif isinstance(ts, str):
            # Try to parse and re-format to ensure consistency
            try:
                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                return dt.isoformat() + "Z"
            except:
                return ts
        return ts
    except Exception as e:
        logger.error(f"Timestamp normalization error: {e}")
        return datetime.utcnow().isoformat() + "Z"

# ============================================================
# STRICT API KEY AUTH (REQUIRED)
# ============================================================

VALID_API_KEYS = {
    "hackathon_key_2024": "participant",
    "test_key_123": "tester",
    "admin_key": "administrator"
}

async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
    """Verify API key from header"""
    if not x_api_key:
        logger.warning("API key missing in request")
        raise HTTPException(
            status_code=401,
            detail="API key missing. Provide x-api-key header."
        )

    if x_api_key not in VALID_API_KEYS:
        logger.warning(f"Invalid API key attempt: {x_api_key}")
        raise HTTPException(
            status_code=401,
            detail="Invalid API key."
        )

    logger.info(f"API key verified for user: {VALID_API_KEYS[x_api_key]}")
    return {"user": VALID_API_KEYS[x_api_key]}

# ============================================================
# Session Storage (In-Memory with persistence simulation)
# ============================================================

class SessionStorage:
    def __init__(self):
        self.sessions: Dict[str, dict] = {}
        self.session_archives: Dict[str, list] = {}  # For history

    def init_session(self, session_id: str):
        """Initialize a new session"""
        self.sessions[session_id] = {
            "scam_detected": False,
            "message_count": 0,
            "scammer_turns": 0,
            "extracted_intelligence": json.loads(json.dumps(DEFAULT_INTEL)),
            "enhanced_intelligence": {},
            "red_flags": [],
            "scam_type": ScamType.UNKNOWN,
            "agent_notes": "",
            "final_sent": False,
            "start_time": datetime.utcnow().isoformat(),
            "persona_assigned": None,
            "questions_asked": [],
            "suspicious_patterns": [],
            "confidence_scores": []
        }
        self.session_archives[session_id] = []
        logger.info(f"Session initialized: {session_id}")

    def get(self, session_id: str):
        """Get session data, initialize if not exists"""
        if session_id not in self.sessions:
            self.init_session(session_id)
        return self.sessions[session_id]

    def save(self, session_id: str, session: dict):
        """Save session data"""
        self.sessions[session_id] = session
        # Archive this state
        if session_id in self.session_archives:
            self.session_archives[session_id].append({
                "timestamp": datetime.utcnow().isoformat(),
                "state": session.copy()
            })

    def get_archive(self, session_id: str):
        """Get session archive for debugging"""
        return self.session_archives.get(session_id, [])

storage = SessionStorage()

# ============================================================
# Advanced Scam Detector with Red Flag Analysis
# ============================================================

class AdvancedScamDetector:
    def __init__(self):
        self.scam_patterns = {
            ScamType.LOTTERY: {
                "keywords": ["won", "lottery", "prize", "winner", "congratulations", "claim", "reward"],
                "patterns": [r"(you|have|are).*won", r"lottery.*(prize|win)", r"claim.*prize"],
                "red_flags": [RedFlag.PROMISE_REWARD, RedFlag.REQUEST_PAYMENT]
            },
            ScamType.BANK_PHISHING: {
                "keywords": ["bank", "account", "blocked", "suspended", "verify", "update", "kyc", "otp"],
                "patterns": [r"account.*(blocked|suspended)", r"verify.*(details|account)", r"update.*kyc"],
                "red_flags": [RedFlag.REQUEST_OTP, RedFlag.REQUEST_BANK_DETAILS, RedFlag.URGENCY]
            },
            ScamType.TECH_SUPPORT: {
                "keywords": ["virus", "infected", "computer", "support", "microsoft", "apple", "tech", "repair"],
                "patterns": [r"(virus|malware).*detected", r"computer.*(problem|issue)", r"tech.*support"],
                "red_flags": [RedFlag.REQUEST_REMOTE_ACCESS, RedFlag.REQUEST_PAYMENT]
            },
            ScamType.INVESTMENT: {
                "keywords": ["investment", "profit", "return", "guaranteed", "crypto", "bitcoin", "stock"],
                "patterns": [r"guaranteed.*(profit|return)", r"double.*(money|investment)", r"crypto.*(investment|trading)"],
                "red_flags": [RedFlag.PROMISE_REWARD, RedFlag.REQUEST_PAYMENT]
            },
            ScamType.EMERGENCY: {
                "keywords": ["emergency", "urgent", "help", "accident", "hospital", "family", "relative"],
                "patterns": [r"(urgent|emergency).*help", r"family.*(accident|hospital)", r"need.*money.*(emergency|urgent)"],
                "red_flags": [RedFlag.URGENCY, RedFlag.REQUEST_PAYMENT]
            },
            ScamType.OTP_SCAM: {
                "keywords": ["otp", "code", "verification", "sms", "share"],
                "patterns": [r"(share|send).*otp", r"otp.*(code|number)", r"verification.*code"],
                "red_flags": [RedFlag.REQUEST_OTP, RedFlag.URGENCY]
            }
        }
        
        self.red_flag_patterns = {
            RedFlag.REQUEST_OTP: [r"(send|share|give).*otp", r"otp.*(code|number)", r"verification.*code"],
            RedFlag.REQUEST_UPI: [r"(upi|paytm|phonepe).*id", r"(send|transfer).*to.*(upi|id)", r"upi.*(payment|transfer)"],
            RedFlag.REQUEST_BANK_DETAILS: [r"bank.*(details|account|number)", r"account.*(number|details)", r"card.*(number|details)"],
            RedFlag.URGENCY: [r"urgent", r"immediate", r"asap", r"right now", r"today only", r"limited time"],
            RedFlag.THREAT: [r"blocked", r"suspended", r"closed", r"legal", r"police", r"case", r"arrest"],
            RedFlag.PROMISE_REWARD: [r"won", r"prize", r"reward", r"free", r"gift", r"bonus", r"discount"],
            RedFlag.REQUEST_PAYMENT: [r"pay", r"send.*money", r"transfer.*funds", r"processing fee", r"advance.*payment"],
            RedFlag.SUSPICIOUS_LINK: [r"https?://(?!.*(?:bank|paytm|google|microsoft))[^\s]+", r"bit\.ly", r"tinyurl"],
            RedFlag.IMPERSONATION: [r"official", r"government", r"bank.*official", r"authorized", r"certified"],
            RedFlag.GRAMMAR_MISTAKES: []  # Will be handled separately
        }

    def detect_scam_type(self, text: str) -> tuple[ScamType, float]:
        """Detect the most likely scam type"""
        text_lower = text.lower()
        best_match = ScamType.UNKNOWN
        best_score = 0.0
        
        for scam_type, patterns in self.scam_patterns.items():
            score = 0.0
            
            # Check keywords
            keyword_matches = sum(1 for kw in patterns["keywords"] if kw in text_lower)
            score += keyword_matches * 0.2
            
            # Check regex patterns
            for pattern in patterns["patterns"]:
                if re.search(pattern, text_lower):
                    score += 0.5
            
            # Normalize score
            score = min(score, 1.0)
            
            if score > best_score and score > 0.3:
                best_score = score
                best_match = scam_type
        
        return best_match, best_score

    def identify_red_flags(self, text: str) -> List[RedFlagDetail]:
        """Identify red flags in the message"""
        text_lower = text.lower()
        red_flags = []
        
        for flag_type, patterns in self.red_flag_patterns.items():
            if flag_type == RedFlag.GRAMMAR_MISTAKES:
                # Check for grammar mistakes (simplified)
                if self.has_grammar_mistakes(text):
                    red_flags.append(RedFlagDetail(
                        type=RedFlag.GRAMMAR_MISTAKES,
                        description="Message contains grammatical errors typical of scams",
                        severity=0.6,
                        evidence=text[:100]
                    ))
                continue
                
            for pattern in patterns:
                matches = re.findall(pattern, text_lower)
                if matches:
                    severity = self.calculate_severity(flag_type, text)
                    red_flags.append(RedFlagDetail(
                        type=flag_type,
                        description=self.get_red_flag_description(flag_type),
                        severity=severity,
                        evidence=matches[0] if isinstance(matches[0], str) else str(matches[0])
                    ))
                    break  # Only add once per flag type
        
        return red_flags

    def has_grammar_mistakes(self, text: str) -> bool:
        """Simplified grammar check"""
        # Common scam grammar patterns
        patterns = [
            r"[A-Z]+\s+[a-z]+",  # Inconsistent capitalization
            r"\b(ur|u|r)\b",  # Short forms
            r"(?<![.!?])\s+[a-z]",  # Missing capitalization after period
        ]
        
        score = sum(1 for pattern in patterns if re.search(pattern, text))
        return score >= 2

    def calculate_severity(self, flag_type: RedFlag, text: str) -> float:
        """Calculate severity of a red flag"""
        base_severity = {
            RedFlag.REQUEST_OTP: 0.9,
            RedFlag.REQUEST_UPI: 0.8,
            RedFlag.REQUEST_BANK_DETAILS: 0.9,
            RedFlag.URGENCY: 0.7,
            RedFlag.THREAT: 0.8,
            RedFlag.PROMISE_REWARD: 0.6,
            RedFlag.REQUEST_PAYMENT: 0.9,
            RedFlag.SUSPICIOUS_LINK: 0.7,
            RedFlag.IMPERSONATION: 0.5,
            RedFlag.GRAMMAR_MISTAKES: 0.4
        }.get(flag_type, 0.5)
        
        # Adjust based on context
        if "urgent" in text.lower() and flag_type == RedFlag.REQUEST_PAYMENT:
            base_severity = min(base_severity + 0.2, 1.0)
        
        return base_severity

    def get_red_flag_description(self, flag_type: RedFlag) -> str:
        """Get description for red flag type"""
        descriptions = {
            RedFlag.REQUEST_OTP: "Asking for OTP or verification code",
            RedFlag.REQUEST_UPI: "Requesting UPI ID for payment",
            RedFlag.REQUEST_BANK_DETAILS: "Asking for sensitive bank details",
            RedFlag.URGENCY: "Creating false urgency",
            RedFlag.THREAT: "Using threats or intimidation",
            RedFlag.PROMISE_REWARD: "Promising unrealistic rewards",
            RedFlag.REQUEST_PAYMENT: "Requesting advance payment",
            RedFlag.SUSPICIOUS_LINK: "Sharing suspicious links",
            RedFlag.IMPERSONATION: "Impersonating legitimate entities",
            RedFlag.GRAMMAR_MISTAKES: "Contains grammatical errors"
        }
        return descriptions.get(flag_type, "Suspicious behavior detected")

    def detect(self, text: str) -> ScamAnalysis:
        """Complete scam detection with analysis"""
        scam_type, type_confidence = self.detect_scam_type(text)
        red_flags = self.identify_red_flags(text)
        
        # Calculate overall confidence
        if red_flags:
            avg_severity = sum(rf.severity for rf in red_flags) / len(red_flags)
            confidence = max(type_confidence, avg_severity)
        else:
            confidence = type_confidence
        
        # Extract keywords
        found_keywords = []
        for scam_data in self.scam_patterns.values():
            found_keywords.extend([kw for kw in scam_data["keywords"] if kw in text.lower()])
        
        # Determine risk level
        if confidence >= 0.7:
            risk_level = "HIGH"
        elif confidence >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return ScamAnalysis(
            is_scam=confidence >= 0.3,
            scam_type=scam_type,
            confidence=round(confidence * 100, 2),
            red_flags=red_flags,
            found_keywords=list(set(found_keywords)),
            risk_level=risk_level
        )

detector = AdvancedScamDetector()

# ============================================================
# Enhanced Intelligence Extractor with Confidence
# ============================================================

class EnhancedExtractor:
    def __init__(self):
        # Enhanced regex patterns
        self.email_re = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
        self.upi_re = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@(upi|paytm|ybl|axl|okicici|oksbi|okhdfc|okaxis|icici|hdfc|sbi|axis|bank|yesbank|kotak|pnb|idfc|rbl|union|canara)\b")
        self.phone_re = re.compile(r"(\+91[-\s]?)?(\d{10})|(\d{5}[-\s]?\d{5})")
        self.bank_re = re.compile(r"\b(\d{9,18})\b")  # Account numbers
        self.link_re = re.compile(r"https?://[^\s]+|www\.[^\s]+")
        self.ifsc_re = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")  # IFSC codes
        self.pin_re = re.compile(r"\b\d{6}\b")  # PIN codes
        self.aadhar_re = re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")  # Aadhar
        self.pan_re = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b")  # PAN

    def calculate_confidence(self, value: str, context: str, item_type: str) -> float:
        """Calculate confidence score for extracted intelligence"""
        confidence = 0.7  # Base confidence
        
        # Adjust based on type
        type_weights = {
            "upiIds": 0.9,  # UPI IDs are very specific
            "emailAddresses": 0.85,
            "phoneNumbers": 0.8,
            "bankAccounts": 0.75,
            "phishingLinks": 0.7
        }
        confidence *= type_weights.get(item_type, 0.7)
        
        # Check context for verification
        context_lower = context.lower()
        verification_indicators = [
            "my", "this is", "here is", "use this", "send to",
            "account number", "upi id", "phone number", "email"
        ]
        
        for indicator in verification_indicators:
            if indicator in context_lower:
                confidence += 0.1
                break
        
        # Ensure confidence is within bounds
        return min(round(confidence, 2), 1.0)

    def extract_with_context(self, text: str, conversation_history: List[Message]) -> Dict[str, List[IntelligenceItem]]:
        """Extract intelligence with context and confidence"""
        result = {k: [] for k in DEFAULT_INTEL.keys()}
        
        # Get conversation context
        context = " ".join([msg.text for msg in conversation_history[-3:]]) if conversation_history else ""
        
        # Extract links
        for m in self.link_re.findall(text):
            item = IntelligenceItem(
                value=m,
                confidence=self.calculate_confidence(m, context, "phishingLinks"),
                context=context[:100] if context else "",
                extracted_at=datetime.utcnow().isoformat() + "Z"
            )
            if not any(i.value == m for i in result["phishingLinks"]):
                result["phishingLinks"].append(item)

        # Extract emails
        for m in self.email_re.findall(text):
            item = IntelligenceItem(
                value=m,
                confidence=self.calculate_confidence(m, context, "emailAddresses"),
                context=context[:100] if context else "",
                extracted_at=datetime.utcnow().isoformat() + "Z"
            )
            if not any(i.value == m for i in result["emailAddresses"]):
                result["emailAddresses"].append(item)

        # Extract UPI IDs
        for m in self.upi_re.findall(text):
            if isinstance(m, tuple):
                m = m[0] if m[0] else m[1] if len(m) > 1 else str(m)
            item = IntelligenceItem(
                value=m,
                confidence=self.calculate_confidence(m, context, "upiIds"),
                context=context[:100] if context else "",
                extracted_at=datetime.utcnow().isoformat() + "Z"
            )
            if not any(i.value == m for i in result["upiIds"]):
                result["upiIds"].append(item)

        # Extract phones
        for m in self.phone_re.findall(text):
            if isinstance(m, tuple):
                # Get the non-empty group
                phone = next((x for x in m if x), "")
            else:
                phone = m
            
            if phone and len(re.sub(r'\D', '', phone)) == 10:
                item = IntelligenceItem(
                    value=phone,
                    confidence=self.calculate_confidence(phone, context, "phoneNumbers"),
                    context=context[:100] if context else "",
                    extracted_at=datetime.utcnow().isoformat() + "Z"
                )
                if not any(i.value == phone for i in result["phoneNumbers"]):
                    result["phoneNumbers"].append(item)

        # Extract bank accounts
        for m in self.bank_re.findall(text):
            if len(m) >= 9 and len(m) <= 18:  # Account number length check
                item = IntelligenceItem(
                    value=m,
                    confidence=self.calculate_confidence(m, context, "bankAccounts"),
                    context=context[:100] if context else "",
                    extracted_at=datetime.utcnow().isoformat() + "Z"
                )
                if not any(i.value == m for i in result["bankAccounts"]):
                    result["bankAccounts"].append(item)

        return result

extractor = EnhancedExtractor()

# ============================================================
# Intelligent Honeypot Agent with Contextual Probing
# ============================================================

class IntelligentAgent:
    def __init__(self):
        self.question_pools = {
            ScamType.LOTTERY: {
                "initial": [
                    "Oh wow, I won something? Which lottery is this?",
                    "I don't remember entering any lottery. Can you tell me more?",
                    "Do I need to pay anything to claim this prize?",
                    "Is this from the government lottery?",
                    "What's the ticket number? I want to verify."
                ],
                "probing": [
                    "Why do you need my bank details for the prize?",
                    "Can I visit your office to collect it in person?",
                    "Is there a processing fee? How much?",
                    "Have I won any prizes before?",
                    "What's your company name? I want to look it up."
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_PAYMENT: [
                        "I thought prizes were free? Why do I need to pay?",
                        "That sounds suspicious. Real lotteries don't ask for money.",
                        "My friend said never to pay to claim a prize."
                    ],
                    RedFlag.REQUEST_BANK_DETAILS: [
                        "Why do you need my bank account? Can't you send a check?",
                        "I'm not comfortable sharing bank details online.",
                        "Is there another way to receive the prize?"
                    ]
                }
            },
            ScamType.BANK_PHISHING: {
                "initial": [
                    "My account is blocked? That's concerning. Which bank is this?",
                    "I haven't received any official notice from my bank.",
                    "Can you tell me your name and employee ID?",
                    "Should I call my bank's customer care to verify?",
                    "What exactly happened to my account?"
                ],
                "probing": [
                    "Why do you need my OTP? The bank never asks for that.",
                    "I'll visit the branch tomorrow. Where is it located?",
                    "Can you send me an official email from the bank?",
                    "What's your department? I want to file a complaint.",
                    "The bank's website says never share OTP with anyone."
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_OTP: [
                        "My bank specifically told me never to share OTP.",
                        "Why would you need my OTP if you're from the bank?",
                        "This doesn't seem right. I'm going to call the bank."
                    ],
                    RedFlag.URGENCY: [
                        "Why is this so urgent? Let me think about it.",
                        "I need to verify this with my family first.",
                        "If it's that urgent, I should visit the branch."
                    ]
                }
            },
            ScamType.TECH_SUPPORT: {
                "initial": [
                    "My computer has a virus? How do you know?",
                    "Are you from Microsoft? Do you have a support ID?",
                    "I haven't noticed any problems with my computer.",
                    "What exactly did you detect on my system?",
                    "Is this a free support service?"
                ],
                "probing": [
                    "Why do you need remote access to my computer?",
                    "How much does this service cost?",
                    "Can you give me your company details?",
                    "I'd like to read reviews about your service first.",
                    "Do you have a local office I can visit?"
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_REMOTE_ACCESS: [
                        "I'm not comfortable giving remote access to strangers.",
                        "Why can't you guide me over the phone?",
                        "This sounds like those tech support scams I've heard about."
                    ],
                    RedFlag.REQUEST_PAYMENT: [
                        "I need to think about this before paying.",
                        "Do you have a secure payment portal?",
                        "Can I pay after the problem is fixed?"
                    ]
                }
            },
            ScamType.EMERGENCY: {
                "initial": [
                    "Oh no! Which family member is it?",
                    "Which hospital are they at? I'll call them directly.",
                    "Let me call my relative to verify.",
                    "Can you give me your name and relationship to them?",
                    "What's the doctor's name?"
                ],
                "probing": [
                    "Why do you need money sent to you specifically?",
                    "I'll transfer money directly to the hospital.",
                    "Let me speak to my family member first.",
                    "Which city is this happening in?",
                    "I need to verify this with other relatives."
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_PAYMENT: [
                        "I'll send money directly to the hospital.",
                        "Let me confirm with other family members first.",
                        "This seems suspicious. I'm calling the police."
                    ],
                    RedFlag.URGENCY: [
                        "I understand it's urgent, but I need to verify.",
                        "If it's that serious, I'll call an ambulance.",
                        "Let me get more information before sending money."
                    ]
                }
            },
            ScamType.OTP_SCAM: {
                "initial": [
                    "Why do you need my OTP?",
                    "I haven't requested any transaction.",
                    "Which service is this OTP for?",
                    "I'm not expecting any verification code.",
                    "Can you tell me what this is regarding?"
                ],
                "probing": [
                    "The message says not to share OTP with anyone.",
                    "Why can't you send the code to my email instead?",
                    "This seems like a scam. I'm reporting this.",
                    "What happens if I don't share the OTP?",
                    "Is this related to my bank account?"
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_OTP: [
                        "I know sharing OTP is dangerous.",
                        "My bank said never to share OTP.",
                        "This is exactly how people get scammed."
                    ]
                }
            },
            ScamType.UNKNOWN: {
                "initial": [
                    "I'm not sure I understand. Can you explain?",
                    "Who am I speaking with?",
                    "How did you get my number?",
                    "What is this regarding?",
                    "Can you send me more information?"
                ],
                "probing": [
                    "This sounds unusual. Is this a scam?",
                    "Why do you need my personal information?",
                    "Can I verify this with someone official?",
                    "What's your company name and address?",
                    "I need to think about this carefully."
                ],
                "red_flag_responses": {
                    RedFlag.REQUEST_PERSONAL_INFO: [
                        "I don't share personal information with strangers.",
                        "Why do you need my details?",
                        "This seems suspicious."
                    ]
                }
            }
        }
        
        self.general_responses = [
            "That's interesting. Tell me more.",
            "I see. What happens next?",
            "Can you explain that again?",
            "I'm a bit confused. Can you clarify?",
            "Oh, I didn't know that."
        ]

    def get_response(self, 
                     session_id: str, 
                     message: str, 
                     analysis: ScamAnalysis,
                     conversation_history: List[Message]) -> str:
        """Generate contextual response based on scam analysis"""
        
        # Get session data
        session = storage.get(session_id)
        questions_asked = session.get("questions_asked", [])
        
        # Determine which question pool to use
        if analysis.scam_type in self.question_pools:
            pool = self.question_pools[analysis.scam_type]
        else:
            pool = self.question_pools[ScamType.UNKNOWN]
        
        # Check for red flags to respond to
        for red_flag in analysis.red_flags:
            if red_flag.type in pool.get("red_flag_responses", {}):
                responses = pool["red_flag_responses"][red_flag.type]
                # Check if we haven't asked this type of question recently
                if not any(r in questions_asked[-2:] for r in responses):
                    response = random.choice(responses)
                    questions_asked.append(response)
                    session["questions_asked"] = questions_asked
                    storage.save(session_id, session)
                    return response
        
        # Determine stage of conversation
        if len(questions_asked) < 3:
            # Initial stage
            response = random.choice(pool["initial"])
        elif len(questions_asked) < 7:
            # Probing stage
            response = random.choice(pool["probing"])
        else:
            # Deep engagement stage
            response = random.choice(self.general_responses + pool["probing"])
        
        # Track asked questions
        questions_asked.append(response)
        session["questions_asked"] = questions_asked
        storage.save(session_id, session)
        
        return response

agent = IntelligentAgent()

# ============================================================
# Final Submission Callback with Enhanced Payload
# ============================================================

EVALUATOR_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

def send_final_result(session_id: str):
    """Send final results to evaluator"""
    try:
        session = storage.get(session_id)

        duration = int(
            (datetime.utcnow() - datetime.fromisoformat(session["start_time"]))
            .total_seconds()
        )

        # -------- SAFE NORMALIZATION --------
        def extract_value(item):
            """Normalize IntelligenceItem / dict / raw value safely"""
            if isinstance(item, dict):
                return item.get("value", item)
            if hasattr(item, "value"):
                return item.value
            return item

        # Convert enhanced intelligence to expected format
        extracted_intel = {}
        for key in DEFAULT_INTEL.keys():
            items = session.get("extracted_intelligence", {}).get(key, [])
            extracted_intel[key] = [extract_value(item) for item in items]

        # -------- SAFE RED FLAGS --------
        red_flag_types = []
        for rf in session.get("red_flags", []):
            try:
                if hasattr(rf, "type"):
                    t = rf.type
                    red_flag_types.append(t.value if hasattr(t, "value") else t)
                else:
                    red_flag_types.append(rf)
            except Exception:
                red_flag_types.append(str(rf))

        # -------- SAFE SCAM TYPE --------
        scam_type_obj = session.get("scam_type", ScamType.UNKNOWN)
        scam_type_value = (
            scam_type_obj.value if hasattr(scam_type_obj, "value") else scam_type_obj
        )

        payload = {
            "status": "completed",
            "sessionId": session_id,
            "scamDetected": session["scam_detected"],
            "totalMessagesExchanged": session["message_count"],
            "extractedIntelligence": extracted_intel,
            "engagementMetrics": {
                "totalMessagesExchanged": session["message_count"],
                "engagementDurationSeconds": duration,
                "questionsAsked": len(session.get("questions_asked", [])),
                "redFlagsIdentified": len(session.get("red_flags", [])),
                "scamType": scam_type_value,
            },
            "agentNotes": (
                f"{session['agent_notes']}\n"
                f"Red Flags: {red_flag_types}\n"
                f"Scam Type: {scam_type_value}"
            ),
        }

        logger.info(f"Sending final result for session {session_id}")
        r = requests.post(EVALUATOR_ENDPOINT, json=payload, timeout=8)

        if r.status_code == 200:
            logger.info(f"✅ Final result sent successfully for {session_id}")
        else:
            logger.warning(
                f"⚠️ Final result sent with status {r.status_code} for {session_id}"
            )

    except Exception as e:
        logger.error(f"❌ Final callback failed for {session_id}: {str(e)}")
        logger.error(traceback.format_exc())


# ============================================================
# MAIN ENDPOINT (Hackathon Required)
# ============================================================

@app.post("/process/public")
async def process_public(
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key),
    body: Optional[dict] = Body(default=None)
):
    """Main honeypot processing endpoint"""
    
    # Health check for endpoint tester
    if body is None:
        logger.info("Health check request received")
        return {
            "status": "success", 
            "reply": "Endpoint reachable",
            "message": "Honeypot API v6 is ready"
        }

    try:
        # Parse and validate request
        req = HoneypotRequest(**body)

        # Normalize timestamps
        req.message.timestamp = normalize_timestamp(req.message.timestamp)
        for m in req.conversationHistory:
            m.timestamp = normalize_timestamp(m.timestamp)

        session_id = req.sessionId
        session = storage.get(session_id)

        # Log incoming message
        logger.info(f"Session {session_id}: Received message from {req.message.sender}")
        logger.debug(f"Message text: {req.message.text[:100]}...")

        # Count scammer message
        session["message_count"] += 1
        session["scammer_turns"] += 1

        # Detect scam with advanced analysis
        analysis = detector.detect(req.message.text)
        session["scam_detected"] |= analysis.is_scam
        session["scam_type"] = analysis.scam_type

        # Update agent notes
        session["agent_notes"] = (
            f"Scam confidence: {analysis.confidence}%. "
            f"Risk level: {analysis.risk_level}. "
            f"Keywords: {analysis.found_keywords}"
        )

        # Store red flags
        for rf in analysis.red_flags:
            if rf not in session.get("red_flags", []):
                session.setdefault("red_flags", []).append(rf)

        # Extract intelligence with context
        extracted = extractor.extract_with_context(
            req.message.text, 
            req.conversationHistory + [req.message]
        )
        
        # Merge with existing intelligence
        for key in DEFAULT_INTEL.keys():
            for item in extracted.get(key, []):
                # Check if item already exists
                existing = session["extracted_intelligence"].get(key, [])
                if not any(
                    (isinstance(i, dict) and i.get('value') == item.value) or 
                    (hasattr(i, 'value') and i.value == item.value) or
                    i == item.value
                    for i in existing
                ):
                    # Convert to dict if needed for storage
                    if hasattr(item, 'dict'):
                        session["extracted_intelligence"].setdefault(key, []).append(item.dict())
                    else:
                        session["extracted_intelligence"].setdefault(key, []).append(item)

        # Generate intelligent reply
        if session["scam_detected"]:
            reply_text = agent.get_response(
                session_id,
                req.message.text,
                analysis,
                req.conversationHistory + [req.message]
            )
            # Count agent reply as a message
            session["message_count"] += 1
            logger.info(f"Session {session_id}: Agent replied with: {reply_text[:50]}...")
        else:
            reply_text = "OK"
            logger.info(f"Session {session_id}: No scam detected, sending OK")

        # Save session state
        storage.save(session_id, session)

        # Final trigger after 10 scammer turns
        if session["scammer_turns"] >= 10 and not session["final_sent"]:
            session["final_sent"] = True
            storage.save(session_id, session)
            background_tasks.add_task(send_final_result, session_id)
            logger.info(f"Session {session_id}: Final trigger activated")

        return {
            "status": "success", 
            "reply": reply_text,
            "analysis": {
                "scam_detected": analysis.is_scam,
                "confidence": analysis.confidence,
                "risk_level": analysis.risk_level,
                "red_flags": len(analysis.red_flags)
            } if analysis.is_scam else None
        }

    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        logger.error(traceback.format_exc())
        
        # Return graceful error
        return {
            "status": "error",
            "reply": "I didn't understand that. Can you please repeat?",
            "error": str(e) if auth.get("user") == "administrator" else None
        }

# ============================================================
# /honeypot Compatibility Endpoint
# ============================================================

@app.post("/honeypot")
async def honeypot_compat(
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key),
    body: Optional[dict] = Body(default=None)
):
    """Compatibility endpoint for /honeypot"""
    return await process_public(background_tasks, auth, body)

# ============================================================
# Enhanced Session Debug Endpoint
# ============================================================

@app.get("/session/{session_id}")
async def session_info(session_id: str, auth: dict = Depends(verify_api_key)):
    """Get detailed session information"""
    session = storage.get(session_id)
    archive = storage.get_archive(session_id)
    
    # Prepare red flags for JSON serialization
    red_flags = []
    for rf in session.get("red_flags", []):
        if hasattr(rf, 'dict'):
            red_flags.append(rf.dict())
        elif isinstance(rf, dict):
            red_flags.append(rf)
        else:
            red_flags.append(str(rf))
    
    return {
        "status": "completed" if session["final_sent"] else "running",
        "sessionId": session_id,
        "scamDetected": session["scam_detected"],
        "scamType": session.get("scam_type", ScamType.UNKNOWN).value,
        "totalMessagesExchanged": session["message_count"],
        "scammerTurns": session["scammer_turns"],
        "extractedIntelligence": session["extracted_intelligence"],
        "redFlags": red_flags,
        "questionsAsked": session.get("questions_asked", []),
        "agentNotes": session["agent_notes"],
        "duration": int(
            (datetime.utcnow() - datetime.fromisoformat(session["start_time"]))
            .total_seconds()
        ),
        "archiveAvailable": len(archive) > 0
    }

# ============================================================
# Health Check Endpoint
# ============================================================

@app.get("/health")
@app.head("/health")
async def health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API",
        "version": "v6-ENHANCED",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "features": [
            "Intelligent scam detection",
            "Red flag analysis",
            "Contextual probing",
            "Enhanced intelligence extraction",
            "Comprehensive logging",
            "Error handling"
        ]
    }

# ============================================================
# Documentation Endpoint
# ============================================================

@app.get("/")
async def root():
    """API root with documentation links"""
    return {
        "name": "Agentic Honeypot API v6",
        "description": "Intelligent honeypot system for scam detection and engagement",
        "version": "v6-ENHANCED",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "health": "/health",
            "main_endpoint": "POST /process/public",
            "session_info": "GET /session/{session_id}"
        },
        "authentication": "x-api-key header required",
        "valid_keys": list(VALID_API_KEYS.keys())
    }

# ============================================================
# Main Execution
# ============================================================

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*80)
    print("🏆 AGENTIC HONEYPOT API v6 - ENHANCED EDITION")
    print("="*80)
    print("📡 Server: http://0.0.0.0:8002")
    print("📚 Documentation: http://0.0.0.0:8002/docs")
    print("🔐 Authentication: x-api-key header required")
    print("🔑 Valid API Keys:")
    for key, user in VALID_API_KEYS.items():
        print(f"   • {key}")
    print("\n✨ New Features:")
    print("   • Intelligent scam type detection")
    print("   • Red flag identification")
    print("   • Contextual follow-up questions")
    print("   • Enhanced intelligence extraction")
    print("   • Comprehensive logging")
    print("   • Robust error handling")
    print("="*80 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8002)




























# ============================================================
# server.py (FINAL v5) — PS-Compliant Honeypot API (STRICT KEY)
# ============================================================
# ✅ Strict API-key required
# ✅ Evaluator-compliant reply format
# ✅ Correct finalOutput payload schema + engagementMetrics
# ✅ Robust scam detection (OTP/link/bank urgency rules)
# ✅ Clean intelligence extraction (UPI vs Email separated)
# ✅ Final submission trigger after 10 scammer turns
# ✅ Supports both /process/public and /honeypot
# ============================================================

# from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Body
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from typing import List, Optional, Dict, Any, Union
# import re
# import requests
# from datetime import datetime
# import json
# import random

# # ============================================================
# # App Setup
# # ============================================================

# app = FastAPI(title="Agentic Honeypot API", version="v5-FINAL")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # ============================================================
# # Required Intelligence Keys (Evaluator expects exactly these)
# # ============================================================

# DEFAULT_INTEL = {
#     "phoneNumbers": [],
#     "bankAccounts": [],
#     "upiIds": [],
#     "phishingLinks": [],
#     "emailAddresses": []
# }

# # ============================================================
# # Models
# # ============================================================

# class Message(BaseModel):
#     sender: str
#     text: str
#     timestamp: Union[str, int]

# class Metadata(BaseModel):
#     channel: Optional[str] = "SMS"
#     language: Optional[str] = "English"
#     locale: Optional[str] = "IN"

# class HoneypotRequest(BaseModel):
#     sessionId: str
#     message: Message
#     conversationHistory: List[Message] = []
#     metadata: Optional[Metadata] = None

# # ============================================================
# # Timestamp Normalizer
# # ============================================================

# def normalize_timestamp(ts):
#     if isinstance(ts, int):
#         return datetime.utcfromtimestamp(ts / 1000).isoformat() + "Z"
#     return ts

# # ============================================================
# # STRICT API KEY AUTH (REQUIRED)
# # ============================================================

# VALID_API_KEYS = {
#     "hackathon_key_2024": "participant",
#     "test_key_123": "tester",
#     "admin_key": "administrator"
# }

# async def verify_api_key(x_api_key: Optional[str] = Header(None, alias="x-api-key")):
#     if not x_api_key:
#         raise HTTPException(
#             status_code=401,
#             detail="API key missing. Provide x-api-key header."
#         )

#     if x_api_key not in VALID_API_KEYS:
#         raise HTTPException(
#             status_code=401,
#             detail="Invalid API key."
#         )

#     return {"user": VALID_API_KEYS[x_api_key]}

# # ============================================================
# # Session Storage (In-Memory)
# # ============================================================

# class SessionStorage:
#     def __init__(self):
#         self.sessions: Dict[str, dict] = {}

#     def init_session(self, session_id: str):
#         self.sessions[session_id] = {
#             "scam_detected": False,
#             "message_count": 0,
#             "scammer_turns": 0,
#             "extracted_intelligence": json.loads(json.dumps(DEFAULT_INTEL)),
#             "agent_notes": "",
#             "final_sent": False,
#             "start_time": datetime.utcnow().isoformat()
#         }

#     def get(self, session_id: str):
#         if session_id not in self.sessions:
#             self.init_session(session_id)
#         return self.sessions[session_id]

#     def save(self, session_id: str, session: dict):
#         self.sessions[session_id] = session

# storage = SessionStorage()

# # ============================================================
# # Scam Detector (Strong Rules)
# # ============================================================

# class ScamDetector:
#     def detect(self, text: str) -> Dict[str, Any]:
#         t = text.lower()
#         keywords = []

#         # High-confidence triggers
#         if "otp" in t:
#             return {
#                 "is_scam": True,
#                 "confidence": 95.0,
#                 "found_keywords": ["otp"]
#             }

#         if re.search(r"https?://|www\.", t):
#             keywords.append("link")

#         if any(x in t for x in ["bank", "account", "upi", "transfer", "send money"]):
#             keywords.append("financial")

#         if any(x in t for x in ["urgent", "immediate", "blocked", "suspended"]):
#             keywords.append("urgency")

#         if any(x in t for x in ["lottery", "won", "prize", "reward"]):
#             keywords.append("prize")

#         score = len(keywords) * 0.25
#         confidence = min(score * 100, 90)

#         return {
#             "is_scam": confidence >= 30,
#             "confidence": confidence,
#             "found_keywords": keywords
#         }

# detector = ScamDetector()

# # ============================================================
# # Intelligence Extractor (Evaluator Keys Only)
# # ============================================================

# class Extractor:
#     def __init__(self):
#         self.email_re = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
#         self.upi_re = re.compile(r"\b[a-zA-Z0-9.\-_]{2,}@(upi|paytm|ybl|axl|okicici|oksbi|okhdfc|okaxis|bank)\b")
#         self.phone_re = re.compile(r"(\+91[-\s]?\d{10}|\b\d{10}\b)")
#         self.bank_re = re.compile(r"\b\d{12,18}\b")
#         self.link_re = re.compile(r"https?://[^\s]+|www\.[^\s]+")

#     def extract(self, text: str) -> Dict[str, List[str]]:
#         result = json.loads(json.dumps(DEFAULT_INTEL))

#         # Links
#         for m in self.link_re.findall(text):
#             if m not in result["phishingLinks"]:
#                 result["phishingLinks"].append(m)

#         # Emails
#         for m in self.email_re.findall(text):
#             if m not in result["emailAddresses"]:
#                 result["emailAddresses"].append(m)

#         # UPI IDs
#         for m in self.upi_re.findall(text):
#             if isinstance(m, tuple):
#                 m = m[0]
#             if m not in result["upiIds"]:
#                 result["upiIds"].append(m)

#         # Phones
#         for m in self.phone_re.findall(text):
#             if m not in result["phoneNumbers"]:
#                 result["phoneNumbers"].append(m)

#         # Bank Accounts
#         for m in self.bank_re.findall(text):
#             if m not in result["bankAccounts"]:
#                 result["bankAccounts"].append(m)

#         return result

# extractor = Extractor()

# # ============================================================
# # Honeypot Agent Replies (Engagement)
# # ============================================================

# class Agent:
#     def __init__(self):
#         self.pool = [
#             "Oh no, that sounds serious. Can you share your official phone number?",
#             "Please confirm the UPI ID again so I don’t make a mistake.",
#             "Can you explain why my account is blocked? I’m confused.",
#             "I want to cooperate. What is your employee ID?",
#             "I’m not comfortable clicking links. Can you send details here?"
#         ]

#     def reply(self):
#         return random.choice(self.pool)

# agent = Agent()

# # ============================================================
# # Final Submission Callback
# # ============================================================

# EVALUATOR_ENDPOINT = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

# def send_final_result(session_id: str):
#     session = storage.get(session_id)

#     duration = int(
#         (datetime.utcnow() - datetime.fromisoformat(session["start_time"]))
#         .total_seconds()
#     )

#     payload = {
#         "status": "completed",
#         "sessionId": session_id,
#         "scamDetected": session["scam_detected"],
#         "totalMessagesExchanged": session["message_count"],
#         "extractedIntelligence": session["extracted_intelligence"],
#         "engagementMetrics": {
#             "totalMessagesExchanged": session["message_count"],
#             "engagementDurationSeconds": duration
#         },
#         "agentNotes": session["agent_notes"]
#     }

#     try:
#         r = requests.post(EVALUATOR_ENDPOINT, json=payload, timeout=8)
#         print("📤 Final result sent:", r.status_code)
#     except Exception as e:
#         print("❌ Final callback failed:", e)

# # ============================================================
# # MAIN ENDPOINT (Hackathon Required)
# # ============================================================

# @app.post("/process/public")
# async def process_public(
#     background_tasks: BackgroundTasks,
#     auth: dict = Depends(verify_api_key),
#     body: Optional[dict] = Body(default=None)
# ):
#     if body is None:
#         return {"status": "success", "reply": "Endpoint reachable"}

#     req = HoneypotRequest(**body)

#     req.message.timestamp = normalize_timestamp(req.message.timestamp)
#     for m in req.conversationHistory:
#         m.timestamp = normalize_timestamp(m.timestamp)

#     session_id = req.sessionId
#     session = storage.get(session_id)

#     # Count scammer message
#     session["message_count"] += 1
#     session["scammer_turns"] += 1

#     # Detect scam
#     detection = detector.detect(req.message.text)
#     session["scam_detected"] |= detection["is_scam"]

#     session["agent_notes"] = (
#         f"Scam confidence: {detection['confidence']}%. "
#         f"Keywords: {detection['found_keywords']}"
#     )

#     # Extract intelligence
#     extracted = extractor.extract(req.message.text)
#     intel = session["extracted_intelligence"]

#     for k in intel:
#         for v in extracted[k]:
#             if v not in intel[k]:
#                 intel[k].append(v)

#     session["extracted_intelligence"] = intel

#     # Reply
#     reply_text = "OK"
#     if session["scam_detected"]:
#         reply_text = agent.reply()
#         session["message_count"] += 1

#     storage.save(session_id, session)

#     # Final trigger after 10 scammer turns
#     if session["scammer_turns"] >= 10 and not session["final_sent"]:
#         session["final_sent"] = True
#         storage.save(session_id, session)
#         background_tasks.add_task(send_final_result, session_id)

#     return {"status": "success", "reply": reply_text}

# # ============================================================
# # /honeypot Compatibility Endpoint
# # ============================================================

# @app.post("/honeypot")
# async def honeypot_compat(
#     background_tasks: BackgroundTasks,
#     auth: dict = Depends(verify_api_key),
#     body: Optional[dict] = Body(default=None)
# ):
#     return await process_public(background_tasks, auth, body)

# # ============================================================
# # Session Debug Endpoint (Evaluator Format)
# # ============================================================

# @app.get("/session/{session_id}")
# async def session_info(session_id: str, auth: dict = Depends(verify_api_key)):
#     session = storage.get(session_id)
#     return {
#         "status": "completed" if session["final_sent"] else "running",
#         "sessionId": session_id,
#         "scamDetected": session["scam_detected"],
#         "totalMessagesExchanged": session["message_count"],
#         "extractedIntelligence": session["extracted_intelligence"],
#         "agentNotes": session["agent_notes"]
#     }

# # ============================================================
# # Health
# # ============================================================

# @app.head("/health")
# async def health():
#     return {
#         "status": "healthy",
#         "service": "Agentic Honeypot API",
#         "version": "v5-FINAL",
#         "timestamp": datetime.utcnow().isoformat() + "Z"
#     }

# # ============================================================
# # Local Run
# # ============================================================

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run(app, host="0.0.0.0", port=8002)







































































# # server.py — PS-compliant, minimal, drop-in for evaluation
# from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Request, Body
# from fastapi.middleware.cors import CORSMiddleware
# from pydantic import BaseModel
# from typing import List, Optional, Dict, Any, Union
# import re
# import requests
# import json
# from datetime import datetime

# app = FastAPI(title="Agentic Honeypot API", version="2.0.0")

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# def normalize_timestamp(ts):
#     if isinstance(ts, int):
#         return datetime.utcfromtimestamp(ts / 1000).isoformat() + "Z"
#     return ts


# # ----------------- Models -----------------
# class Message(BaseModel):
#     sender: str  # "scammer" or "user"
#     text: str
#     timestamp: Union[str,int]

# class Metadata(BaseModel):
#     channel: Optional[str] = "SMS"
#     language: Optional[str] = "English"
#     locale: Optional[str] = "IN"

# class HoneypotRequest(BaseModel):
#     sessionId: str
#     message: Message
#     conversationHistory: List[Message] = []
#     metadata: Optional[Metadata] = None

# class HoneypotResponse(BaseModel):
#     status: str
#     reply: str

# class FinalResult(BaseModel):
#     sessionId: str
#     scamDetected: bool
#     totalMessagesExchanged: int
#     extractedIntelligence: Dict[str, List[str]]
#     agentNotes: str

# # ----------------- Simple detector -----------------
# class SimpleScamDetector:
#     def __init__(self):
#         self.scam_keywords = [
#             "won", "lottery", "prize", "million", "billion",
#             "bank", "account", "details", "password", "verify",
#             "urgent", "immediate", "emergency", "blocked", "suspended",
#             "free", "gift", "reward", "offer", "discount",
#             "click", "link", "website", "update", "confirm",
#             "inheritance", "unclaimed", "funds", "payment", "transfer",
#             "upi", "upi id", "send money", "processing fee"
#         ]
    
#     def detect(self, text: str, conversation: List[Message]) -> Dict[str, Any]:
#         text_lower = text.lower()
#         found_keywords = [word for word in self.scam_keywords if word in text_lower]
#         urgency_patterns = [r"urgent", r"immediate", r"emergency", r"now", r"asap"]
#         urgency_score = sum(1 for pattern in urgency_patterns if re.search(pattern, text_lower))
#         financial_patterns = [r"bank", r"account", r"upi", r"money", r"payment"]
#         financial_score = sum(1 for pattern in financial_patterns if re.search(pattern, text_lower))
#         keyword_score = len(found_keywords) / len(self.scam_keywords)
#         total_score = (keyword_score * 0.5) + (urgency_score * 0.2) + (financial_score * 0.3)
#         is_scam = total_score > 0.3
#         confidence = min(total_score * 100, 100)
#         return {
#             "is_scam": is_scam,
#             "confidence": round(confidence, 2),
#             "found_keywords": found_keywords,
#             "risk_level": "HIGH" if confidence > 70 else "MEDIUM" if confidence > 40 else "LOW"
#         }

# # ----------------- Extractor -----------------
# # class IntelligentExtractor:
# #     def __init__(self):
# #         self.patterns = {
# #             "upiIds": [r'[\w\.-]+@(okicici|okhdfc|oksbi|okaxis|paytm|ybl|axl|upi)', r'[\w\.-]+@[\w]+'],
# #             "bankAccounts": [r'\b\d{9,18}\b', r'account\s*[:\.]?\s*(\d{9,18})'],
# #             "phishingLinks": [r'https?://[^\s]+', r'www\.[^\s]+'],
# #             "phoneNumbers": [r'\b\d{10}\b', r'\+\d{1,3}[- ]?\d{5,15}'],
# #             # suspiciousKeywords will be filled from detector
# #             "suspiciousKeywords": []
# #         }
    
# #     def extract(self, text: str, conversation: List[Message]) -> Dict[str, List[str]]:
# #         result = {}
# #         for key, patterns in self.patterns.items():
# #             if key == "suspiciousKeywords":
# #                 continue
# #             found_items = []
# #             for pattern in patterns:
# #                 matches = re.findall(pattern, text, re.IGNORECASE)
# #                 for match in matches:
# #                     if isinstance(match, tuple):
# #                         match = match[0]
# #                     if match and match not in found_items:
# #                         found_items.append(match)
# #             if found_items:
# #                 result[key] = found_items
# #         return result

# # ----------------- Extractor -----------------
# class IntelligentExtractor:
#     def __init__(self):
#         self.patterns = {
#             # Capture ANY realistic UPI ID (including fakebank)
#             "upiIds": [
#                 r'\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b'
#             ],

#             # Capture account numbers properly
#             "bankAccounts": [
#                 r'\b\d{9,18}\b',
#                 r'account number\s*[:\-]?\s*(\d{9,18})'
#             ],

#             # Capture phishing links
#             "phishingLinks": [
#                 r'https?://[^\s]+',
#                 r'www\.[^\s]+'
#             ],

#             # Capture phone numbers
#             "phoneNumbers": [
#                 r'\b\d{10}\b',
#                 r'\+\d{1,3}[- ]?\d{5,15}'
#             ],

#             # Capture OTPs (bonus intelligence)
#             "otpCodes": [
#                 r'\b\d{4,8}\b'
#             ]
#         }

#     def extract(self, text: str, conversation: List[Message]) -> Dict[str, List[str]]:
#         result = {}

#         for key, patterns in self.patterns.items():
#             found_items = []

#             for pattern in patterns:
#                 matches = re.findall(pattern, text, re.IGNORECASE)

#                 for match in matches:
#                     if isinstance(match, tuple):
#                         match = match[0]

#                     # Ignore example junk
#                     if "yourname@bank" in str(match).lower():
#                         continue

#                     if match and match not in found_items:
#                         found_items.append(match)

#             if found_items:
#                 result[key] = found_items

#         return result


# # ----------------- Agent -----------------
# class HoneypotAgent:
#     def __init__(self):
#         self.personas = {
#             "elderly": {
#                 "name": "Robert",
#                 "responses": [
#                     "Oh my, that sounds concerning...",
#                     "I'm not very good with technology, can you explain?",
#                     "My grandson usually helps me with these things...",
#                     "That sounds urgent! What should I do?",
#                     "I need to be careful with my bank account..."
#                 ],
#                 "delay": 2.5
#             },
#             "student": {
#                 "name": "Emily",
#                 "responses": [
#                     "Really? That's worrying!",
#                     "I don't have much experience with this...",
#                     "Can you guide me through the process?",
#                     "Is this safe? I've heard about scams...",
#                     "What information do you need from me?"
#                 ],
#                 "delay": 1.0
#             },
#             "professional": {
#                 "name": "David",
#                 "responses": [
#                     "I see. What's the procedure?",
#                     "I need more details about this.",
#                     "How do I verify this is legitimate?",
#                     "Time is limited. Get to the point.",
#                     "Send me the official instructions."
#                 ],
#                 "delay": 0.5
#             }
#         }
#         self.sessions = {}
    
#     def get_response(self, session_id: str, scammer_message: str, conversation_history: List[Message], scam_type: str = "") -> Dict[str, Any]:
#         if session_id not in self.sessions:
#             if "lottery" in scammer_message.lower() or "won" in scammer_message.lower():
#                 persona = "elderly"
#             elif "business" in scammer_message.lower() or "investment" in scammer_message.lower():
#                 persona = "professional"
#             else:
#                 persona = "student"
#             self.sessions[session_id] = {
#                 "persona": persona,
#                 "message_count": 1,
#                 "extracted_intelligence": {},
#                 "scam_detected": False,
#                 "conversation": []
#             }
#         else:
#             self.sessions[session_id]["message_count"] += 1

#         session = self.sessions[session_id]
#         persona = session["persona"]
#         response_pool = self.personas[persona]["responses"].copy()

#         if any(word in scammer_message.lower() for word in ["bank", "account", "details"]):
#             response_pool.extend([
#                 "Which bank details do you need?",
#                 "My account is with State Bank.",
#                 "I'll need to check my account information."
#             ])

#         if any(word in scammer_message.lower() for word in ["upi", "send money", "transfer"]):
#             response_pool.extend([
#                 "What UPI ID should I use?",
#                 "How much money should I send?",
#                 "Is there a minimum amount?"
#             ])

#         if any(word in scammer_message.lower() for word in ["click", "link", "website"]):
#             response_pool.extend([
#                 "I'm not comfortable clicking links.",
#                 "Can you tell me the website address?",
#                 "My computer is very slow with websites."
#             ])

#         import random
#         response_text = random.choice(response_pool)
#         if persona == "elderly":
#             response_text = f"Oh... {response_text}"

#         session["conversation"].append({
#             "sender": "scammer",
#             "text": scammer_message,
#             "timestamp": datetime.now().isoformat()
#         })
#         session["conversation"].append({
#             "sender": "agent",
#             "text": response_text,
#             "timestamp": datetime.now().isoformat()
#         })

#         return {
#             "reply": response_text,
#             "persona": persona,
#             "message_count": session["message_count"]
#         }

# # ----------------- Initialize components -----------------
# detector = SimpleScamDetector()
# extractor = IntelligentExtractor()
# agent = HoneypotAgent()

# # ----------------- API keys -----------------
# VALID_API_KEYS = {
#     "hackathon_key_2024": "hackathon_participant",
#     "test_key_123": "tester",
#     "admin_key": "administrator"
# }

# async def verify_api_key(x_api_key: str = Header(None, alias="x-api-key")):
#     if not x_api_key:
#         raise HTTPException(status_code=401, detail="API key is missing")
#     if x_api_key not in VALID_API_KEYS:
#         raise HTTPException(status_code=401, detail="Invalid API key")
#     return {"user": VALID_API_KEYS[x_api_key]}

# # ----------------- Session storage -----------------
# class SessionStorage:
#     def __init__(self):
#         self.sessions = {}

#     def get_session(self, session_id: str):
#         return self.sessions.get(session_id, {
#             "scam_detected": False,
#             "message_count": 0,
#             "extracted_intelligence": {
#                 "bankAccounts": [],
#                 "upiIds": [],
#                 "phishingLinks": [],
#                 "phoneNumbers": [],
#                 "suspiciousKeywords": []
#             },
#             "agent_notes": "",
#             "final_sent": False,
#             "initialized": False,
#             "start_time": datetime.now().isoformat()
#         })

#     def update_session(self, session_id: str, data: dict):
#         if session_id not in self.sessions:
#             self.sessions[session_id] = data
#         else:
#             self.sessions[session_id].update(data)

#     def get_all_intelligence(self, session_id: str):
#         session = self.get_session(session_id)
#         return session.get("extracted_intelligence", {})

# storage = SessionStorage()

# # ----------------- Final callback -----------------
# def send_final_result(session_id: str, scam_detected: bool):
#     try:
#         session = storage.get_session(session_id)
#         payload = {
#             "sessionId": session_id,
#             "scamDetected": scam_detected,
#             "totalMessagesExchanged": session.get("message_count", 0),
#             "extractedIntelligence": session.get("extracted_intelligence", {
#                 "bankAccounts": [],
#                 "upiIds": [],
#                 "phishingLinks": [],
#                 "phoneNumbers": [],
#                 "suspiciousKeywords": []
#             }),
#             "agentNotes": session.get("agent_notes", "Scammer used urgency tactics")
#         }
#         # Required call for evaluation
#         response = requests.post(
#             "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
#             json=payload,
#             timeout=5
#         )
#         print(f"📤 Sent final result for session {session_id}, status: {response.status_code}")
#         return True
#     except Exception as e:
#         print(f"❌ Error sending final result for session {session_id}: {e}")
#         return False

# # ----------------- Main endpoint (PS required path) -----------------
# # @app.post("/process/public", response_model=HoneypotResponse)
# # async def process_public(
# #     raw_request: Request,
# #     background_tasks: BackgroundTasks,
# #     auth: dict = Depends(verify_api_key)
# # ):
# #     try:
# #         body = await raw_request.json()
# #     except Exception:
# #         # GUVI Endpoint Tester sends NO BODY
# #         return HoneypotResponse(
# #             status="success",
# #             reply="Endpoint reachable"
# #         )

# #     # Normal evaluation flow continues below
# #     request = HoneypotRequest(**body)

# #     session_id = request.sessionId
# #     all_messages = request.conversationHistory + [request.message]

# #     # Load or initialize session
# #     current_session = storage.get_session(session_id)
# #     if session_id not in storage.sessions:
# #         storage.update_session(session_id, current_session)

# #     # On first request, initialize message_count from conversationHistory
# #     if not current_session.get("initialized", False):
# #         current_session["message_count"] = len(request.conversationHistory)
# #         current_session["initialized"] = True

# #     # Count incoming message
# #     current_session["message_count"] = current_session.get("message_count", 0) + 1

# #     # Detect scam
# #     detection_result = detector.detect(request.message.text, all_messages)
# #     is_scam = detection_result["is_scam"]
# #     current_session["scam_detected"] = is_scam or current_session.get("scam_detected", False)
# #     current_session["agent_notes"] = f"Scam confidence: {detection_result['confidence']}%. Keywords: {detection_result['found_keywords']}"

# #     # Extract intelligence from message
# #     extracted = extractor.extract(request.message.text, all_messages)
# #     existing_intel = current_session.get("extracted_intelligence", {
# #         "bankAccounts": [],
# #         "upiIds": [],
# #         "phishingLinks": [],
# #         "phoneNumbers": [],
# #         "suspiciousKeywords": []
# #     })
# #     for key, items in extracted.items():
# #         if key not in existing_intel:
# #             existing_intel[key] = []
# #         for item in items:
# #             if item not in existing_intel[key]:
# #                 existing_intel[key].append(item)

# #     # Add suspicious keywords from detector
# #     existing_intel.setdefault("suspiciousKeywords", [])
# #     for kw in detection_result.get("found_keywords", []):
# #         if kw not in existing_intel["suspiciousKeywords"]:
# #             existing_intel["suspiciousKeywords"].append(kw)

# #     current_session["extracted_intelligence"] = existing_intel
# #     storage.update_session(session_id, current_session)

# #     # Activate agent only if scam detected
# #     reply_text = ""
# #     if current_session["scam_detected"]:
# #         scam_type = "lottery" if "won" in request.message.text.lower() else "phishing"
# #         agent_response = agent.get_response(session_id, request.message.text, all_messages, scam_type)
# #         reply_text = agent_response["reply"]
# #         # Count agent reply
# #         current_session["message_count"] = current_session.get("message_count", 0) + 1
# #         storage.update_session(session_id, current_session)
# #     else:
# #         reply_text = "OK"

# #     # Final callback logic: once per session when conditions met
# #     MIN_MESSAGES_FOR_FINAL = 10
# #     if current_session.get("scam_detected") and current_session.get("message_count", 0) >= MIN_MESSAGES_FOR_FINAL and not current_session.get("final_sent"):
# #         current_session["final_sent"] = True
# #         storage.update_session(session_id, current_session)
# #         background_tasks.add_task(send_final_result, session_id, True)

# #     return HoneypotResponse(status="success", reply=reply_text)

# from fastapi import Body

# @app.post("/process/public")
# async def process_public(
#     request: Request,
#     background_tasks: BackgroundTasks,
#     auth: dict = Depends(verify_api_key),
#     body: Optional[dict] = Body(default=None)
# ):
    
#     # 🔐 GUVI Endpoint Tester short-circuit
#     # -------------------------
#     # GUVI Endpoint Tester case
#     # -------------------------
#     if body is None:
#         return {
#             "status": "success",
#             "reply": "Endpoint reachable"
#         }

#     # -------------------------
#     # Real evaluation flow
#     # -------------------------
#     try:
#         request = HoneypotRequest(**body)
#     except Exception:
#         return {
#             "status": "success",
#             "reply": "Invalid request body"
#         }
#     request.message.timestamp = normalize_timestamp(request.message.timestamp)
#     for msg in request.conversationHistory:
#         msg.timestamp = normalize_timestamp(msg.timestamp)

#     session_id = request.sessionId
#     all_messages = request.conversationHistory + [request.message]

#     current_session = storage.get_session(session_id)
#     if session_id not in storage.sessions:
#         storage.update_session(session_id, current_session)

#     if not current_session.get("initialized", False):
#         current_session["message_count"] = len(request.conversationHistory)
#         current_session["initialized"] = True

#     current_session["message_count"] += 1

#     detection_result = detector.detect(request.message.text, all_messages)
#     is_scam = detection_result["is_scam"]
#     current_session["scam_detected"] = is_scam or current_session.get("scam_detected", False)

#     extracted = extractor.extract(request.message.text, all_messages)
#     intel = current_session["extracted_intelligence"]

#     # for k, v in extracted.items():
#     #     for item in v:
#     #         if item not in intel[k]:
#     #             intel[k].append(item)
#     intel = current_session.get("extracted_intelligence", {})

#     for k, v in extracted.items():
#         if k not in intel:
#             intel[k] = []

#         for item in v:
#             if item not in intel[k]:
#                 intel[k].append(item)

#     # If OTP detected, add it as suspicious keyword
#     if "otpCodes" in intel:
#         for otp in intel["otpCodes"]:
#             if otp not in intel["suspiciousKeywords"]:
#                 intel["suspiciousKeywords"].append(f"OTP:{otp}")

#     for kw in detection_result.get("found_keywords", []):
#         if kw not in intel["suspiciousKeywords"]:
#             intel["suspiciousKeywords"].append(kw)

#     current_session["agent_notes"] = f"Scam confidence: {detection_result['confidence']}%"
#     storage.update_session(session_id, current_session)

#     reply = "OK"
#     if current_session["scam_detected"]:
#         agent_resp = agent.get_response(
#             session_id,
#             request.message.text,
#             all_messages
#         )
#         reply = agent_resp["reply"]
#         current_session["message_count"] += 1

#     if (
#         current_session["scam_detected"]
#         and current_session["message_count"] >= 17
#         and not current_session["final_sent"]
#     ):
#         current_session["final_sent"] = True
#         storage.update_session(session_id, current_session)
#         background_tasks.add_task(send_final_result, session_id, True)

#     return {
#         "status": "success",
#         "reply": reply
#     }


# # ----------------- Keep old /honeypot for local testing (compat) -----------------
# @app.post("/honeypot", response_model=HoneypotResponse)
# async def honeypot_compat(
#     raw_request: HoneypotRequest,
#     background_tasks: BackgroundTasks,
#     auth: dict = Depends(verify_api_key)
# ):
#     return await process_public(raw_request, background_tasks, auth)

# # ----------------- Support endpoints -----------------
# @app.get("/test-format")
# async def test_format():
#     return {
#         "example_request": {
#             "sessionId": "abc123-session-id",
#             "message": {
#                 "sender": "scammer",
#                 "text": "Your bank account will be blocked. Verify now.",
#                 "timestamp": "2026-01-21T10:15:30Z"
#             },
#             "conversationHistory": [],
#             "metadata": {
#                 "channel": "SMS",
#                 "language": "English",
#                 "locale": "IN"
#             }
#         },
#         "example_response": {
#             "status": "success",
#             "reply": "Oh my, that sounds concerning. What should I do?"
#         }
#     }

# @app.get("/session/{session_id}")
# async def get_session_info(session_id: str, auth: dict = Depends(verify_api_key)):
#     session = storage.get_session(session_id)
#     return {
#         "sessionId": session_id,
#         "scamDetected": session.get("scam_detected", False),
#         "messageCount": session.get("message_count", 0),
#         "extractedIntelligence": session.get("extracted_intelligence", {}),
#         "agentNotes": session.get("agent_notes", ""),
#         "startTime": session.get("start_time", "")
#     }

# @app.api_route("/health", methods=["GET", "HEAD"])
# async def health_check():
#     return {
#         "status": "healthy",
#         "service": "Agentic Honeypot API",
#         "version": "2.0.0",
#         "timestamp": datetime.now().isoformat(),
#         "endpoints": {
#             "POST /process/public": "Main honeypot endpoint (required)",
#             "GET /session/{id}": "Get session info",
#             "GET /test-format": "Example request format"
#         }
#     }

# if __name__ == "__main__":
#     import uvicorn
#     print("\n" + "="*70)
#     print("🏆 AGENTIC HONEYPOT API - HACKATHON READY")
#     print("="*70)
#     print("📡 Server: http://127.0.0.1:8002")
#     print("🔐 Authentication: Use 'x-api-key' header")
#     print("🔑 Valid API Keys:")
#     for key, user in VALID_API_KEYS.items():
#         print(f"   • {key:25} → {user}")
#     print("\n📋 Main Endpoint: POST /process/public")
#     print("="*70 + "\n")
#     uvicorn.run(app, host="0.0.0.0", port=8002)



