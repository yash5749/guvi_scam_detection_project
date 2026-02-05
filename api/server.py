# server.py — PS-compliant, minimal, drop-in for evaluation
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks, Request, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any, Union
import re
import requests
import json
from datetime import datetime

app = FastAPI(title="Agentic Honeypot API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def normalize_timestamp(ts):
    if isinstance(ts, int):
        return datetime.utcfromtimestamp(ts / 1000).isoformat() + "Z"
    return ts


# ----------------- Models -----------------
class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: Union[str,int]

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: List[Message] = []
    metadata: Optional[Metadata] = None

class HoneypotResponse(BaseModel):
    status: str
    reply: str

class FinalResult(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: Dict[str, List[str]]
    agentNotes: str

# ----------------- Simple detector -----------------
class SimpleScamDetector:
    def __init__(self):
        self.scam_keywords = [
            "won", "lottery", "prize", "million", "billion",
            "bank", "account", "details", "password", "verify",
            "urgent", "immediate", "emergency", "blocked", "suspended",
            "free", "gift", "reward", "offer", "discount",
            "click", "link", "website", "update", "confirm",
            "inheritance", "unclaimed", "funds", "payment", "transfer",
            "upi", "upi id", "send money", "processing fee"
        ]
    
    def detect(self, text: str, conversation: List[Message]) -> Dict[str, Any]:
        text_lower = text.lower()
        found_keywords = [word for word in self.scam_keywords if word in text_lower]
        urgency_patterns = [r"urgent", r"immediate", r"emergency", r"now", r"asap"]
        urgency_score = sum(1 for pattern in urgency_patterns if re.search(pattern, text_lower))
        financial_patterns = [r"bank", r"account", r"upi", r"money", r"payment"]
        financial_score = sum(1 for pattern in financial_patterns if re.search(pattern, text_lower))
        keyword_score = len(found_keywords) / len(self.scam_keywords)
        total_score = (keyword_score * 0.5) + (urgency_score * 0.2) + (financial_score * 0.3)
        is_scam = total_score > 0.3
        confidence = min(total_score * 100, 100)
        return {
            "is_scam": is_scam,
            "confidence": round(confidence, 2),
            "found_keywords": found_keywords,
            "risk_level": "HIGH" if confidence > 70 else "MEDIUM" if confidence > 40 else "LOW"
        }

# ----------------- Extractor -----------------
# class IntelligentExtractor:
#     def __init__(self):
#         self.patterns = {
#             "upiIds": [r'[\w\.-]+@(okicici|okhdfc|oksbi|okaxis|paytm|ybl|axl|upi)', r'[\w\.-]+@[\w]+'],
#             "bankAccounts": [r'\b\d{9,18}\b', r'account\s*[:\.]?\s*(\d{9,18})'],
#             "phishingLinks": [r'https?://[^\s]+', r'www\.[^\s]+'],
#             "phoneNumbers": [r'\b\d{10}\b', r'\+\d{1,3}[- ]?\d{5,15}'],
#             # suspiciousKeywords will be filled from detector
#             "suspiciousKeywords": []
#         }
    
#     def extract(self, text: str, conversation: List[Message]) -> Dict[str, List[str]]:
#         result = {}
#         for key, patterns in self.patterns.items():
#             if key == "suspiciousKeywords":
#                 continue
#             found_items = []
#             for pattern in patterns:
#                 matches = re.findall(pattern, text, re.IGNORECASE)
#                 for match in matches:
#                     if isinstance(match, tuple):
#                         match = match[0]
#                     if match and match not in found_items:
#                         found_items.append(match)
#             if found_items:
#                 result[key] = found_items
#         return result

# ----------------- Extractor -----------------
class IntelligentExtractor:
    def __init__(self):
        self.patterns = {
            # Capture ANY realistic UPI ID (including fakebank)
            "upiIds": [
                r'\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b'
            ],

            # Capture account numbers properly
            "bankAccounts": [
                r'\b\d{9,18}\b',
                r'account number\s*[:\-]?\s*(\d{9,18})'
            ],

            # Capture phishing links
            "phishingLinks": [
                r'https?://[^\s]+',
                r'www\.[^\s]+'
            ],

            # Capture phone numbers
            "phoneNumbers": [
                r'\b\d{10}\b',
                r'\+\d{1,3}[- ]?\d{5,15}'
            ],

            # Capture OTPs (bonus intelligence)
            "otpCodes": [
                r'\b\d{4,8}\b'
            ]
        }

    def extract(self, text: str, conversation: List[Message]) -> Dict[str, List[str]]:
        result = {}

        for key, patterns in self.patterns.items():
            found_items = []

            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)

                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]

                    # Ignore example junk
                    if "yourname@bank" in str(match).lower():
                        continue

                    if match and match not in found_items:
                        found_items.append(match)

            if found_items:
                result[key] = found_items

        return result


# ----------------- Agent -----------------
class HoneypotAgent:
    def __init__(self):
        self.personas = {
            "elderly": {
                "name": "Robert",
                "responses": [
                    "Oh my, that sounds concerning...",
                    "I'm not very good with technology, can you explain?",
                    "My grandson usually helps me with these things...",
                    "That sounds urgent! What should I do?",
                    "I need to be careful with my bank account..."
                ],
                "delay": 2.5
            },
            "student": {
                "name": "Emily",
                "responses": [
                    "Really? That's worrying!",
                    "I don't have much experience with this...",
                    "Can you guide me through the process?",
                    "Is this safe? I've heard about scams...",
                    "What information do you need from me?"
                ],
                "delay": 1.0
            },
            "professional": {
                "name": "David",
                "responses": [
                    "I see. What's the procedure?",
                    "I need more details about this.",
                    "How do I verify this is legitimate?",
                    "Time is limited. Get to the point.",
                    "Send me the official instructions."
                ],
                "delay": 0.5
            }
        }
        self.sessions = {}
    
    def get_response(self, session_id: str, scammer_message: str, conversation_history: List[Message], scam_type: str = "") -> Dict[str, Any]:
        if session_id not in self.sessions:
            if "lottery" in scammer_message.lower() or "won" in scammer_message.lower():
                persona = "elderly"
            elif "business" in scammer_message.lower() or "investment" in scammer_message.lower():
                persona = "professional"
            else:
                persona = "student"
            self.sessions[session_id] = {
                "persona": persona,
                "message_count": 1,
                "extracted_intelligence": {},
                "scam_detected": False,
                "conversation": []
            }
        else:
            self.sessions[session_id]["message_count"] += 1

        session = self.sessions[session_id]
        persona = session["persona"]
        response_pool = self.personas[persona]["responses"].copy()

        if any(word in scammer_message.lower() for word in ["bank", "account", "details"]):
            response_pool.extend([
                "Which bank details do you need?",
                "My account is with State Bank.",
                "I'll need to check my account information."
            ])

        if any(word in scammer_message.lower() for word in ["upi", "send money", "transfer"]):
            response_pool.extend([
                "What UPI ID should I use?",
                "How much money should I send?",
                "Is there a minimum amount?"
            ])

        if any(word in scammer_message.lower() for word in ["click", "link", "website"]):
            response_pool.extend([
                "I'm not comfortable clicking links.",
                "Can you tell me the website address?",
                "My computer is very slow with websites."
            ])

        import random
        response_text = random.choice(response_pool)
        if persona == "elderly":
            response_text = f"Oh... {response_text}"

        session["conversation"].append({
            "sender": "scammer",
            "text": scammer_message,
            "timestamp": datetime.now().isoformat()
        })
        session["conversation"].append({
            "sender": "agent",
            "text": response_text,
            "timestamp": datetime.now().isoformat()
        })

        return {
            "reply": response_text,
            "persona": persona,
            "message_count": session["message_count"]
        }

# ----------------- Initialize components -----------------
detector = SimpleScamDetector()
extractor = IntelligentExtractor()
agent = HoneypotAgent()

# ----------------- API keys -----------------
VALID_API_KEYS = {
    "hackathon_key_2024": "hackathon_participant",
    "test_key_123": "tester",
    "admin_key": "administrator"
}

async def verify_api_key(x_api_key: str = Header(None, alias="x-api-key")):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is missing")
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return {"user": VALID_API_KEYS[x_api_key]}

# ----------------- Session storage -----------------
class SessionStorage:
    def __init__(self):
        self.sessions = {}

    def get_session(self, session_id: str):
        return self.sessions.get(session_id, {
            "scam_detected": False,
            "message_count": 0,
            "extracted_intelligence": {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            },
            "agent_notes": "",
            "final_sent": False,
            "initialized": False,
            "start_time": datetime.now().isoformat()
        })

    def update_session(self, session_id: str, data: dict):
        if session_id not in self.sessions:
            self.sessions[session_id] = data
        else:
            self.sessions[session_id].update(data)

    def get_all_intelligence(self, session_id: str):
        session = self.get_session(session_id)
        return session.get("extracted_intelligence", {})

storage = SessionStorage()

# ----------------- Final callback -----------------
def send_final_result(session_id: str, scam_detected: bool):
    try:
        session = storage.get_session(session_id)
        payload = {
            "sessionId": session_id,
            "scamDetected": scam_detected,
            "totalMessagesExchanged": session.get("message_count", 0),
            "extractedIntelligence": session.get("extracted_intelligence", {
                "bankAccounts": [],
                "upiIds": [],
                "phishingLinks": [],
                "phoneNumbers": [],
                "suspiciousKeywords": []
            }),
            "agentNotes": session.get("agent_notes", "Scammer used urgency tactics")
        }
        # Required call for evaluation
        response = requests.post(
            "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
            json=payload,
            timeout=5
        )
        print(f"📤 Sent final result for session {session_id}, status: {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Error sending final result for session {session_id}: {e}")
        return False

# ----------------- Main endpoint (PS required path) -----------------
# @app.post("/process/public", response_model=HoneypotResponse)
# async def process_public(
#     raw_request: Request,
#     background_tasks: BackgroundTasks,
#     auth: dict = Depends(verify_api_key)
# ):
#     try:
#         body = await raw_request.json()
#     except Exception:
#         # GUVI Endpoint Tester sends NO BODY
#         return HoneypotResponse(
#             status="success",
#             reply="Endpoint reachable"
#         )

#     # Normal evaluation flow continues below
#     request = HoneypotRequest(**body)

#     session_id = request.sessionId
#     all_messages = request.conversationHistory + [request.message]

#     # Load or initialize session
#     current_session = storage.get_session(session_id)
#     if session_id not in storage.sessions:
#         storage.update_session(session_id, current_session)

#     # On first request, initialize message_count from conversationHistory
#     if not current_session.get("initialized", False):
#         current_session["message_count"] = len(request.conversationHistory)
#         current_session["initialized"] = True

#     # Count incoming message
#     current_session["message_count"] = current_session.get("message_count", 0) + 1

#     # Detect scam
#     detection_result = detector.detect(request.message.text, all_messages)
#     is_scam = detection_result["is_scam"]
#     current_session["scam_detected"] = is_scam or current_session.get("scam_detected", False)
#     current_session["agent_notes"] = f"Scam confidence: {detection_result['confidence']}%. Keywords: {detection_result['found_keywords']}"

#     # Extract intelligence from message
#     extracted = extractor.extract(request.message.text, all_messages)
#     existing_intel = current_session.get("extracted_intelligence", {
#         "bankAccounts": [],
#         "upiIds": [],
#         "phishingLinks": [],
#         "phoneNumbers": [],
#         "suspiciousKeywords": []
#     })
#     for key, items in extracted.items():
#         if key not in existing_intel:
#             existing_intel[key] = []
#         for item in items:
#             if item not in existing_intel[key]:
#                 existing_intel[key].append(item)

#     # Add suspicious keywords from detector
#     existing_intel.setdefault("suspiciousKeywords", [])
#     for kw in detection_result.get("found_keywords", []):
#         if kw not in existing_intel["suspiciousKeywords"]:
#             existing_intel["suspiciousKeywords"].append(kw)

#     current_session["extracted_intelligence"] = existing_intel
#     storage.update_session(session_id, current_session)

#     # Activate agent only if scam detected
#     reply_text = ""
#     if current_session["scam_detected"]:
#         scam_type = "lottery" if "won" in request.message.text.lower() else "phishing"
#         agent_response = agent.get_response(session_id, request.message.text, all_messages, scam_type)
#         reply_text = agent_response["reply"]
#         # Count agent reply
#         current_session["message_count"] = current_session.get("message_count", 0) + 1
#         storage.update_session(session_id, current_session)
#     else:
#         reply_text = "OK"

#     # Final callback logic: once per session when conditions met
#     MIN_MESSAGES_FOR_FINAL = 10
#     if current_session.get("scam_detected") and current_session.get("message_count", 0) >= MIN_MESSAGES_FOR_FINAL and not current_session.get("final_sent"):
#         current_session["final_sent"] = True
#         storage.update_session(session_id, current_session)
#         background_tasks.add_task(send_final_result, session_id, True)

#     return HoneypotResponse(status="success", reply=reply_text)

from fastapi import Body

@app.post("/process/public")
async def process_public(
    request: Request,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key),
    body: Optional[dict] = Body(default=None)
):
    
    # 🔐 GUVI Endpoint Tester short-circuit
    # -------------------------
    # GUVI Endpoint Tester case
    # -------------------------
    if body is None:
        return {
            "status": "success",
            "reply": "Endpoint reachable"
        }

    # -------------------------
    # Real evaluation flow
    # -------------------------
    try:
        request = HoneypotRequest(**body)
    except Exception:
        return {
            "status": "success",
            "reply": "Invalid request body"
        }
    request.message.timestamp = normalize_timestamp(request.message.timestamp)
    for msg in request.conversationHistory:
        msg.timestamp = normalize_timestamp(msg.timestamp)

    session_id = request.sessionId
    all_messages = request.conversationHistory + [request.message]

    current_session = storage.get_session(session_id)
    if session_id not in storage.sessions:
        storage.update_session(session_id, current_session)

    if not current_session.get("initialized", False):
        current_session["message_count"] = len(request.conversationHistory)
        current_session["initialized"] = True

    current_session["message_count"] += 1

    detection_result = detector.detect(request.message.text, all_messages)
    is_scam = detection_result["is_scam"]
    current_session["scam_detected"] = is_scam or current_session.get("scam_detected", False)

    extracted = extractor.extract(request.message.text, all_messages)
    intel = current_session["extracted_intelligence"]

    # for k, v in extracted.items():
    #     for item in v:
    #         if item not in intel[k]:
    #             intel[k].append(item)
    intel = current_session.get("extracted_intelligence", {})

    for k, v in extracted.items():
        if k not in intel:
            intel[k] = []

        for item in v:
            if item not in intel[k]:
                intel[k].append(item)

    # If OTP detected, add it as suspicious keyword
    if "otpCodes" in intel:
        for otp in intel["otpCodes"]:
            if otp not in intel["suspiciousKeywords"]:
                intel["suspiciousKeywords"].append(f"OTP:{otp}")

    for kw in detection_result.get("found_keywords", []):
        if kw not in intel["suspiciousKeywords"]:
            intel["suspiciousKeywords"].append(kw)

    current_session["agent_notes"] = f"Scam confidence: {detection_result['confidence']}%"
    storage.update_session(session_id, current_session)

    reply = "OK"
    if current_session["scam_detected"]:
        agent_resp = agent.get_response(
            session_id,
            request.message.text,
            all_messages
        )
        reply = agent_resp["reply"]
        current_session["message_count"] += 1

    if (
        current_session["scam_detected"]
        and current_session["message_count"] >= 10
        and not current_session["final_sent"]
    ):
        current_session["final_sent"] = True
        storage.update_session(session_id, current_session)
        background_tasks.add_task(send_final_result, session_id, True)

    return {
        "status": "success",
        "reply": reply
    }


# ----------------- Keep old /honeypot for local testing (compat) -----------------
@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_compat(
    raw_request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key)
):
    return await process_public(raw_request, background_tasks, auth)

# ----------------- Support endpoints -----------------
@app.get("/test-format")
async def test_format():
    return {
        "example_request": {
            "sessionId": "abc123-session-id",
            "message": {
                "sender": "scammer",
                "text": "Your bank account will be blocked. Verify now.",
                "timestamp": "2026-01-21T10:15:30Z"
            },
            "conversationHistory": [],
            "metadata": {
                "channel": "SMS",
                "language": "English",
                "locale": "IN"
            }
        },
        "example_response": {
            "status": "success",
            "reply": "Oh my, that sounds concerning. What should I do?"
        }
    }

@app.get("/session/{session_id}")
async def get_session_info(session_id: str, auth: dict = Depends(verify_api_key)):
    session = storage.get_session(session_id)
    return {
        "sessionId": session_id,
        "scamDetected": session.get("scam_detected", False),
        "messageCount": session.get("message_count", 0),
        "extractedIntelligence": session.get("extracted_intelligence", {}),
        "agentNotes": session.get("agent_notes", ""),
        "startTime": session.get("start_time", "")
    }

@app.api_route("/health", methods=["GET", "HEAD"])
async def health_check():
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "POST /process/public": "Main honeypot endpoint (required)",
            "GET /session/{id}": "Get session info",
            "GET /test-format": "Example request format"
        }
    }

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("🏆 AGENTIC HONEYPOT API - HACKATHON READY")
    print("="*70)
    print("📡 Server: http://127.0.0.1:8002")
    print("🔐 Authentication: Use 'x-api-key' header")
    print("🔑 Valid API Keys:")
    for key, user in VALID_API_KEYS.items():
        print(f"   • {key:25} → {user}")
    print("\n📋 Main Endpoint: POST /process/public")
    print("="*70 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8002)
