# 📁 scam_detection_project/api/server.py - COMPLETE HACKATHON VERSION
from fastapi import FastAPI, HTTPException, Depends, Header, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import sys
import os
import time
import json
import re
import requests
import uuid
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ========== CREATE THE APP ==========
app = FastAPI(
    title="Agentic Honeypot API",
    description="AI-powered scam detection and intelligence extraction system",
    version="2.0.0"
)

# ========== CORS MIDDLEWARE ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== DATA MODELS ==========
class Message(BaseModel):
    sender: str  # "scammer" or "user"
    text: str
    timestamp: str

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
    status: str  # "success" or "error"
    reply: str   # Agent's response message

class FinalResult(BaseModel):
    sessionId: str
    scamDetected: bool
    totalMessagesExchanged: int
    extractedIntelligence: Dict[str, List[str]]
    agentNotes: str

# ========== SIMPLE AI MODULES ==========
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
        
        # Check for scam keywords
        found_keywords = [word for word in self.scam_keywords if word in text_lower]
        
        # Check for urgency
        urgency_patterns = [r"urgent", r"immediate", r"emergency", r"now", r"asap"]
        urgency_score = sum(1 for pattern in urgency_patterns if re.search(pattern, text_lower))
        
        # Check for financial requests
        financial_patterns = [r"bank", r"account", r"upi", r"money", r"payment"]
        financial_score = sum(1 for pattern in financial_patterns if re.search(pattern, text_lower))
        
        # Calculate confidence
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

class IntelligentExtractor:
    def __init__(self):
        self.patterns = {
            "upiIds": [r'[\w\.-]+@(okicici|okhdfc|oksbi|okaxis|paytm|ybl|axl|upi)', r'[\w\.-]+@[\w]+'],
            "bankAccounts": [r'\b\d{9,18}\b', r'account\s*[:\.]?\s*(\d{9,18})'],
            "phishingLinks": [r'https?://[^\s]+', r'www\.[^\s]+'],
            "phoneNumbers": [r'\b\d{10}\b', r'\+\d{1,3}[- ]?\d{5,15}'],
            "suspiciousKeywords": []
        }
    
    def extract(self, text: str, conversation: List[Message]) -> Dict[str, List[str]]:
        result = {}
        
        for key, patterns in self.patterns.items():
            if key == "suspiciousKeywords":
                # Already handled by detector
                continue
            
            found_items = []
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match and match not in found_items:
                        found_items.append(match)
            
            if found_items:
                result[key] = found_items
        
        return result

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
                "typing_pattern": "...",
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
                "typing_pattern": "",
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
                "typing_pattern": "",
                "delay": 0.5
            }
        }
        
        # Store conversation state by sessionId
        self.sessions = {}
    
    def get_response(self, session_id: str, scammer_message: str, 
                    conversation_history: List[Message], scam_type: str = "") -> Dict[str, Any]:
        
        # Initialize or get session
        if session_id not in self.sessions:
            # Choose persona based on first message
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
        
        # Generate response based on context
        response_pool = self.personas[persona]["responses"].copy()
        
        # Context-aware responses
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
        
        # Choose response
        import random
        response_text = random.choice(response_pool)
        
        # Add persona touch
        if persona == "elderly":
            response_text = f"Oh... {response_text}"
        
        # Update conversation
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

# ========== INITIALIZE COMPONENTS ==========
detector = SimpleScamDetector()
extractor = IntelligentExtractor()
agent = HoneypotAgent()

# ========== API KEYS ==========
VALID_API_KEYS = {
    "hackathon_key_2024": "hackathon_participant",
    "test_key_123": "tester",
    "admin_key": "administrator"
}

# ========== SESSION STORAGE ==========
class SessionStorage:
    def __init__(self):
        self.sessions = {}  # session_id -> session_data
    
    def get_session(self, session_id: str):
        return self.sessions.get(session_id, {
            "scam_detected": False,
            "message_count": 0,
            "extracted_intelligence": {},
            "agent_notes": "",
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

# ========== FINAL RESULT CALLBACK ==========
async def send_final_result(session_id: str, scam_detected: bool):
    """Send final results to GUVI evaluation endpoint"""
    try:
        session = storage.get_session(session_id)
        
        # Prepare payload
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
        
        # Send to GUVI endpoint (commented for testing, uncomment for actual submission)
        # response = requests.post(
        #     "https://hackathon.guvi.in/api/updateHoneyPotFinalResult",
        #     json=payload,
        #     timeout=5
        # )
        
        # For now, just log it
        print(f"📤 Would send final result for session {session_id}:")
        print(json.dumps(payload, indent=2))
        
        return True
    except Exception as e:
        print(f"❌ Error sending final result: {e}")
        return False

# ========== AUTHENTICATION ==========
async def verify_api_key(x_api_key: str = Header(None, alias="x-api-key")):
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key is missing")
    
    if x_api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid API key. Valid keys: {list(VALID_API_KEYS.keys())}"
        )
    
    return {"user": VALID_API_KEYS[x_api_key]}

# ========== MAIN ENDPOINT ==========
@app.post("/honeypot", response_model=HoneypotResponse)
async def honeypot_endpoint(
    request: HoneypotRequest,
    background_tasks: BackgroundTasks,
    auth: dict = Depends(verify_api_key)
):
    """
    Main honeypot endpoint that accepts GUVI's format
    and returns agent responses.
    """
    
    # Get current message
    current_message = request.message.text
    session_id = request.sessionId
    
    # Get conversation history
    all_messages = request.conversationHistory + [request.message]
    
    # 1. Detect scam
    detection_result = detector.detect(current_message, all_messages)
    is_scam = detection_result["is_scam"]
    
    # Update session
    current_session = storage.get_session(session_id)
    current_session.update({
        "scam_detected": is_scam or current_session.get("scam_detected", False),
        "message_count": current_session.get("message_count", 0) + 1,
        "agent_notes": f"Scam confidence: {detection_result['confidence']}%. Keywords: {detection_result['found_keywords']}"
    })
    
    # 2. Extract intelligence
    extracted = extractor.extract(current_message, all_messages)
    
    # Merge with existing intelligence
    existing_intel = current_session.get("extracted_intelligence", {})
    for key, items in extracted.items():
        if key not in existing_intel:
            existing_intel[key] = []
        for item in items:
            if item not in existing_intel[key]:
                existing_intel[key].append(item)
    
    current_session["extracted_intelligence"] = existing_intel
    storage.update_session(session_id, current_session)
    
    # 3. If scam detected and enough messages exchanged, send final result
    if is_scam and current_session["message_count"] >= 5:
        background_tasks.add_task(send_final_result, session_id, True)
    
    # 4. Generate agent response
    scam_type = "lottery" if "won" in current_message.lower() else "phishing"
    agent_response = agent.get_response(
        session_id, 
        current_message, 
        all_messages,
        scam_type
    )
    
    return HoneypotResponse(
        status="success",
        reply=agent_response["reply"]
    )

# ========== TEST ENDPOINT ==========
@app.get("/test-format")
async def test_format():
    """Example of expected request format"""
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

# ========== SESSION INFO ENDPOINT ==========
@app.get("/session/{session_id}")
async def get_session_info(session_id: str, auth: dict = Depends(verify_api_key)):
    """Get information about a session"""
    session = storage.get_session(session_id)
    return {
        "sessionId": session_id,
        "scamDetected": session.get("scam_detected", False),
        "messageCount": session.get("message_count", 0),
        "extractedIntelligence": session.get("extracted_intelligence", {}),
        "agentNotes": session.get("agent_notes", ""),
        "startTime": session.get("start_time", "")
    }

# ========== HEALTH CHECK ==========
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Agentic Honeypot API",
        "version": "2.0.0",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "POST /honeypot": "Main honeypot endpoint",
            "GET /session/{id}": "Get session info",
            "GET /test-format": "Example request format"
        }
    }

# ========== MAIN ==========
if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "="*70)
    print("🏆 AGENTIC HONEYPOT API - HACKATHON READY")
    print("="*70)
    print("📡 Server: http://127.0.0.1:8000")
    print("\n🔐 Authentication: Use 'x-api-key' header")
    print("🔑 Valid API Keys:")
    for key, user in VALID_API_KEYS.items():
        print(f"   • {key:25} → {user}")
    
    print("\n📋 Main Endpoint: POST /honeypot")
    print("📝 Expected Request Format:")
    print(json.dumps({
        "sessionId": "unique-session-id",
        "message": {
            "sender": "scammer",
            "text": "Your message here",
            "timestamp": "2026-01-21T10:15:30Z"
        },
        "conversationHistory": [],
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }, indent=2))
    
    print("\n✅ Returns: {'status': 'success', 'reply': 'agent response'}")
    print("="*70 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8002)