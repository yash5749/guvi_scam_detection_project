# 📁 scam_detection_project/ai_models/scam_detector_simple.py
import re

class SimpleScamDetector:
    def __init__(self):
        # List of scam words to look for
        self.scam_words = [
            "won", "lottery", "prize", "million", "billion",
            "bank", "account", "details", "information",
            "urgent", "immediate", "emergency",
            "free", "gift", "reward",
            "click", "link", "website",
            "verify", "confirm", "update",
            "inheritance", "unclaimed", "funds"
        ]
        
        # Scam patterns (like phone numbers, UPI IDs)
        self.patterns = {
            "upi_id": r'[\w\.-]+@[\w]+',
            "bank_account": r'\b\d{10,18}\b',
            "phone_number": r'\b\d{10}\b',
            "url": r'https?://[^\s]+'
        }
    
    def check_message(self, message):
        """Check if a message is a scam"""
        message_lower = message.lower()
        
        # Count scam words found
        found_words = []
        for word in self.scam_words:
            if word in message_lower:
                found_words.append(word)
        
        # Calculate scam score
        word_score = len(found_words) / len(self.scam_words)
        
        # Check for patterns
        pattern_score = 0
        for pattern_name, pattern in self.patterns.items():
            if re.search(pattern, message):
                pattern_score += 0.2
        
        # Total score
        total_score = min(word_score + pattern_score, 1.0)
        
        # Decision
        is_scam = total_score > 0.3  # If score > 30%, it's a scam
        
        return {
            "is_scam": is_scam,
            "confidence_score": round(total_score * 100, 2),  # Percentage
            "found_scam_words": found_words,
            "patterns_found": self._find_patterns(message),
            "risk_level": self._get_risk_level(total_score)
        }
    
    def _find_patterns(self, message):
        """Find specific patterns in the message"""
        results = {}
        for pattern_name, pattern in self.patterns.items():
            matches = re.findall(pattern, message)
            if matches:
                results[pattern_name] = matches
        return results
    
    def _get_risk_level(self, score):
        """Convert score to risk level"""
        if score < 0.3:
            return "LOW"
        elif score < 0.6:
            return "MEDIUM"
        elif score < 0.8:
            return "HIGH"
        else:
            return "CRITICAL"

# Test the detector immediately
if __name__ == "__main__":
    print("🧪 Testing Scam Detector...")
    
    detector = SimpleScamDetector()
    
    # Test messages
    test_messages = [
        "You won $1,000,000! Send your bank account details to claim.",
        "Hi, how are you doing today?",
        "URGENT: Your account has been locked. Click http://fake-bank.com to verify.",
        "Please transfer money to UPI: scammer@icici",
        "Hello, I'm calling from Microsoft support."
    ]
    
    for msg in test_messages:
        print("\n" + "="*50)
        print(f"Message: {msg}")
        result = detector.check_message(msg)
        print(f"Scam: {result['is_scam']}")
        print(f"Confidence: {result['confidence_score']}%")
        print(f"Risk: {result['risk_level']}")
        print(f"Found words: {result['found_scam_words']}")



        # Add this to your existing scam_detector_simple.py (just add, don't replace)
class EnhancedScamDetector(SimpleScamDetector):
    def __init__(self):
        super().__init__()
        # Add just ONE advanced model
        try:
            from transformers import pipeline
            self.bert_model = pipeline("text-classification", 
                                      model="mrm8488/bert-tiny-finetuned-sms-spam-detection")
            print("✅ Loaded advanced AI model")
        except:
            print("⚠️ Using basic detection only")
            self.bert_model = None
    
    def check_message_enhanced(self, message):
        # Your existing code
        basic_result = super().check_message(message)
        
        # Add AI if available
        if self.bert_model:
            ai_result = self.bert_model(message)[0]
            # Combine scores
            enhanced_score = (basic_result['confidence_score']/100 + ai_result['score'])/2
            basic_result['confidence_score'] = enhanced_score * 100
            basic_result['ai_confidence'] = ai_result['score'] * 100
        
        return basic_result