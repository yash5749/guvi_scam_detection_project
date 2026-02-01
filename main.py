# 📁 scam_detection_project/main.py
import json
from ai_models.scam_detector_simple import SimpleScamDetector
from ai_models.chatbot import ScamEngagementBot
from ai_models.data_extractor import IntelligenceExtractor
import time

class AgenticHoneypotSystem:
    def __init__(self):
        print("🚀 Initializing Agentic Honeypot System...")
        
        # Initialize all components
        self.detector = SimpleScamDetector()
        self.chatbot = ScamEngagementBot()
        self.extractor = IntelligenceExtractor()
        
        # System state
        self.active_conversations = {}
        self.total_scams_detected = 0
        self.total_intelligence_extracted = 0
        
        print("✅ System ready!")
    
    def process_scam_message(self, message, scammer_id="unknown"):
        """Main pipeline: Detect → Engage → Extract"""
        
        print(f"\n{'='*60}")
        print(f"Processing message from scammer: {scammer_id}")
        print(f"Message: {message}")
        print(f"{'='*60}")
        
        # Step 1: Detect if it's a scam
        print("\n🔍 Step 1: Scam Detection")
        detection_result = self.detector.check_message(message)
        
        if not detection_result["is_scam"]:
            print("❌ Not a scam. Ignoring message.")
            return None
        
        self.total_scams_detected += 1
        print(f"✅ Scam detected! (Confidence: {detection_result['confidence_score']}%)")
        
        # Step 2: Choose persona based on scam type
        print("\n🎭 Step 2: Choosing Persona")
        scam_words = detection_result["found_scam_words"]
        scam_type = " ".join(scam_words[:2]) if scam_words else "generic"
        
        persona = self.chatbot.choose_best_persona(scam_type)
        self.chatbot.current_persona = self.chatbot.personas[persona]
        print(f"Selected persona: {self.chatbot.current_persona['name']}")
        
        # Step 3: Generate response
        print("\n💬 Step 3: Generating Response")
        response_data = self.chatbot.generate_response(message, scam_type)
        print(f"Response: {response_data['response']}")
        
        # Step 4: Extract intelligence
        print("\n📊 Step 4: Extracting Intelligence")
        extracted_data = self.extractor.extract_all(message)
        formatted_data = self.extractor.format_for_json(extracted_data)
        
        self.total_intelligence_extracted += formatted_data["summary"]["total_items_found"]
        
        # Step 5: Prepare final output
        print("\n📦 Step 5: Preparing Output")
        final_output = {
            "status": "success",
            "scammer_id": scammer_id,
            "detection": detection_result,
            "engagement": {
                "response": response_data["response"],
                "persona": response_data["persona"],
                "conversation_id": response_data["conversation_id"]
            },
            "intelligence": formatted_data,
            "system_metrics": {
                "total_scams_detected": self.total_scams_detected,
                "total_intelligence_extracted": self.total_intelligence_extracted,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        }
        
        # Save to active conversations
        self.active_conversations[scammer_id] = {
            "last_message": message,
            "last_response": response_data["response"],
            "extracted_intelligence": formatted_data,
            "start_time": time.time()
        }
        
        # Print summary
        print("\n📈 SUMMARY:")
        print(f"• Scam Type: {scam_type}")
        print(f"• Confidence: {detection_result['confidence_score']}%")
        print(f"• Persona: {response_data['persona']}")
        print(f"• Intelligence Items Found: {formatted_data['summary']['total_items_found']}")
        print(f"• Intelligence Score: {formatted_data['summary']['intelligence_score']}/100")
        
        return final_output
    
    def get_system_stats(self):
        """Get current system statistics"""
        return {
            "active_conversations": len(self.active_conversations),
            "total_scams_detected": self.total_scams_detected,
            "total_intelligence_extracted": self.total_intelligence_extracted,
            "conversation_ids": list(self.active_conversations.keys())
        }

# Test the complete system
if __name__ == "__main__":
    print("🏆 AGENTIC HONEYPOT SYSTEM - COMPLETE TEST")
    print("="*60)
    
    # Create the system
    system = AgenticHoneypotSystem()
    
    # Test messages (simulating scammers)
    test_cases = [
        {
            "message": "CONGRATULATIONS! You won $5,000,000 in the Mega Lottery!",
            "scammer_id": "lottery_scammer_001"
        },
        {
            "message": "URGENT: Your bank account is locked. Click http://secure-bank-verify.com to unlock.",
            "scammer_id": "phishing_scammer_002"
        },
        {
            "message": "Send $1000 to UPI: fraud@okicici to receive your inheritance of $10,000,000",
            "scammer_id": "inheritance_scammer_003"
        }
    ]
    
    # Process each test case
    all_results = []
    
    for test in test_cases:
        print(f"\n\n🎯 PROCESSING TEST CASE: {test['scammer_id']}")
        result = system.process_scam_message(test["message"], test["scammer_id"])
        
        if result:
            all_results.append(result)
            
            # Print JSON output (as required)
            print(f"\n📋 JSON OUTPUT for {test['scammer_id']}:")
            print(json.dumps(result, indent=2))
        
        print("\n" + "="*60)
    
    # Final statistics
    print("\n\n📊 FINAL SYSTEM STATISTICS:")
    stats = system.get_system_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")