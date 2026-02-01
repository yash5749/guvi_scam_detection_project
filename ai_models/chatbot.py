# 📁 scam_detection_project/ai_models/chatbot.py
import random
import time

class ScamEngagementBot:
    def __init__(self, persona="elderly"):
        # Define different personas
        self.personas = {
            "elderly": {
                "name": "Robert Smith",
                "age": 68,
                "responses": [
                    "Oh my, that sounds interesting...",
                    "Let me get my glasses to read this properly...",
                    "My grandson usually helps me with these things...",
                    "I'm not very good with technology, can you explain?",
                    "That sounds wonderful! How does it work?",
                    "I need to be careful with my savings..."
                ],
                "typing_speed": 2.5,  # seconds delay
                "emoji": "👴"
            },
            "student": {
                "name": "Emily Johnson",
                "age": 22,
                "responses": [
                    "Wow, really? That's amazing!",
                    "I don't have much money though...",
                    "Can you send me more details?",
                    "Is this safe? I've been scammed before...",
                    "How quickly can I get the money?",
                    "I need this for my college fees!"
                ],
                "typing_speed": 1.0,
                "emoji": "🎓"
            },
            "business": {
                "name": "David Chen",
                "age": 45,
                "responses": [
                    "I'm interested. Send me the details.",
                    "Time is money. Get to the point.",
                    "What's the procedure?",
                    "I've seen similar offers before.",
                    "How do I verify this is legitimate?",
                    "Let's move this to email."
                ],
                "typing_speed": 0.5,
                "emoji": "💼"
            }
        }
        
        self.current_persona = self.personas.get(persona, self.personas["elderly"])
        self.conversation_history = []
    
    def choose_best_persona(self, scam_type):
        """Choose persona based on scam type"""
        if "lottery" in scam_type or "won" in scam_type:
            return "elderly"
        elif "investment" in scam_type or "business" in scam_type:
            return "business"
        else:
            return "student"
    
    def generate_response(self, scammer_message, scam_type=""):
        """Generate a believable response"""
        
        # Add to conversation history
        self.conversation_history.append({
            "from": "scammer",
            "message": scammer_message,
            "time": time.time()
        })
        
        # Choose response based on keywords
        response_pool = self.current_persona["responses"].copy()
        
        # Add specific responses based on scammer's message
        message_lower = scammer_message.lower()
        
        if any(word in message_lower for word in ["bank", "account", "details"]):
            response_pool.extend([
                "What bank details do you need?",
                "My account is with Chase Bank.",
                "I'll need to check my account number."
            ])
        
        if any(word in message_lower for word in ["money", "transfer", "send"]):
            response_pool.extend([
                "How much money are we talking about?",
                "I can transfer some money next week.",
                "What's the minimum amount needed?"
            ])
        
        if any(word in message_lower for word in ["link", "click", "website"]):
            response_pool.extend([
                "I'm not good with links, can you explain?",
                "Is the website safe?",
                "My computer is very slow."
            ])
        
        # Choose random response
        response = random.choice(response_pool)
        
        # Add persona-specific touch
        response = f"{self.current_persona['emoji']} {response}"
        
        # Add to history
        self.conversation_history.append({
            "from": "bot",
            "message": response,
            "persona": self.current_persona["name"],
            "time": time.time()
        })
        
        return {
            "response": response,
            "persona": self.current_persona["name"],
            "delay": self.current_persona["typing_speed"],
            "conversation_id": len(self.conversation_history)
        }
    
    def get_conversation_summary(self):
        """Get summary of the conversation"""
        return {
            "total_messages": len(self.conversation_history),
            "persona_used": self.current_persona["name"],
            "last_interaction": self.conversation_history[-1] if self.conversation_history else None
        }

# Test the chatbot
if __name__ == "__main__":
    print("🤖 Testing Chatbot...")
    
    # Create bot with elderly persona
    bot = ScamEngagementBot(persona="elderly")
    
    # Test conversation
    test_conversation = [
        "Congratulations! You won $1,000,000!",
        "To claim your prize, we need your bank account details.",
        "Please send $100 processing fee to UPI: scam@bank"
    ]
    
    print(f"\nPersona: {bot.current_persona['name']} ({bot.current_persona['age']} years old)")
    
    for scammer_msg in test_conversation:
        print(f"\nScammer: {scammer_msg}")
        response = bot.generate_response(scammer_msg)
        print(f"Bot: {response['response']}")
        print(f"(Delay: {response['delay']} seconds)")
        time.sleep(1)  # Simulate waiting