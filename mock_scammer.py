# mock_scammer.py (NEW FILE - add to your project)
import random

def generate_test_scam():
    scams = [
        "🎉 You won $5,000,000! Send bank details to claim.",
        "URGENT: Account locked. Click http://secure-bank.com",
        "Send $100 to UPI: scam@bank for your prize",
        "Investment opportunity: 500% returns guaranteed!"
    ]
    return random.choice(scams)

# Add to your main.py just one line:
# scam_message = generate_test_scam()  # Instead of hardcoded