# 📁 scam_detection_project/ai_models/data_extractor.py
import re
import json

class IntelligenceExtractor:
    def __init__(self):
        # Patterns for different types of information
        self.patterns = {
            # UPI IDs (Indian payment system)
            "upi_ids": [
                r'[\w\.-]+@(okicici|okhdfc|oksbi|okaxis|paytm|ybl|axl)',
                r'[\w\.-]+@[\w]+'
            ],
            
            # Bank accounts (international)
            "bank_accounts": [
                r'account\s*(?:no|number|#)?[:\.]?\s*(\d{9,18})',
                r'acct\s*[:\.]?\s*(\d{9,18})',
                r'\b\d{9,18}\b'  # Just any long number
            ],
            
            # Credit/Debit cards
            "cards": [
                r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
                r'card\s*(?:no|number|#)?[:\.]?\s*(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})'
            ],
            
            # Phone numbers
            "phone_numbers": [
                r'\b\d{10}\b',
                r'\+\d{1,3}[- ]?\d{5,15}',
                r'phone\s*[:\.]?\s*(\d{10})'
            ],
            
            # URLs and links
            "urls": [
                r'https?://[^\s]+',
                r'www\.[^\s]+',
                r'click\s*(?:here|link)[:\.]?\s*([^\s]+)'
            ],
            
            # Email addresses
            "emails": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            ],
            
            # Cryptocurrency addresses
            "crypto": [
                r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',  # Bitcoin
                r'0x[a-fA-F0-9]{40}',  # Ethereum
            ]
        }
        
        # Known scam domains
        self.known_scam_domains = [
            "fake-bank.com",
            "secure-verify.net",
            "prize-claim.org",
            "lottery-winner.com",
            "urgent-payment.xyz"
        ]
    
    def extract_all(self, text):
        """Extract all possible intelligence from text"""
        results = {}
        
        for data_type, patterns in self.patterns.items():
            found_items = []
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    # Clean up the matches
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]  # Get the captured group
                        if match and match not in found_items:
                            found_items.append(match)
            
            if found_items:
                results[data_type] = found_items
        
        # Check for known scam domains in URLs
        if "urls" in results:
            scam_urls = []
            for url in results["urls"]:
                for domain in self.known_scam_domains:
                    if domain in url:
                        scam_urls.append({
                            "url": url,
                            "domain": domain,
                            "risk": "HIGH",
                            "known_scam": True
                        })
            if scam_urls:
                results["scam_urls"] = scam_urls
        
        # Calculate intelligence score
        results["intelligence_score"] = self._calculate_score(results)
        
        return results
    
    def _calculate_score(self, extracted_data):
        """Calculate how much intelligence was extracted"""
        score = 0
        max_score = 100
        
        # Points for each type of data found
        points = {
            "upi_ids": 25,
            "bank_accounts": 30,
            "cards": 35,
            "urls": 20,
            "phone_numbers": 15,
            "emails": 10,
            "crypto": 40,
            "scam_urls": 50  # Bonus for identifying known scams
        }
        
        for data_type, found_items in extracted_data.items():
            if data_type in points and found_items:
                score += points[data_type]
                # Bonus for multiple items
                if len(found_items) > 1:
                    score += 5
        
        return min(score, max_score)
    
    def format_for_json(self, extracted_data):
        """Format extracted data for JSON output"""
        formatted = {
            "extracted_intelligence": {},
            "summary": {
                "total_items_found": 0,
                "intelligence_score": extracted_data.get("intelligence_score", 0),
                "high_value_found": False
            }
        }
        
        # Count total items
        total = 0
        high_value = False
        
        for data_type, items in extracted_data.items():
            if data_type != "intelligence_score":
                formatted["extracted_intelligence"][data_type] = items
                total += len(items)
                
                # Check for high-value intelligence
                if data_type in ["bank_accounts", "cards", "crypto"]:
                    high_value = True
        
        formatted["summary"]["total_items_found"] = total
        formatted["summary"]["high_value_found"] = high_value
        
        return formatted

# Test the extractor
if __name__ == "__main__":
    print("🔍 Testing Intelligence Extractor...")
    
    extractor = IntelligenceExtractor()
    
    test_texts = [
        "Send money to UPI: scammer@okicici or call me at 9876543210",
        "My bank account is 123456789012 and card is 4111-1111-1111-1111",
        "Visit http://fake-bank.com/verify to secure your account",
        "Bitcoin address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
    ]
    
    for text in test_texts:
        print(f"\nText: {text}")
        extracted = extractor.extract_all(text)
        formatted = extractor.format_for_json(extracted)
        
        print("Extracted:")
        for key, value in formatted["extracted_intelligence"].items():
            print(f"  {key}: {value}")
        print(f"Score: {formatted['summary']['intelligence_score']}/100")