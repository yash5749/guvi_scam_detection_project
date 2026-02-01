# 📁 scam_detection_project/tests/test_api.py
import requests
import json

# Test the API
BASE_URL = "http://localhost:8000"

def test_all_endpoints():
    print("🧪 Testing API Endpoints...")
    
    # Test message
    test_message = {
        "message": "You won $10,000,000! Send bank details to UPI: winner@okicici",
        "scammer_id": "test_001",
        "persona": "elderly"
    }
    
    # Test 1: Root endpoint
    print("\n1. Testing root endpoint...")
    response = requests.get(BASE_URL)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Test 2: Detect endpoint
    print("\n2. Testing detect endpoint...")
    response = requests.post(f"{BASE_URL}/detect", json=test_message)
    print(f"Status: {response.status_code}")
    print(f"Is Scam: {response.json()['is_scam']}")
    
    # Test 3: Extract endpoint
    print("\n3. Testing extract endpoint...")
    response = requests.post(f"{BASE_URL}/extract", json=test_message)
    print(f"Status: {response.status_code}")
    data = response.json()
    print(f"UPI IDs found: {data['extracted_intelligence'].get('upi_ids', [])}")
    
    # Test 4: Engage endpoint
    print("\n4. Testing engage endpoint...")
    response = requests.post(f"{BASE_URL}/engage", json=test_message)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()['response']}")
    
    # Test 5: Complete process
    print("\n5. Testing complete process endpoint...")
    response = requests.post(f"{BASE_URL}/process", json=test_message)
    print(f"Status: {response.status_code}")
    result = response.json()
    
    print(f"\n🎯 FINAL RESULTS:")
    print(f"Scammer ID: {result['scammer_id']}")
    print(f"Confidence: {result['detection_result']['confidence_score']}%")
    print(f"Response: {result['engagement_response']['message']}")
    print(f"Intelligence Score: {result['extracted_intelligence']['summary']['intelligence_score']}/100")
    
    # Save to file
    with open("test_output.json", "w") as f:
        json.dump(result, f, indent=2)
    print("\n✅ Results saved to test_output.json")

if __name__ == "__main__":
    test_all_endpoints()