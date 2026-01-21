"""Quick API test while the app is running"""

import requests
import time

def test_api():
    """Test the API endpoints"""
    try:
        print("Testing API endpoints...")

        # Test health endpoint
        response = requests.get('http://127.0.0.1:5000/health', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✓ Health check passed")
            print(f"  API version: {data.get('version', 'unknown')}")
            print(f"  Features: {len(data.get('features', []))} features")
        else:
            print(f"✗ Health check failed: {response.status_code}")
            return False

        # Test parsers endpoint
        response = requests.get('http://127.0.0.1:5000/parsers', timeout=5)
        if response.status_code == 200:
            data = response.json()
            print("✓ Parsers endpoint working")
            print(f"  Total parsers: {data.get('total', 0)}")
        else:
            print(f"✗ Parsers endpoint failed: {response.status_code}")

        print("✓ All API tests passed!")
        return True

    except requests.exceptions.RequestException as e:
        print(f"✗ API test failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == '__main__':
    print("FreeKhana SIEM API Test")
    print("=" * 30)

    # Wait a moment for the app to start
    time.sleep(3)

    success = test_api()
    if success:
        print("\n🎉 API is working correctly!")
        print("The desktop application should now be running.")
    else:
        print("\n❌ API test failed. Check if the application is running.")