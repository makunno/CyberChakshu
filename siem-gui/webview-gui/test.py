"""Test the core parsing functionality"""

import sys
import os
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

def test_parsing():
    """Test basic log parsing"""
    print("Testing log parsing...")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from parsers import auto_parse

        # Test SSH log
        ssh_log = "Jan 15 10:30:45 server sshd[12345]: Failed password for user admin from 192.168.1.100 port 22 ssh2"
        result = auto_parse(ssh_log)
        print(f"[OK] SSH parsing: {len(result['entries'])} entries, {result['stats']['parsedLines']} parsed")

        # Test Apache log
        apache_log = '192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /admin HTTP/1.1" 404 123 "-" "Mozilla/5.0"'
        result = auto_parse(apache_log)
        print(f"[OK] Apache parsing: {len(result['entries'])} entries, {result['stats']['parsedLines']} parsed")

        print("[OK] All parsing tests passed!")
        return True

    except Exception as e:
        print(f"[FAIL] Parsing test failed: {e}")
        return False

def test_ml():
    """Test ML functionality"""
    print("\nTesting ML features...")

    try:
        from ml.correlation import correlate_multiple_logs
        print("[OK] ML correlation import successful")

        # Test with empty data (should not crash)
        result = correlate_multiple_logs([])
        print(f"[OK] ML correlation: {len(result['attackChains'])} attack chains detected")

        print("[OK] ML tests passed!")
        return True

    except Exception as e:
        print(f"[FAIL] ML test failed: {e}")
        return False

def test_api():
    """Test Flask API"""
    print("\nTesting Flask API...")

    try:
        import sys
        import os
        sys.path.insert(0, os.path.dirname(__file__))
        from api.app import app
        print("[OK] Flask API import successful")

        # Test that app is created
        with app.test_client() as client:
            response = client.get('/health')
            if response.status_code == 200:
                print("[OK] Flask API health check passed")
                return True
            else:
                print(f"[FAIL] Flask API health check failed: {response.status_code}")
                return False

    except Exception as e:
        print(f"[FAIL] API test failed: {e}")
        return False

if __name__ == '__main__':
    print("FreeKhana SIEM Desktop - Core Functionality Test")
    print("=" * 50)

    parsing_ok = test_parsing()
    ml_ok = test_ml()
    api_ok = test_api()

    print("\n" + "=" * 50)
    if parsing_ok and ml_ok and api_ok:
        print("[SUCCESS] All tests passed! The application is ready to run.")
        print("\nTo start the application:")
        print("  python run.py")
    else:
        print("[ERROR] Some tests failed. Check the errors above.")
        sys.exit(1)