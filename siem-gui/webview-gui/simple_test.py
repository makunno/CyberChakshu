"""Simple parser test"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_single_parser():
    """Test a single parser directly"""
    print("Testing single SSH parser...")

    try:
        from parsers.auth import SSHAuthParser

        parser = SSHAuthParser()
        test_line = "Jan 15 10:30:45 server sshd[12345]: Failed password for user admin from 192.168.1.100 port 22 ssh2"

        if parser.detect(test_line):
            print("[OK] SSH parser detected the line")
            result = parser.parse(test_line)
            if result:
                print(f"[OK] SSH parser parsed: user={result.user}, ip={result.source.get('ip')}")
                return True
            else:
                print("[FAIL] SSH parser returned None")
                return False
        else:
            print("[FAIL] SSH parser failed to detect the line")
            return False

    except Exception as e:
        print(f"[FAIL] SSH parser test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    success = test_single_parser()
    print(f"\nTest {'PASSED' if success else 'FAILED'}")