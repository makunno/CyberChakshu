#!/usr/bin/env python3
"""
Basic tests for FreeKhana SIEM GUI Tool
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test that all imports work"""
    try:
        print("Testing imports...")

        # Test basic imports
        import datetime
        import uuid
        from collections import defaultdict, Counter
        print("OK: Basic Python imports work")

        # Test class definitions (without GUI)
        from main import LogEntry, AttackChain, LogParser, ApacheAccessParser, SSHAuthParser, DynamicParser
        print("OK: Core classes import successfully")

        # Test parser functionality
        parser = ApacheAccessParser()
        test_line = '192.168.1.100 - - [10/Dec/2023:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 1024'
        entry = parser.parse(test_line)

        if entry and entry.source.get('ip') == '192.168.1.100':
            print("OK: Apache parser works correctly")
        else:
            print("ERROR: Apache parser failed")
            return False

        # Test dynamic parser
        dynamic_parser = DynamicParser()
        entry2 = dynamic_parser.parse("user=root action=login ip=10.0.0.1")

        if entry2 and entry2.user and entry2.user.get('name') == 'root':
            print("OK: Dynamic parser works correctly")
        else:
            print("ERROR: Dynamic parser failed")
            return False

        return True

    except ImportError as e:
        print(f"Import error: {e}")
        return False
    except Exception as e:
        print(f"Test error: {e}")
        return False

def test_log_parsing():
    """Test log parsing functionality"""
    try:
        from main import LogParserManager

        print("\nTesting log parsing...")

        manager = LogParserManager()
        test_logs = [
            # Apache access log
            '192.168.1.100 - - [10/Dec/2023:10:15:32 +0000] "GET /api/users HTTP/1.1" 200 1024',
            # SSH auth log
            'Dec 10 10:15:32 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22',
            # Unknown format
            'timestamp=2023-12-10T10:15:32 user=admin action=login ip=10.0.0.1'
        ]

        total_parsed = 0
        for log_line in test_logs:
            entry = manager.parse_line(log_line)
            if entry:
                total_parsed += 1
                print(f"Parsed: {entry.log_type} - {entry.message[:50]}...")

        if total_parsed == len(test_logs):
            print(f"OK: All {total_parsed} test logs parsed successfully")
            return True
        else:
            print(f"ERROR: Only {total_parsed}/{len(test_logs)} logs parsed")
            return False

    except Exception as e:
        print(f"Log parsing test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("TEST: FreeKhana SIEM GUI Tool - Basic Tests")
    print("=" * 50)

    # Test imports
    if not test_imports():
        print("\nERROR: Basic import tests failed")
        sys.exit(1)

    # Test log parsing
    if not test_log_parsing():
        print("\nERROR: Log parsing tests failed")
        sys.exit(1)

    print("\n" + "=" * 50)
    print("SUCCESS: All basic tests passed!")
    print("\nReady to run the GUI application:")
    print("   python setup.py    # Install deps and run")
    print("   python run.py      # Run if deps are installed")

if __name__ == "__main__":
    main()