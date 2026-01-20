#!/usr/bin/env python3
"""
Run script for FreeKhana SIEM GUI Tool
"""

import sys
import os
from pathlib import Path

# Add src directory to path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

# Import and run main application
try:
    from main import main
    main()
except ImportError as e:
    print(f"Import error: {e}")
    print("\nPlease ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)