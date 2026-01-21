"""Run FreeKhana SIEM Desktop Application"""

import sys
import os
from pathlib import Path

# Add current directory to path for imports
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

# Import and run main application
try:
    from main import main
    main()
except ImportError as e:
    print(f"Import error: {e}")
    print("\nPlease ensure all dependencies are installed:")
    print("pip install pywebview flask flask-cors")
    print("pip install numpy scikit-learn  # For ML features")
    sys.exit(1)
