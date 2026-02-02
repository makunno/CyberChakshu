#!/usr/bin/env python3
"""
Download and process real attack datasets for FreeKhana SIEM ML training.
"""

import os
import zipfile
import subprocess
import sys

DATASETS_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(DATASETS_DIR)

def install_requirements():
    """Install required packages."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "datasets", "pandas"])

def download_unsw_nb15():
    """Download UNSW-NB15 dataset from Hugging Face."""
    print("Downloading UNSW-NB15 dataset from Hugging Face...")
    code = f'''
from datasets import load_dataset
import pandas as pd

print("Loading dataset...")
ds = load_dataset("Mouwiya/UNSW-NB15")
print(f"Dataset loaded: {{ds}}")

print("Converting to DataFrame...")
df = ds['train'].to_pandas()
print(f"Shape: {{df.shape}}")
print(f"Columns: {{list(df.columns)}}")

# Save to CSV
df.to_csv("unsw-nb15.csv", index=False)
print("Saved to unsw-nb15.csv")
print(df['attack_cat'].value_counts())
'''
    with open("unsw_download.py", "w") as f:
        f.write(code)
    subprocess.check_call([sys.executable, "unsw_download.py"])
    os.remove("unsw_download.py")
    print("UNSW-NB15 download complete!")

def download_kyoto_honeypot():
    """Download Kyoto University honeypot data."""
    print("\nDownloading Kyoto honeypot data...")
    kyoto_url = "https://www.stratosphereips.org/datasets/kyoto"
    print(f"URL: {kyoto_url}")
    print("Note: Kyoto dataset is available from Stratosphere IPS website")
    print("Manual download may be required from: https://www.stratosphereips.org/datasets/kyoto")

def main():
    print("=" * 60)
    print("FreeKhana SIEM - Dataset Downloader")
    print("=" * 60)

    install_requirements()
    download_unsw_nb15()
    download_kyoto_honeypot()

    print("\n" + "=" * 60)
    print("Dataset download complete!")
    print(f"Files saved to: {DATASETS_DIR}")
    print("=" * 60)

if __name__ == "__main__":
    main()
