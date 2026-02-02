#!/usr/bin/env python3
"""
Train FreeKhana SIEM ML model on real attack data from UNSW-NB15.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, accuracy_score
import pickle
import json
from datetime import datetime

DATA_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(DATA_DIR, "unsw-nb15.csv")
MODEL_DIR = os.path.join(DATA_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

ATTACK_TYPE_MAPPING = {
    "Exploits": "exploit",
    " Fuzzers": "fuzzer",
    "Fuzzers": "fuzzer",
    "Generic": "generic_attack",
    "DoS": "dos",
    " Denial of Service": "dos",
    "Reconnaissance": "reconnaissance",
    " Reconnaissance": "reconnaissance",
    "Analysis": "analysis",
    "Backdoor": "backdoor",
    "Backdoors": "backdoor",
    "Shellcode": "shellcode",
    "Worms": "worm",
}

NORMAL_TRAFFIC = ["Normal", "normal", "Benign", "benign", ""]

def load_and_preprocess_data():
    """Load and preprocess UNSW-NB15 dataset."""
    print("Loading UNSW-NB15 dataset...")
    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded {len(df)} rows")
    
    df['attack_cat'] = df['attack_cat'].fillna('Normal').astype(str)
    df['attack_type'] = df['attack_cat'].apply(lambda x: "normal" if x in NORMAL_TRAFFIC else ATTACK_TYPE_MAPPING.get(x.strip(), "unknown"))
    
    df['attack_type'] = df['attack_type'].replace("unknown", "other")
    
    print(f"\nAttack type distribution:")
    print(df['attack_type'].value_counts())
    
    feature_cols = [
        'dur', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss',
        'Spkts', 'Dpkts', 'swin', 'dwin', 'stcpb', 'dtcpb',
        'smeansz', 'dmeansz', 'res_bdy_len', 'Sjit', 'Djit',
        'Sintpkt', 'Dintpkt', 'tcprtt', 'synack', 'ackdat',
        'is_sm_ips_ports', 'ct_state_ttl', 'ct_flw_http_mthd',
        'is_ftp_login', 'ct_ftp_cmd', 'ct_srv_src', 'ct_srv_dst',
        'ct_dst_ltm', 'ct_src_ltm', 'ct_src_dport_ltm', 
        'ct_dst_sport_ltm', 'ct_dst_src_ltm'
    ]
    
    feature_cols = [c for c in feature_cols if c in df.columns]
    
    X = df[feature_cols].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    X = X.fillna(0)
    X = X.replace([np.inf, -np.inf], 0)
    
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['attack_type'])
    
    print(f"\nClasses: {list(label_encoder.classes_)}")
    
    return X, y, label_encoder, feature_cols

def train_model(X, y, label_encoder, feature_cols):
    """Train the ML model."""
    print("\n" + "=" * 60)
    print("Training model...")
    print("=" * 60)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Test set: {len(X_test)} samples")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("\nTraining Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=50,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )
    rf_model.fit(X_train_scaled, y_train)
    
    rf_pred = rf_model.predict(X_test_scaled)
    rf_accuracy = accuracy_score(y_test, rf_pred)
    print(f"Random Forest Accuracy: {rf_accuracy:.4f}")
    
    print("\nTraining Gradient Boosting...")
    gb_model = GradientBoostingClassifier(
        n_estimators=50,
        max_depth=8,
        learning_rate=0.1,
        random_state=42
    )
    gb_model.fit(X_train_scaled, y_train)
    
    gb_pred = gb_model.predict(X_test_scaled)
    gb_accuracy = accuracy_score(y_test, gb_pred)
    print(f"Gradient Boosting Accuracy: {gb_accuracy:.4f}")
    
    best_model = rf_model if rf_accuracy >= gb_accuracy else gb_model
    best_name = "Random Forest" if rf_accuracy >= gb_accuracy else "Gradient Boosting"
    print(f"\nBest model: {best_name} with accuracy {max(rf_accuracy, gb_accuracy):.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, best_model.predict(X_test_scaled), 
                                target_names=label_encoder.classes_))
    
    return best_model, scaler

def save_model(model, scaler, label_encoder, feature_cols):
    """Save trained model and associated objects."""
    print("\n" + "=" * 60)
    print("Saving model...")
    print("=" * 60)
    
    model_data = {
        "model": model,
        "scaler": scaler,
        "label_encoder": label_encoder,
        "feature_columns": feature_cols,
        "attack_types": list(label_encoder.classes_),
        "training_date": datetime.now().isoformat(),
        "training_samples": len(label_encoder.classes_),
        "version": "2.0.0"
    }
    
    model_path = os.path.join(MODEL_DIR, "attack_detector.pkl")
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    print(f"Model saved to: {model_path}")
    
    feature_importance = {}
    if hasattr(model, 'feature_importances_'):
        importance = model.feature_importances_
        feature_importance = dict(zip(feature_cols, importance.tolist()))
        feature_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True)[:15])
    
    metadata = {
        "version": "2.0.0",
        "training_date": datetime.now().isoformat(),
        "attack_types": list(label_encoder.classes_),
        "feature_columns": feature_cols,
        "num_features": len(feature_cols),
        "model_type": type(model).__name__,
        "feature_importance_top_15": feature_importance,
        "source_dataset": "UNSW-NB15"
    }
    
    metadata_path = os.path.join(MODEL_DIR, "model_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")
    
    print("\nModel files created:")
    for f in os.listdir(MODEL_DIR):
        print(f"  - {f}")

def main():
    print("=" * 60)
    print("FreeKhana SIEM - ML Model Trainer")
    print("Training on UNSW-NB15 Real Attack Data")
    print("=" * 60)
    
    X, y, label_encoder, feature_cols = load_and_preprocess_data()
    model, scaler = train_model(X, y, label_encoder, feature_cols)
    save_model(model, scaler, label_encoder, feature_cols)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)
    print(f"\nAttack types learned: {list(label_encoder.classes_)}")
    print("Model ready for deployment in siem-gui/webview-gui/ml/")

if __name__ == "__main__":
    main()
