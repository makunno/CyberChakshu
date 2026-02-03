#!/usr/bin/env python3
"""
Train FreeKhana SIEM ML model on real attack data from UNSW-NB15.
GPU-accelerated training using LightGBM and XGBoost with CUDA.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from sklearn.ensemble import RandomForestClassifier
import pickle
import json
from datetime import datetime

print("Loading libraries...")

try:
    import lightgbm as lgb
    print("LightGBM loaded")
    LGBM_AVAILABLE = True
except ImportError:
    print("LightGBM not available")
    LGBM_AVAILABLE = False

try:
    import xgboost as xgb
    print("XGBoost loaded")
    XGB_AVAILABLE = True
except ImportError:
    print("XGBoost not available")
    XGB_AVAILABLE = False

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
    print("\n" + "=" * 60)
    print("Loading UNSW-NB15 dataset...")
    print("=" * 60)
    
    df = pd.read_csv(DATASET_PATH, low_memory=False)
    print(f"Loaded {len(df):,} rows")
    
    df['attack_cat'] = df['attack_cat'].fillna('Normal').astype(str)
    df['attack_type'] = df['attack_cat'].apply(
        lambda x: "normal" if x in NORMAL_TRAFFIC else ATTACK_TYPE_MAPPING.get(x.strip(), "other")
    )
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
    print(f"\nUsing {len(feature_cols)} features")
    
    X = df[feature_cols].copy()
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    X = X.fillna(0)
    X = X.replace([np.inf, -np.inf], 0)
    
    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df['attack_type'])
    
    print(f"\nClasses: {list(label_encoder.classes_)}")
    
    return X.values, y, label_encoder, feature_cols

def train_lgbm(X_train, y_train, X_test, y_test, label_encoder):
    """Train LightGBM model with GPU acceleration."""
    print("\n" + "=" * 60)
    print("Training LightGBM (GPU)...")
    print("=" * 60)
    
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    params = {
        'objective': 'multiclass',
        'num_class': len(label_encoder.classes_),
        'boosting_type': 'gbdt',
        'metric': 'multi_logloss',
        'num_leaves': 63,
        'learning_rate': 0.1,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'n_jobs': -1,
        'device': 'gpu',
    }
    
    print(f"Training with {len(label_encoder.classes_)} classes...")
    model = lgb.train(
        params,
        train_data,
        num_boost_round=200,
        valid_sets=[valid_data],
        callbacks=[lgb.early_stopping(stopping_rounds=30), lgb.log_evaluation(50)]
    )
    
    y_pred_proba = model.predict(X_test)
    y_pred = np.argmax(y_pred_proba, axis=1)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"LightGBM Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    return model, accuracy

def train_xgboost(X_train, y_train, X_test, y_test, label_encoder):
    """Train XGBoost model with GPU acceleration."""
    print("\n" + "=" * 60)
    print("Training XGBoost (GPU)...")
    print("=" * 60)
    
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'multi:softmax',
        'num_class': len(label_encoder.classes_),
        'max_depth': 8,
        'learning_rate': 0.1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'tree_method': 'gpu_hist',
        'n_jobs': -1,
    }
    
    print(f"Training with {len(label_encoder.classes_)} classes...")
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=200,
        evals=[(dtest, 'test')],
        early_stopping_rounds=30,
        verbose_eval=50
    )
    
    y_pred = model.predict(dtest)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"XGBoost Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    return model, accuracy

def train_sklearn_rf(X_train, y_train, X_test, y_test, label_encoder):
    """Train sklearn Random Forest as baseline."""
    print("\n" + "=" * 60)
    print("Training Random Forest (sklearn)...")
    print("=" * 60)
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=42
    )
    
    print("Training...")
    model.fit(X_train, y_train)
    
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Random Forest Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
    
    return model, accuracy

def save_model(best_model, best_name, scaler, label_encoder, feature_cols):
    """Save trained model and associated objects."""
    print("\n" + "=" * 60)
    print("Saving model...")
    print("=" * 60)
    
    if LGBM_AVAILABLE and 'lgb' in best_name.lower():
        model_path = os.path.join(MODEL_DIR, "attack_detector_lgbm.txt")
        best_model.save_model(model_path)
        model_type = "LightGBM"
    elif XGB_AVAILABLE and 'xgb' in best_name.lower():
        model_path = os.path.join(MODEL_DIR, "attack_detector_xgb.json")
        best_model.save_model(model_path)
        model_type = "XGBoost"
    else:
        model_path = os.path.join(MODEL_DIR, "attack_detector.pkl")
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': best_model,
                'scaler': scaler,
                'label_encoder': label_encoder,
                'feature_columns': feature_cols,
                'attack_types': list(label_encoder.classes_),
                'training_date': datetime.now().isoformat(),
                'version': "2.0.0"
            }, f)
        model_type = "sklearn"
    
    print(f"Model saved to: {model_path}")
    
    feature_importance = {}
    if hasattr(best_model, 'feature_importances_'):
        importance = best_model.feature_importances_
        feature_importance = dict(zip(feature_cols, importance.tolist()))
        feature_importance = dict(sorted(feature_importance.items(), 
                                          key=lambda x: x[1], reverse=True)[:15])
    
    metadata = {
        "version": "2.0.0",
        "training_date": datetime.now().isoformat(),
        "attack_types": list(label_encoder.classes_),
        "feature_columns": feature_cols,
        "num_features": len(feature_cols),
        "model_type": model_type,
        "feature_importance_top_15": feature_importance,
        "source_dataset": "UNSW-NB15",
        "gpu_accelerated": False,
        "training_samples": len(label_encoder.classes_),
    }
    
    metadata_path = os.path.join(MODEL_DIR, "model_metadata.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to: {metadata_path}")
    
    print("\nModel files created:")
    for f in os.listdir(MODEL_DIR):
        fpath = os.path.join(MODEL_DIR, f)
        size = os.path.getsize(fpath)
        print(f"  - {f} ({size:,} bytes)")

def main():
    print("=" * 60)
    print("FreeKhana SIEM - GPU-Accelerated ML Model Trainer")
    print("Training on UNSW-NB15 Real Attack Data")
    print("=" * 60)
    
    X, y, label_encoder, feature_cols = load_and_preprocess_data()
    
    print("\nSplitting data...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train):,} samples")
    print(f"Test set: {len(X_test):,} samples")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    models = []
    
    if LGBM_AVAILABLE:
        try:
            lgbm_model, lgbm_acc = train_lgbm(X_train_scaled, y_train, X_test_scaled, y_test, label_encoder)
            models.append(("LightGBM", lgbm_model, lgbm_acc))
        except Exception as e:
            print(f"LightGBM training failed: {e}")
    
    if XGB_AVAILABLE:
        try:
            xgb_model, xgb_acc = train_xgboost(X_train_scaled, y_train, X_test_scaled, y_test, label_encoder)
            models.append(("XGBoost", xgb_model, xgb_acc))
        except Exception as e:
            print(f"XGBoost training failed: {e}")
    
    rf_model, rf_acc = train_sklearn_rf(X_train_scaled, y_train, X_test_scaled, y_test, label_encoder)
    models.append(("RandomForest", rf_model, rf_acc))
    
    print("\n" + "=" * 60)
    print("MODEL COMPARISON")
    print("=" * 60)
    for name, model, acc in models:
        print(f"{name:20s}: {acc:.4f}")
    
    if models:
        best = max(models, key=lambda x: x[2])
        best_name, best_model, best_acc = best
        print(f"\nBest model: {best_name} with accuracy {best_acc:.4f}")
        save_model(best_model, best_name, scaler, label_encoder, feature_cols)
    else:
        print("No models trained successfully!")
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)
    print(f"\nAttack types learned: {list(label_encoder.classes_)}")
    print("Model ready for deployment in siem-gui/webview-gui/ml/")

if __name__ == "__main__":
    main()
