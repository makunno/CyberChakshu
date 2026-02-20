"""
ML Attack Classifier
Uses the trained model for attack detection
"""

import os
import pickle
import numpy as np
from typing import List, Dict, Any

# Load the trained model
MODELS_DIR = os.path.join(os.path.dirname(__file__), '..', 'models')

model = None
vectorizer = None
label_encoder = None
_models_loaded = False

def _load_models():
    """Load trained models"""
    global model, vectorizer, label_encoder, _models_loaded
    
    if _models_loaded:
        return
    
    model_path = os.path.join(MODELS_DIR, 'unified_model.pkl')
    vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
    label_encoder_path = os.path.join(MODELS_DIR, 'label_encoder.pkl')
    
    try:
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
        
        if os.path.exists(vectorizer_path):
            with open(vectorizer_path, 'rb') as f:
                vectorizer = pickle.load(f)
        
        if os.path.exists(label_encoder_path):
            with open(label_encoder_path, 'rb') as f:
                label_encoder = pickle.load(f)
        
        _models_loaded = True
        print("ML models loaded successfully!")
    except Exception as e:
        print(f"Error loading models: {e}")
        _models_loaded = False

def detect_ml_attacks(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect attacks using ML model"""
    if not entries:
        return []
    
    _load_models()
    
    if not _models_loaded or not model or not vectorizer or not label_encoder:
        # Return empty if models not available
        return []
    
    predictions = []
    
    # Get messages for prediction
    messages = [e.get('message', '') or e.get('rawLine', '') for e in entries]
    
    try:
        # Transform messages
        X = vectorizer.transform(messages)
        
        # Get predictions
        preds = model.predict(X)
        probas = model.predict_proba(X)
        
        for i, (pred, proba) in enumerate(zip(preds, probas)):
            attack_type = label_encoder.inverse_transform([pred])[0]
            confidence = float(proba[pred])
            
            # Only include if attack and confidence >= threshold
            if attack_type not in ['safe', 'normal'] and confidence >= 0.3:
                predictions.append({
                    'attackType': attack_type,
                    'confidence': confidence,
                    'probability': confidence,
                    'explanation': [f"{attack_type} detected (confidence: {confidence:.1%})"]
                })
    except Exception as e:
        print(f"ML prediction error: {e}")
    
    return predictions

def enrich_entries_with_attacks(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Enrich entries with attack detection results"""
    # This is called from main.py which does keyword detection
    # ML detection is also run in main.py
    return entries
