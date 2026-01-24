import joblib
import numpy as np
import os

class AnomalyDetector:
    def __init__(self, anomaly_model_path='model.pkl', attack_model_path='attack_model.pkl'):
        """
        Hybrid ML Detection System:
        - anomaly_model: Isolation Forest for detecting any anomalies (including unknown attacks)
        - attack_model: Random Forest for classifying known attack types (DoS, Probe, Other)
        """
        self.anomaly_model_path = anomaly_model_path
        self.attack_model_path = attack_model_path
        self.anomaly_model = None  # Isolation Forest - detects anomalies
        self.attack_model = None    # Random Forest - classifies attack types
        self.load_models()

    def load_models(self):
        """Load both anomaly detection and attack classification models"""
        # Load Isolation Forest (anomaly detection)
        if os.path.exists(self.anomaly_model_path):
            try:
                self.anomaly_model = joblib.load(self.anomaly_model_path)
                print(f"✅ Anomaly model loaded: {self.anomaly_model_path}")
            except Exception as e:
                print(f"❌ Failed to load anomaly model: {e}")
        else:
            print(f"⚠️  Anomaly model {self.anomaly_model_path} not found.")
        
        # Load Random Forest (attack classification)
        if os.path.exists(self.attack_model_path):
            try:
                self.attack_model = joblib.load(self.attack_model_path)
                print(f"✅ Attack classification model loaded: {self.attack_model_path}")
            except Exception as e:
                print(f"❌ Failed to load attack model: {e}")
        else:
            print(f"⚠️  Attack model {self.attack_model_path} not found.")
        
        if not self.anomaly_model and not self.attack_model:
            print("⚠️  WARNING: No ML models loaded! ML detection will be disabled.")

    def predict(self, features_dict):
        """
        Hybrid prediction using both models:
        1. Isolation Forest detects if there's an anomaly (catches unknown attacks)
        2. Random Forest classifies the attack type (if it's a known attack)
        
        Returns a dictionary:
        {
            'is_anomaly': True/False,      # From Isolation Forest
            'attack_type': 'Normal'/'DoS'/'Probe'/'Other'/'Unknown',  # From Random Forest or 'Unknown' if anomaly but not classified
            'confidence': 'high'/'medium'/'low'  # Based on agreement between models
        }
        """
        ml_features = features_dict.get('ml_features')
        
        if not ml_features or len(ml_features) != 4:
            return {
                'is_anomaly': False,
                'attack_type': 'Normal',
                'confidence': 'low'
            }

        # Prepare features with log transform
        try:
            X = np.array([ml_features], dtype=float)
            # Apply Log Transform to bytes (indices 0 and 1) to match training
            X[0, 0] = np.log1p(X[0, 0])
            X[0, 1] = np.log1p(X[0, 1])
        except Exception as e:
            print(f"Feature preparation error: {e}")
            return {
                'is_anomaly': False,
                'attack_type': 'Normal',
                'confidence': 'low'
            }

        # 1. Anomaly Detection (Isolation Forest) - catches everything unusual
        is_anomaly = False
        anomaly_score = 0.0
        if self.anomaly_model:
            try:
                # Get both prediction and anomaly score
                anomaly_pred = self.anomaly_model.predict(X)[0]
                anomaly_score = self.anomaly_model.score_samples(X)[0]
                is_anomaly = (anomaly_pred == -1)  # -1 = anomaly, 1 = normal
                
                # FIX: Reduce false positives by requiring stronger anomaly signal
                # Lower score_samples means more anomalous (typically < -0.5 for real attacks)
                # Only flag as anomaly if score is significantly negative
                if is_anomaly and anomaly_score > -0.3:
                    # Weak anomaly signal - likely false positive, ignore it
                    is_anomaly = False
            except Exception as e:
                print(f"Anomaly prediction error: {e}")

        # 2. Attack Classification (Random Forest) - categorizes known attacks
        attack_type = 'Normal'
        attack_probability = 0.0
        if self.attack_model:
            try:
                attack_pred = self.attack_model.predict(X)[0]
                attack_probs = self.attack_model.predict_proba(X)[0]
                attack_type = attack_pred  # Returns: 'Normal', 'DoS', 'Probe', or 'Other'
                
                # Get probability of the predicted class
                classes = self.attack_model.classes_
                pred_idx = list(classes).index(attack_type)
                attack_probability = attack_probs[pred_idx]
            except Exception as e:
                print(f"Attack classification error: {e}")
                attack_type = 'Normal'

        # 3. Hybrid Logic: Combine both model outputs with false positive reduction
        if not is_anomaly and attack_type == 'Normal':
            # Both agree: Normal traffic
            return {
                'is_anomaly': False,
                'attack_type': 'Normal',
                'confidence': 'high'
            }
        elif is_anomaly and attack_type != 'Normal':
            # Both agree: Known attack type detected
            # FIX: Require high probability (>0.7) to reduce false positives
            if attack_probability > 0.7:
                return {
                    'is_anomaly': True,
                    'attack_type': attack_type,  # DoS, Probe, or Other
                    'confidence': 'high'
                }
            else:
                # Low probability - likely false positive, downgrade to medium confidence
                return {
                    'is_anomaly': True,
                    'attack_type': attack_type,
                    'confidence': 'low'  # Low confidence - don't alert
                }
        elif is_anomaly and attack_type == 'Normal':
            # Isolation Forest detected anomaly, but Random Forest says Normal
            # FIX: Only flag as "Unknown" if anomaly score is very negative (strong signal)
            # This reduces false positives from normal high-traffic activities
            if anomaly_score < -0.5:
                return {
                    'is_anomaly': True,
                    'attack_type': 'Unknown',  # Novel attack not in training data
                    'confidence': 'medium'
                }
            else:
                # Weak anomaly signal - likely false positive from normal traffic
                return {
                    'is_anomaly': False,
                    'attack_type': 'Normal',
                    'confidence': 'low'
                }
        else:
            # Random Forest says attack, but Isolation Forest says normal
            # FIX: Require high probability to trust Random Forest alone
            if attack_probability > 0.8:
                return {
                    'is_anomaly': True,
                    'attack_type': attack_type,
                    'confidence': 'medium'
                }
            else:
                # Low probability - likely false positive
                return {
                    'is_anomaly': False,
                    'attack_type': 'Normal',
                    'confidence': 'low'
                }