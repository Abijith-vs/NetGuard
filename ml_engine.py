import joblib
import pandas as pd
import numpy as np
import os

class AnomalyDetector:
    def __init__(self, model_path='model.pkl'):
        self.model_path = model_path
        self.model = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"Model loaded from {self.model_path}")
            except Exception as e:
                print(f"Failed to load model: {e}")
                self.model = None
        else:
            print("Model file not found. Using fallback logic.")
            self.model = None

    def predict(self, features_dict):
        """
        Predicts anomaly based on features.
        Returns: 
            -1 for Anomaly
             1 for Normal
        """
        # Features needed: src_bytes, dst_bytes, count, srv_count
        ml_features = features_dict.get('ml_features')
        
        if not ml_features or len(ml_features) != 4:
            return 1 # Fallback to normal if data invalid
            
        src_bytes, dst_bytes, count, srv_count = ml_features

        if self.model:
            try:
                # Reshape for sklearn
                X = np.array([ml_features])
                # Isolation Forest returns -1 for outlier, 1 for inlier
                prediction = self.model.predict(X)[0]
                return prediction
            except Exception as e:
                print(f"Prediction error: {e}")
                return self.fallback_logic(count)
        else:
            return self.fallback_logic(count)

    def fallback_logic(self, count):
        """
        Simple heuristic:
        If packets from same IP in 2s (count) > 50, flag as Anomaly (-1).
        Else Normal (1).
        """
        if count > 50:
            return -1
        return 1
