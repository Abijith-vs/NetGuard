import joblib
import numpy as np
import os

class AnomalyDetector:
    def __init__(self, model_path='attack_model.pkl'): # <--- CHANGED FILENAME
        self.model_path = model_path
        self.model = None
        self.load_model()

    def load_model(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print(f"Model loaded: {self.model_path}")
            except Exception as e:
                print(f"Failed to load model: {e}")
        else:
            print(f"Model {self.model_path} not found.")

    def predict(self, features_dict):
        """
        Returns: String (e.g., 'Normal', 'DoS', 'Probe')
        """
        ml_features = features_dict.get('ml_features')
        
        if not ml_features or len(ml_features) != 4:
            return "Normal"

        if self.model:
            try:
                # Reshape and Predict
                X = np.array([ml_features])
                prediction = self.model.predict(X)[0] # Returns string now!
                return prediction
            except Exception as e:
                print(f"Prediction error: {e}")
                return "Normal"
        else:
            return "Normal"