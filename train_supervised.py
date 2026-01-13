import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "rf_model.pkl"

def get_feature_indices():
    """
    Returns the list of 0-based indices for numerical features to use.
    Using same expanded feature set as Isolation Forest attempt.
    """
    return [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

def train_supervised_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # Features
        feature_indices = get_feature_indices()
        X_train = df.iloc[:, feature_indices].values
        
        # Labels (Column 41)
        # 'normal' -> 1, anything else -> -1 (to match our convention)
        y_train = df.iloc[:, 41].apply(lambda x: 1 if x == 'normal' else -1).values
        
        print(f"Training data shape: {X_train.shape}")
        
        print("Training Random Forest Classifier...")
        # Random Forest is a robust supervised model
        clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        clf.fit(X_train, y_train)
        
        # Save model
        joblib.dump(clf, MODEL_FILE)
        print(f"Supervised Model saved to {MODEL_FILE}")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")

if __name__ == "__main__":
    train_supervised_model()
