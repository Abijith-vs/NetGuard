import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Dataset Path
DATASET_DIR = r"C:\Users\karth\OneDrive\Documents\Projects\NetGuard\nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "model.pkl"

# NSL-KDD Column Names (Subset relevant to our simplistic extraction + label)
# The full dataset has 43 columns. We need to be careful with current pandas logic.
# If the file doesn't have headers, we need to assign them or read carefully.
# KDDTrain+.txt usually does NOT have headers.

# We will define a subset of columns to read or just read all and select by index if we know them.
# Standard NSL-KDD columns: 
# 0: duration, 1: protocol_type, 2: service, 3: flag, 4: src_bytes, 5: dst_bytes, ...
# 22: count, 23: srv_count ...
# 41: class (normal/anomaly)

def train_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        # Read only necessary columns to identify and train
        # Columns used in network_engine: src_bytes, dst_bytes, count, srv_count
        # Their indices in NSL-KDD (0-based):
        # src_bytes: 4
        # dst_bytes: 5
        # count: 22
        # srv_count: 23
        
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # Select relevant features
        X_train = df.iloc[:, [4, 5, 22, 23]].values
        
        print(f"Training data shape: {X_train.shape}")
        
        # Train Isolation Forest
        # contamination='auto' or 0.1 depending on expected anomaly rate
        print("Training Isolation Forest model...")
        clf = IsolationForest(n_estimators=100, max_samples='auto', contamination='auto', random_state=42)
        clf.fit(X_train)
        
        # Save model
        joblib.dump(clf, MODEL_FILE)
        print(f"Model saved to {MODEL_FILE}")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")

if __name__ == "__main__":
    train_model()
