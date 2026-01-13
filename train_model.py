import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TRAIN_FILE = os.path.join(DATASET_DIR, "KDDTrain+.txt")
MODEL_FILE = "model.pkl"

def get_feature_indices():
    """
    Returns the list of 0-based indices for numerical features to use.
    
    selected_features = [
        0,  # duration
        4,  # src_bytes
        5,  # dst_bytes
        22, # count
        23, # srv_count
        28, # same_srv_rate
        29, # diff_srv_rate
        31, # dst_host_count
        32, # dst_host_srv_count
        33, # dst_host_same_srv_rate
        34, # dst_host_diff_srv_rate
        35, # dst_host_same_src_port_rate
        37, # dst_host_serror_rate
        38, # dst_host_srv_serror_rate
    ]
    """
    return [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]

def train_model():
    if not os.path.exists(TRAIN_FILE):
        print(f"Error: Dataset file not found at {TRAIN_FILE}")
        return

    print("Loading dataset...")
    try:
        # KDDTrain+.txt does not have headers
        df = pd.read_csv(TRAIN_FILE, header=None)
        
        # Select expanded feature set
        feature_indices = get_feature_indices()
        X_train = df.iloc[:, feature_indices].values
        
        print(f"Training data shape: {X_train.shape}")
        
        # Train Isolation Forest
        # Tuning: contamination=0.01 (assuming anomalies are rare in normal traffic training data)
        # Note: KDDTrain+ contains attacks, so it's not a 'clean' baseline. 
        # IsolationForest works by assuming anomalies are 'few and different'. 
        # KDDTrain+ is actually ~46% anomaly. Training IF on mixed labeled data as if it were normal 
        # is suboptimal, but fits the 'unsupervised' requirement if labels weren't known. 
        # For the purpose of this step "Tune IsolationForest", we will adjust parameters.
        print("Training Isolation Forest model (Expanded Features)...")
        clf = IsolationForest(
            n_estimators=200, 
            max_samples=256, 
            contamination=0.1, 
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X_train)
        
        # Save model
        joblib.dump(clf, MODEL_FILE)
        print(f"Model saved to {MODEL_FILE}")
        
    except Exception as e:
        print(f"An error occurred during training: {e}")

if __name__ == "__main__":
    train_model()
