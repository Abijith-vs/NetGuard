import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Dataset Path
DATASET_DIR = r"nsl-kdd"
TEST_FILE = os.path.join(DATASET_DIR, "KDDTest+.txt")
# MODEL_FILE = "model.pkl" # Isolation Forest
MODEL_FILE = "rf_model.pkl" # Random Forest

def evaluate_model():
    print(f"Loading model from {MODEL_FILE}...")
    if not os.path.exists(MODEL_FILE):
        print(f"Error: Model file {MODEL_FILE} not found. Please train the model first.")
        return

    try:
        clf = joblib.load(MODEL_FILE)
    except Exception as e:
        print(f"Error loading model: {e}")
        return

    print(f"Loading test dataset from {TEST_FILE}...")
    if not os.path.exists(TEST_FILE):
        print(f"Error: Test file {TEST_FILE} not found.")
        return

    try:
        # Read the dataset (no header)
        df = pd.read_csv(TEST_FILE, header=None)
        
        # Select expanded relevant features: 
        # 0:duration, 4:src_bytes, 5:dst_bytes, 22:count, 23:srv_count, 
        # 28:same_srv_rate, 29:diff_srv_rate, 31:dst_host_count, 32:dst_host_srv_count, 
        # 33:dst_host_same_srv_rate, 34:dst_host_diff_srv_rate, 35:dst_host_same_src_port_rate, 
        # 37:dst_host_serror_rate, 38:dst_host_srv_serror_rate
        feature_indices = [0, 4, 5, 22, 23, 28, 29, 31, 32, 33, 34, 35, 37, 38]
        X_test = df.iloc[:, feature_indices].values
        
        # Extract ground truth labels from column 41
        # 'normal' -> 1, anything else -> -1
        y_true = df.iloc[:, 41].apply(lambda x: 1 if x == 'normal' else -1).values
        
        print(f"Test data shape: {X_test.shape}")
        
        print("Running predictions...")
        y_pred = clf.predict(X_test)
        
        # Calculate metrics
        accuracy = accuracy_score(y_true, y_pred)
        # Handle cases where division by zero might occur if no anomalies are predicted/exist
        precision = precision_score(y_true, y_pred, pos_label=-1, zero_division=0) # Focus on Anomaly class (-1)
        recall = recall_score(y_true, y_pred, pos_label=-1, zero_division=0)
        f1 = f1_score(y_true, y_pred, pos_label=-1, zero_division=0)
        conf_matrix = confusion_matrix(y_true, y_pred)
        
        print("\n--- Evaluation Results ---")
        print(f"Accuracy: {accuracy:.4f}")
        print(f"Precision (Anomaly): {precision:.4f}")
        print(f"Recall (Anomaly): {recall:.4f}")
        print(f"F1 Score (Anomaly): {f1:.4f}")
        
        print("\nConfusion Matrix:")
        print("                 Predicted Anomaly (-1)   Predicted Normal (1)")
        try:
            print(f"Actual Anomaly (-1)       {conf_matrix[0][0]:<20} {conf_matrix[0][1]}")
            print(f"Actual Normal  (1)       {conf_matrix[1][0]:<20} {conf_matrix[1][1]}")
        except IndexError:
             print("Confusion Matrix shape mismatch (possibly only one class predicted):")
             print(conf_matrix)
        
    except Exception as e:
        print(f"An error occurred during evaluation: {e}")

if __name__ == "__main__":
    evaluate_model()
