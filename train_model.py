import pandas as pd
import joblib 
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
dataset_path = "nsl-kdd/KDDTrain+.txt" 
model_filename = "model.pkl"

print("1. Loading dataset...")
try:
    df = pd.read_csv(dataset_path, header=None)
except FileNotFoundError:
    print(f"ERROR: Could not find {dataset_path}")
    exit()

# --- SELECT 4 FEATURES ---
# 4=src_bytes, 5=dst_bytes, 22=count, 23=srv_count
print("2. Selecting features...")
selected_columns = [4, 5, 22, 23]
X_train = df.iloc[:, selected_columns]

# --- TRAIN MODEL ---
print("3. Training Isolation Forest...")
# FIX: Reduced contamination from 0.01 to 0.05 to reduce false positives
# contamination=0.05 means we expect ~5% of traffic to be malicious
# This is more realistic for real networks and reduces false positives
# Lower contamination = more sensitive (more false positives)
# Higher contamination = less sensitive (fewer false positives, but may miss attacks)
clf = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
clf.fit(X_train)

# --- SAVE ---
print(f"4. Saving to {model_filename}...")
joblib.dump(clf, model_filename)
print("SUCCESS! Model created.")