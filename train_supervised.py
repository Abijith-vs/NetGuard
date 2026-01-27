import pandas as pd
import joblib
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# --- 1. CONFIGURATION ---
train_path = "nsl-kdd/KDDTrain+.txt"
test_path = "nsl-kdd/KDDTest+.txt"
model_filename = "attack_model.pkl"

# Dictionary to map specific KDD attacks to General Categories
attack_mapping = {
    'normal': 'Normal',
    'neptune': 'DoS', 'smurf': 'DoS', 'back': 'DoS', 'teardrop': 'DoS', 
    'pod': 'DoS', 'land': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 
    'processtable': 'DoS', 'udpstorm': 'DoS',
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
    'mscan': 'Probe', 'saint': 'Probe',
    'guess_passwd': 'Other', 'ftp_write': 'Other', 'imap': 'Other', 'phf': 'Other', 
    'multihop': 'Other', 'warezmaster': 'Other', 'warezclient': 'Other', 
    'spy': 'Other', 'rootkit': 'Other', 'buffer_overflow': 'Other', 
    'loadmodule': 'Other', 'perl': 'Other'
}

def load_and_merge_datasets():
    print("1. Loading datasets...")
    if not os.path.exists(train_path):
        print(f"❌ ERROR: '{train_path}' not found.")
        exit()

    df1 = pd.read_csv(train_path, header=None)
    print(f"   Loaded Training Set: {len(df1)} rows")

    if os.path.exists(test_path):
        df2 = pd.read_csv(test_path, header=None)
        print(f"   Loaded Testing Set:  {len(df2)} rows")
        df = pd.concat([df1, df2], ignore_index=True)
    else:
        print("   ⚠️  Test file not found. Training on Train set only.")
        df = df1
    return df

# --- MAIN EXECUTION ---
df = load_and_merge_datasets()

# --- 2. SELECT FEATURES ---
# 4=src_bytes, 5=dst_bytes, 22=count, 23=srv_count
print("2. Preparing features...")
X = df.iloc[:, [4, 5, 22, 23]]

# Force numeric
X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

# --- 3. PREPROCESSING (LOG TRANSFORM) ---
# Fixes the "YouTube" False Positive issue
print("   [Applying Log Transformation to Bytes...]")
X.iloc[:, 0] = np.log1p(X.iloc[:, 0]) # src_bytes
X.iloc[:, 1] = np.log1p(X.iloc[:, 1]) # dst_bytes

# --- 4. PREPARE LABELS ---
y_raw = df.iloc[:, 41]
y = y_raw.map(lambda x: attack_mapping.get(x, 'Other'))

# --- 5. TRAIN ---
print(f"3. Training Random Forest on {len(X)} packets...")
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X, y)

# --- 6. SAVE ---
print(f"4. Saving model to {model_filename}...")
joblib.dump(clf, model_filename, compress=3)
print("SUCCESS! You can now run 'main.py'.")