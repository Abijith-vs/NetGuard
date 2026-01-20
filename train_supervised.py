import pandas as pd
import joblib
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier

# --- 1. CONFIGURATION ---
# We define paths for BOTH datasets to make the model smarter
train_path = "nsl-kdd/KDDTrain+.txt"
test_path = "nsl-kdd/KDDTest+.txt"
model_filename = "attack_model.pkl"

# Dictionary to map specific KDD attacks to General Categories
attack_mapping = {
    'normal': 'Normal',
    
    # DoS (Denial of Service)
    'neptune': 'DoS', 'smurf': 'DoS', 'back': 'DoS', 'teardrop': 'DoS', 
    'pod': 'DoS', 'land': 'DoS', 'mailbomb': 'DoS', 'apache2': 'DoS', 
    'processtable': 'DoS', 'udpstorm': 'DoS',
    
    # Probe (Scanning)
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe', 
    'mscan': 'Probe', 'saint': 'Probe',
    
    # All others (R2L, U2R) -> Group as 'Other'
    'guess_passwd': 'Other', 'ftp_write': 'Other', 'imap': 'Other', 'phf': 'Other', 
    'multihop': 'Other', 'warezmaster': 'Other', 'warezclient': 'Other', 
    'spy': 'Other', 'rootkit': 'Other', 'buffer_overflow': 'Other', 
    'loadmodule': 'Other', 'perl': 'Other'
}

def load_and_merge_datasets():
    print("1. Loading datasets...")
    
    # Check if files exist
    if not os.path.exists(train_path):
        print(f"❌ ERROR: '{train_path}' not found.")
        print("   Make sure the 'nsl-kdd' folder is in your project directory.")
        exit()

    # Load Train
    df1 = pd.read_csv(train_path, header=None)
    print(f"   Loaded Training Set: {len(df1)} rows")

    # Load Test (If it exists) - Makes model stronger
    if os.path.exists(test_path):
        df2 = pd.read_csv(test_path, header=None)
        print(f"   Loaded Testing Set:  {len(df2)} rows")
        # Combine them
        df = pd.concat([df1, df2], ignore_index=True)
        print(f"   MERGED TOTAL:        {len(df)} rows")
    else:
        print("   ⚠️  Warning: Test file not found. Training on Train set only.")
        df = df1
        
    return df

# --- MAIN EXECUTION ---
df = load_and_merge_datasets()

# --- 2. SELECT SAME 4 FEATURES AS YOUR SNIFFER ---
# 4=src_bytes, 5=dst_bytes, 22=count, 23=srv_count
print("2. Preparing features...")
X = df.iloc[:, [4, 5, 22, 23]]

# [DEBUG] Force all data to be numeric (fixes "string" errors)
X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

# --- 3. PREPARE LABELS ---
# Column 41 contains the attack name
y_raw = df.iloc[:, 41]
y = y_raw.map(lambda x: attack_mapping.get(x, 'Other'))

print(f"   Attack types found: {y.unique()}")

# --- 4. TRAIN THE CLASSIFIER ---
print("3. Training Random Forest (200 Trees)...")
# n_estimators=200 makes it more stable
clf = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
clf.fit(X, y)

# ---