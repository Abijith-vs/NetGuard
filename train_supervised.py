import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# --- 1. CONFIGURATION ---
dataset_path = "nsl-kdd/KDDTrain+.txt"
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
    
    # All others (R2L, U2R) -> Group as 'Other Malicious' for simplicity
    'guess_passwd': 'Other', 'ftp_write': 'Other', 'imap': 'Other', 'phf': 'Other', 
    'multihop': 'Other', 'warezmaster': 'Other', 'warezclient': 'Other', 
    'spy': 'Other', 'rootkit': 'Other', 'buffer_overflow': 'Other', 
    'loadmodule': 'Other', 'perl': 'Other'
}

print("1. Loading dataset...")
try:
    df = pd.read_csv(dataset_path, header=None)
except FileNotFoundError:
    print("Error: KDDTrain+.txt not found in nsl-kdd folder.")
    exit()

# --- 2. SELECT SAME 4 FEATURES AS YOUR SNIFFER ---
# 4=src_bytes, 5=dst_bytes, 22=count, 23=srv_count
print("2. Preparing features...")
X = df.iloc[:, [4, 5, 22, 23]]

# --- 3. PREPARE LABELS (The "Answer Key") ---
# Column 41 contains the attack name (e.g., 'neptune', 'normal')
y_raw = df.iloc[:, 41]
# Convert specific names to categories (DoS, Probe, Normal)
y = y_raw.map(lambda x: attack_mapping.get(x, 'Other'))

print(f"   Training on {len(X)} packets.")
print(f"   Attack types found: {y.unique()}")

# --- 4. TRAIN THE CLASSIFIER ---
print("3. Training Random Forest (This may take a minute)...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

# --- 5. SAVE ---
print(f"4. Saving model to {model_filename}...")
joblib.dump(clf, model_filename)
print("SUCCESS! You can now predict attack types.")