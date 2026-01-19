import pandas as pd
import joblib # Used to save the model
from sklearn.ensemble import IsolationForest

# --- CONFIGURATION ---
# We point to where your dataset is stored
dataset_path = "nsl-kdd/KDDTrain+.txt" 
model_filename = "model.pkl"

print("1. Loading dataset...")
try:
    # We read the CSV file. header=None means the file has no column names at the top.
    df = pd.read_csv(dataset_path, header=None)
except FileNotFoundError:
    print(f"ERROR: Could not find {dataset_path}")
    print("Please make sure the 'nsl-kdd' folder and 'KDDTrain+.txt' exist.")
    exit()

# --- THE FIX IS HERE ---
# Your 'network_engine.py' only calculates these 4 things:
# src_bytes, dst_bytes, count, srv_count
# In the NSL-KDD dataset, these live at specific column numbers (indices):
# Col 4  = src_bytes
# Col 5  = dst_bytes
# Col 22 = count
# Col 23 = srv_count

print("2. Selecting only the 4 features...")
selected_columns = [4, 5, 22, 23]
X_train = df.iloc[:, selected_columns]

# Show the user what we are training on
print(f"   Training data shape: {X_train.shape}")
print("   (This should say something like (125973, 4) - verify the '4'!)")

# --- TRAINING THE MODEL ---
print("3. Training the Isolation Forest model...")
# contamination=0.01 means we guess about 1% of the data is malicious
clf = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
clf.fit(X_train)

# --- SAVING ---
print(f"4. Saving the new model to {model_filename}...")
joblib.dump(clf, model_filename)

print("SUCCESS! New model created.")