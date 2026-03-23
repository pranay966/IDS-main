"""
train_model.py — Train & save IDS models locally using the NSL-KDD dataset.

This script:
  1. Downloads NSL-KDD training + test data from a public mirror
  2. Preprocesses the data (encode categoricals, scale features)
  3. Trains a Random Forest  → saved as  ml_model.pkl
  4. Trains a Gradient Boosting (Transfer Learning proxy) → tl_model.pkl
  5. Saves label encoders

Run once before starting the server:
    python train_model.py

⚠  If you already exported your Colab model as ml_model.pkl / tl_model.pkl,
   place those files in this same folder and skip running this script.
"""

import os
import urllib.request
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score

# ─── NSL-KDD column names ────────────────────────────────────────────────────
COLUMNS = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root',
    'num_file_creations','num_shells','num_access_files','num_outbound_cmds',
    'is_host_login','is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate','same_srv_rate',
    'diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label','difficulty'
]

TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL  = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))


def download_data(url: str, filename: str) -> str:
    path = os.path.join(MODEL_DIR, filename)
    if not os.path.exists(path):
        print(f"  Downloading {filename} ...")
        urllib.request.urlretrieve(url, path)
        print(f"  ✓ Saved to {path}")
    else:
        print(f"  ✓ {filename} already exists, skipping download.")
    return path


def load_and_preprocess(train_path: str, test_path: str):
    print("\n📂 Loading data...")
    train_df = pd.read_csv(train_path, header=None, names=COLUMNS)
    test_df  = pd.read_csv(test_path,  header=None, names=COLUMNS)

    # Drop difficulty column
    train_df.drop('difficulty', axis=1, inplace=True)
    test_df.drop('difficulty',  axis=1, inplace=True)

    # Simplify labels to binary: normal vs attack
    # (comment this section out if you want multi-class)
    def simplify_label(label):
        return 'normal' if str(label).strip().lower() == 'normal' else 'attack'

    train_df['label'] = train_df['label'].apply(simplify_label)
    test_df['label']  = test_df['label'].apply(simplify_label)

    # Encode categorical features
    cat_cols = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        combined = pd.concat([train_df[col], test_df[col]], axis=0)
        le.fit(combined)
        train_df[col] = le.transform(train_df[col])
        test_df[col]  = le.transform(test_df[col])
        encoders[col] = le

    # Encode target label
    label_encoder = LabelEncoder()
    label_encoder.fit(pd.concat([train_df['label'], test_df['label']]))
    y_train = label_encoder.transform(train_df['label'])
    y_test  = label_encoder.transform(test_df['label'])

    X_train = train_df.drop('label', axis=1).values.astype(float)
    X_test  = test_df.drop('label',  axis=1).values.astype(float)

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    print(f"  Train: {X_train.shape}  |  Test: {X_test.shape}")
    print(f"  Classes: {label_encoder.classes_}")

    return X_train, y_train, X_test, y_test, label_encoder, scaler


def train_and_save_ml(X_train, y_train, X_test, y_test, label_encoder, scaler):
    print("\n🌳 Training ML model (Random Forest)...")
    ml_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        n_jobs=-1,
        random_state=42
    )
    ml_model.fit(X_train, y_train)

    y_pred = ml_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  ✓ Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    joblib.dump(ml_model,   os.path.join(MODEL_DIR, 'ml_model.pkl'))
    joblib.dump(label_encoder, os.path.join(MODEL_DIR, 'ml_label_encoder.pkl'))
    joblib.dump(scaler,     os.path.join(MODEL_DIR, 'ml_scaler.pkl'))
    print("  ✓ Saved: ml_model.pkl, ml_label_encoder.pkl, ml_scaler.pkl")


def train_and_save_tl(X_train, y_train, X_test, y_test, label_encoder, scaler):
    print("\n⚡ Training TL model (Gradient Boosting — Transfer Learning proxy)...")
    tl_model = GradientBoostingClassifier(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=5,
        random_state=42
    )
    tl_model.fit(X_train, y_train)

    y_pred = tl_model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"  ✓ Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

    joblib.dump(tl_model,      os.path.join(MODEL_DIR, 'tl_model.pkl'))
    joblib.dump(label_encoder, os.path.join(MODEL_DIR, 'tl_label_encoder.pkl'))
    joblib.dump(scaler,        os.path.join(MODEL_DIR, 'tl_scaler.pkl'))
    print("  ✓ Saved: tl_model.pkl, tl_label_encoder.pkl, tl_scaler.pkl")


if __name__ == '__main__':
    print("=" * 60)
    print("  IDS Model Training Script")
    print("=" * 60)

    # Download NSL-KDD data
    train_path = download_data(TRAIN_URL, 'KDDTrain+.txt')
    test_path  = download_data(TEST_URL,  'KDDTest+.txt')

    # Preprocess
    X_train, y_train, X_test, y_test, label_encoder, scaler = \
        load_and_preprocess(train_path, test_path)

    # Train and save both models
    train_and_save_ml(X_train, y_train, X_test, y_test, label_encoder, scaler)
    train_and_save_tl(X_train, y_train, X_test, y_test, label_encoder, scaler)

    print("\n🎉 Training complete! Models saved in backend/ folder.")
    print("   Now run:  python app.py")
