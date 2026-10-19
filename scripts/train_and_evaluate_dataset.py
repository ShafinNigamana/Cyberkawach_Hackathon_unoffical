"""
Download Kaggle / UCI SMS Spam & Phishing Dataset, combine with Indian Cyber-Fraud Vectors,
train the ML Classifier, and evaluate accuracy metrics (Precision, Recall, F1, Accuracy, Confusion Matrix).
"""

import csv
import io
import json
import logging
import sys
from pathlib import Path

PROJECT_ROOT = Path(r"c:\Users\5430\OneDrive\Documents\OneDrive\Desktop\cyberkawach\Cyberkawach_Hackathon_unoffical")
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.model_selection import train_test_split

DATA_DIR = PROJECT_ROOT / "backend" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = DATA_DIR / "kaggle_sms_dataset.csv"

# 1. Download Kaggle / UCI SMS dataset if not already cached
if not CACHE_FILE.exists():
    print("Downloading Kaggle/UCI SMS Spam & Phishing benchmark dataset (5,574 samples)...")
    url = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"
    resp = httpx.get(url, timeout=30.0)
    resp.raise_for_status()
    
    rows = []
    for line in resp.text.splitlines():
        if "\t" in line:
            label, text = line.split("\t", 1)
            # label 1 for spam/phishing, 0 for ham/legitimate
            rows.append({"text": text.strip(), "label": 1 if label.strip() == "spam" else 0})
            
    with open(CACHE_FILE, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Cached {len(rows)} samples to {CACHE_FILE}")
else:
    print(f"Loading cached dataset from {CACHE_FILE}...")
    rows = []
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({"text": r["text"], "label": int(r["label"])})
    print(f"Loaded {len(rows)} samples.")

# 2. Add Indian Cyber Fraud & Phishing Telemetric Vectors (high-priority localized vectors)
from backend.modules.ml_classifier import _TRAINING_DATA

all_texts = [r["text"] for r in rows] + [t[0] for t in _TRAINING_DATA]
all_labels = [r["label"] for r in rows] + [t[1] for t in _TRAINING_DATA]

print(f"Total dataset size: {len(all_texts)} samples ({sum(all_labels)} phishing/scam, {len(all_labels) - sum(all_labels)} legitimate)")

# 3. Train/Test Split (80% Train, 20% Test with stratification)
X_train, X_test, y_train, y_test = train_test_split(
    all_texts, all_labels, test_size=0.20, random_state=42, stratify=all_labels
)

print(f"Training set: {len(X_train)} samples | Test set: {len(X_test)} samples")

# 4. Train TF-IDF + Logistic Regression Classifier
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=2500,
    lowercase=True,
    sublinear_tf=True,
    token_pattern=r"(?u)\b\w+\b|https?://\S+",
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(C=2.0, max_iter=400, class_weight="balanced", random_state=42)
model.fit(X_train_vec, y_train)

# 5. Evaluate on Test Split
y_pred = model.predict(X_test_vec)
acc = accuracy_score(y_test, y_pred)
cm = confusion_matrix(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing/Scam"])

print("\n" + "=" * 60)
print(f" MODEL EVALUATION ON HELD-OUT TEST SPLIT (20% of {len(all_texts)} samples)")
print("=" * 60)
print(f"Overall Accuracy: {acc * 100:.2f}%\n")
print("Classification Report:")
print(report)
print("Confusion Matrix:")
print(f"  [TN: {cm[0][0]:<4}  FP: {cm[0][1]:<4}]")
print(f"  [FN: {cm[1][0]:<4}  TP: {cm[1][1]:<4}]")
print("=" * 60)

# 6. Evaluate on Cyberkawach 20-Case Accuracy Matrix
fixture_path = PROJECT_ROOT / "fixtures" / "accuracy_matrix_cases.json"
with open(fixture_path, "r", encoding="utf-8") as f:
    cases = json.load(f)

print("\n" + "=" * 80)
print(" EVALUATION ON 20 CYBERKAWACH BENCHMARK CASES")
print("=" * 80)
print(f"{'Case ID':<32} | {'True Type':<6} | {'Pred Class':<10} | {'Prob':<6} | {'Status':<6}")
print("-" * 80)

correct_count = 0
for case in cases:
    cid = case["id"]
    msg = case["message"]
    is_phish = bool(case.get("is_phishing", False))
    true_type = "PHISH" if is_phish else "LEGIT"
    
    vec = vectorizer.transform([msg])
    prob = float(model.predict_proba(vec)[0][1])
    pred_phish = prob >= 0.50
    pred_label = "PHISH" if pred_phish else "LEGIT"
    
    is_correct = (pred_phish == is_phish)
    if is_correct:
        correct_count += 1
    status = "PASS" if is_correct else "FAIL"
    print(f"{cid:<32} | {true_type:<6} | {pred_label:<10} | {prob:<6.3f} | {status:<6}")

print("=" * 80)
print(f"Benchmark Accuracy: {correct_count} / {len(cases)} ({correct_count / len(cases) * 100:.1f}%)")
print("=" * 80)
