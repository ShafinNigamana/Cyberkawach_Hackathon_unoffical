"""
Train and evaluate Laya Typed-Decision Model on the 500+ sample corpus.
Computes Training Accuracy, 5-Fold Cross-Validation Accuracy, Precision, Recall, F1, and Generalization Gap.
"""
import json
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, Ridge
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

def run_evaluation():
    data_path = os.path.join(os.path.dirname(__file__), "laya_training_corpus.json")
    with open(data_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    print(f"Loaded {len(samples)} samples from {data_path}")

    texts = [s["text"] for s in samples]
    y_fraud = np.array([1 if s["fraud"] >= 0.5 else 0 for s in samples])
    y_cat = np.array([s["category"] for s in samples])

    # Class distribution
    print("\nClass Distribution:")
    unique, counts = np.unique(y_cat, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"  {u:16s}: {c:3d} samples")

    # Feature extraction
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=350,
        min_df=2,
        sublinear_tf=True,
        lowercase=True,
        stop_words="english",
    )
    X = vectorizer.fit_transform(texts)
    print(f"\nFeature matrix shape: {X.shape} ({X.shape[0]} samples, {X.shape[1]} features)")

    # ─── Full Training Set Performance ───
    clf_fraud = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
    clf_fraud.fit(X, y_fraud)
    y_train_pred = clf_fraud.predict(X)

    train_acc = accuracy_score(y_fraud, y_train_pred)
    train_prec = precision_score(y_fraud, y_train_pred)
    train_rec = recall_score(y_fraud, y_train_pred)
    train_f1 = f1_score(y_fraud, y_train_pred)

    clf_cat = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
    clf_cat.fit(X, y_cat)
    y_cat_train_pred = clf_cat.predict(X)
    train_cat_acc = accuracy_score(y_cat, y_cat_train_pred)

    # ─── 5-Fold Stratified Cross-Validation (Out-of-Fold Evaluation) ───
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    val_fraud_preds = np.zeros(len(y_fraud))
    val_fraud_probs = np.zeros(len(y_fraud))
    val_cat_preds = ["" for _ in range(len(y_cat))]

    fold_accs = []
    fold_f1s = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, y_cat)):
        # Train fold on fraud
        fold_clf_fraud = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
        fold_clf_fraud.fit(X[train_idx], y_fraud[train_idx])
        pred_f = fold_clf_fraud.predict(X[val_idx])
        prob_f = fold_clf_fraud.predict_proba(X[val_idx])[:, 1]
        val_fraud_preds[val_idx] = pred_f
        val_fraud_probs[val_idx] = prob_f

        fold_acc = accuracy_score(y_fraud[val_idx], pred_f)
        fold_f1 = f1_score(y_fraud[val_idx], pred_f)
        fold_accs.append(fold_acc)
        fold_f1s.append(fold_f1)

        # Train fold on category
        fold_clf_cat = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
        fold_clf_cat.fit(X[train_idx], y_cat[train_idx])
        pred_c = fold_clf_cat.predict(X[val_idx])
        for i, idx in enumerate(val_idx):
            val_cat_preds[idx] = pred_c[i]

    val_cat_preds = np.array(val_cat_preds)

    # Metrics on Out-of-Fold Validation
    val_acc = accuracy_score(y_fraud, val_fraud_preds)
    val_prec = precision_score(y_fraud, val_fraud_preds)
    val_rec = recall_score(y_fraud, val_fraud_preds)
    val_f1 = f1_score(y_fraud, val_fraud_preds)
    val_cat_acc = accuracy_score(y_cat, val_cat_preds)

    print("\n" + "="*50)
    print("      LAYA MODEL PERFORMANCE (508 SAMPLES)")
    print("="*50)
    print(f"TRAINING SET METRICS:")
    print(f"  • Fraud Accuracy:  {train_acc * 100:.2f}%")
    print(f"  • Fraud Precision: {train_prec * 100:.2f}%")
    print(f"  • Fraud Recall:    {train_rec * 100:.2f}%")
    print(f"  • Fraud F1 Score:  {train_f1 * 100:.2f}%")
    print(f"  • Category Acc:    {train_cat_acc * 100:.2f}%")

    print("\nVALIDATION SET METRICS (5-Fold Stratified CV):")
    print(f"  • Fraud Accuracy:  {val_acc * 100:.2f}% (Fold std: {np.std(fold_accs)*100:.2f}%)")
    print(f"  • Fraud Precision: {val_prec * 100:.2f}%")
    print(f"  • Fraud Recall:    {val_rec * 100:.2f}%")
    print(f"  • Fraud F1 Score:  {val_f1 * 100:.2f}%")
    print(f"  • Category Acc:    {val_cat_acc * 100:.2f}%")

    gap = (train_acc - val_acc) * 100
    print(f"\nGENERALIZATION GAP (Train - Val): {gap:.2f}%")
    print("="*50)

    cm = confusion_matrix(y_fraud, val_fraud_preds)
    print("\nConfusion Matrix on Validation Data:")
    print(f"  True Negatives (Legit identified as Legit): {cm[0][0]}")
    print(f"  False Positives (Legit flagged as Fraud):   {cm[0][1]}")
    print(f"  False Negatives (Fraud missed):             {cm[1][0]}")
    print(f"  True Positives (Fraud caught):              {cm[1][1]}")

if __name__ == "__main__":
    run_evaluation()
