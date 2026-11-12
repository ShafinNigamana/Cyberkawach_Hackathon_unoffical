"""
Train and calibrate the Scikit-Learn ML Classifier on the new 520-sample dataset.
Evaluates Training, 5-Fold Stratified Cross-Validation, and saves model to backend/data/ml_classifier_model.pkl.
"""
import json
import os
import pickle
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

def train_and_evaluate_ml_classifier():
    data_path = os.path.join(os.path.dirname(__file__), "ml_classifier_training_corpus.json")
    with open(data_path, "r", encoding="utf-8") as f:
        samples = json.load(f)

    texts = [s["text"] for s in samples]
    labels = np.array([s["label"] for s in samples])

    print(f"Loaded {len(samples)} distinct samples:")
    print(f"  • Phishing / Fraud (Label 1): {np.sum(labels == 1)} samples")
    print(f"  • Benign / Non-Fraud (Label 0): {np.sum(labels == 0)} samples")

    # Regularized TF-IDF feature extraction
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=400,
        min_df=2,
        sublinear_tf=True,
        lowercase=True,
        token_pattern=r"(?u)\b\w+\b|https?://\S+",
    )
    X = vectorizer.fit_transform(texts)
    print(f"\nFeature matrix: {X.shape[0]} samples x {X.shape[1]} features (ratio: {X.shape[1]/X.shape[0]:.2f})")

    # 1. Full Training Set Fit
    model = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
    model.fit(X, labels)
    train_preds = model.predict(X)

    train_acc = accuracy_score(labels, train_preds)
    train_prec = precision_score(labels, train_preds)
    train_rec = recall_score(labels, train_preds)
    train_f1 = f1_score(labels, train_preds)

    # 2. 5-Fold Stratified Cross-Validation (Out-of-Fold Validation)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    val_preds = np.zeros(len(labels))
    val_accs = []

    for fold, (train_idx, val_idx) in enumerate(skf.split(X, labels)):
        fold_clf = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
        fold_clf.fit(X[train_idx], labels[train_idx])
        pred = fold_clf.predict(X[val_idx])
        val_preds[val_idx] = pred
        val_accs.append(accuracy_score(labels[val_idx], pred))

    val_acc = accuracy_score(labels, val_preds)
    val_prec = precision_score(labels, val_preds)
    val_rec = recall_score(labels, val_preds)
    val_f1 = f1_score(labels, val_preds)
    cm = confusion_matrix(labels, val_preds)

    print("\n" + "="*55)
    print("   SCIKIT-LEARN ML CLASSIFIER PERFORMANCE METRICS")
    print("="*55)
    print("TRAINING SET EVALUATION:")
    print(f"  • Training Accuracy:  {train_acc * 100:.2f}%")
    print(f"  • Training Precision: {train_prec * 100:.2f}%")
    print(f"  • Training Recall:    {train_rec * 100:.2f}%")
    print(f"  • Training F1 Score:  {train_f1 * 100:.2f}%")

    print("\nVALIDATION SET EVALUATION (5-Fold Stratified CV):")
    print(f"  • Validation Accuracy:  {val_acc * 100:.2f}% (Fold std: {np.std(val_accs)*100:.2f}%)")
    print(f"  • Validation Precision: {val_prec * 100:.2f}%")
    print(f"  • Validation Recall:    {val_rec * 100:.2f}%")
    print(f"  • Validation F1 Score:  {val_f1 * 100:.2f}%")

    gap = (train_acc - val_acc) * 100
    print(f"\nGENERALIZATION GAP (Train - Validation): {gap:.2f}%")
    print(f"STATUS: {'BALANCED / PROPER FIT' if gap < 10 else 'OVERFIT'}")
    print("="*55)

    print("\nValidation Confusion Matrix:")
    print(f"  • True Negatives (Benign verified as Benign): {cm[0][0]} / {np.sum(labels == 0)}")
    print(f"  • False Positives (Benign misclassified as Fraud): {cm[0][1]} / {np.sum(labels == 0)}")
    print(f"  • False Negatives (Fraud missed): {cm[1][0]} / {np.sum(labels == 1)}")
    print(f"  • True Positives (Fraud caught): {cm[1][1]} / {np.sum(labels == 1)}")

    # 3. Save serialized model to backend/data/ml_classifier_model.pkl
    output_model_path = os.path.join(os.path.dirname(__file__), "ml_classifier_model.pkl")
    with open(output_model_path, "wb") as f:
        pickle.dump((vectorizer, model), f)
    print(f"\nSuccessfully serialized and cached model to {output_model_path}")

    # 4. Cross-Dataset Generalization Test (Testing on Laya 538 dataset as completely held-out data!)
    laya_path = os.path.join(os.path.dirname(__file__), "laya_training_corpus.json")
    if os.path.exists(laya_path):
        with open(laya_path, "r", encoding="utf-8") as f:
            laya_samples = json.load(f)
        laya_texts = [s["text"] for s in laya_samples]
        laya_labels = [1 if s["fraud"] >= 0.5 else 0 for s in laya_samples]

        X_laya = vectorizer.transform(laya_texts)
        laya_preds = model.predict(X_laya)

        cross_acc = accuracy_score(laya_labels, laya_preds)
        cross_prec = precision_score(laya_labels, laya_preds)
        cross_rec = recall_score(laya_labels, laya_preds)
        cross_f1 = f1_score(laya_labels, laya_preds)
        cross_cm = confusion_matrix(laya_labels, laya_preds)

        print("\n" + "="*55)
        print(" CROSS-DATASET INDEPENDENT VALIDATION (on 538 Held-Out Samples)")
        print("="*55)
        print(f"  • Cross-Dataset Accuracy:  {cross_acc * 100:.2f}%")
        print(f"  • Cross-Dataset Precision: {cross_prec * 100:.2f}%")
        print(f"  • Cross-Dataset Recall:    {cross_rec * 100:.2f}%")
        print(f"  • Cross-Dataset F1 Score:  {cross_f1 * 100:.2f}%")
        print(f"  • False Positives on Held-Out Benign: {cross_cm[0][1]} / {cross_cm[0][0] + cross_cm[0][1]}")
        print("="*55)

if __name__ == "__main__":
    train_and_evaluate_ml_classifier()
