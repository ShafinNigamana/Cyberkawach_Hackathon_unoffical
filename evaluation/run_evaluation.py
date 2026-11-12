"""
Comprehensive Cybersecurity Model Evaluation Suite for CyberKawach.
Senior ML Engineer & Model Evaluation Specialist benchmark.

Evaluates:
- Module 1: ML Baseline (ml_baseline.py)
- Module 2: Scikit-Learn Hybrid Classifier (ml_classifier.py)
- Module 3: Laya Multi-Head Fast Decision Engine (laya.py)
  * Head 1: Binary Fraud Classifier
  * Head 2: Multi-Class Threat Category Classifier (Top-K, Top-1, Top-3, Top-5)
  * Heads 3-6: Continuous Risk Estimators (Ridge Regression)
- Module 4: Deterministic Rules & Hybrid Fusion Pipeline

Computes:
- AUC-ROC & PR-AUC
- Top-K Accuracy
- Training Loss & Validation Loss over iterations
- Convergence Rate & Stability
- Learning Curves (Train/Val vs Dataset Size)
- Precision, Recall, F1, Confusion Matrix, FPR, FNR
- Inference Latency (Mean, Std, P50, P95, P99 in ms)
- Plots: ROC, PR, Confusion Matrices, Loss Convergence, Learning Curves, Latency
"""

import json
import logging
import os
import sys
import time
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression, Ridge, SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    log_loss,
    mean_absolute_error,
    mean_squared_error,
    precision_score,
    r2_score,
    recall_score,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    top_k_accuracy_score,
)
from sklearn.model_selection import StratifiedKFold, learning_curve, train_test_split

# Setup directories
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

EVAL_DIR = BASE_DIR / "evaluation"
PLOTS_DIR = EVAL_DIR / "plots"
PLOTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluator")

# ─────────────────────────────────────────────────────────────
# 1. LOAD DATASETS
# ─────────────────────────────────────────────────────────────
def load_all_datasets():
    logger.info("Loading local datasets...")

    # Dataset A: ML Baseline corpus (loads extended corpus if available)
    from backend.modules.ml_baseline import _load_baseline_corpus
    baseline_corpus = _load_baseline_corpus()
    baseline_texts = [row[0] for row in baseline_corpus]
    baseline_labels = np.array([row[1] for row in baseline_corpus])

    # Dataset B: Laya multi-task corpus
    laya_json = BASE_DIR / "backend" / "data" / "laya_training_corpus.json"
    if laya_json.exists():
        with open(laya_json, "r", encoding="utf-8") as f:
            laya_data = json.load(f)
    else:
        from backend.modules.laya import _CALIBRATION_DATA
        laya_data = [
            {"text": r[0], "fraud": r[1], "category": r[2], "brand_imp": r[3], "cred_req": r[4], "pay_req": r[5], "deep_analysis": r[6]}
            for r in _CALIBRATION_DATA
        ]

    laya_texts = [r["text"] for r in laya_data]
    laya_fraud_labels = np.array([1 if r["fraud"] >= 0.5 else 0 for r in laya_data])
    laya_categories = np.array([r["category"] for r in laya_data])
    laya_continuous = {
        "brand": np.array([r.get("brand_imp", 0.0) for r in laya_data]),
        "credential": np.array([r.get("cred_req", 0.0) for r in laya_data]),
        "payment": np.array([r.get("pay_req", 0.0) for r in laya_data]),
        "deep_analysis": np.array([r.get("deep_analysis", 0.0) for r in laya_data]),
    }

    # Dataset C: ML Classifier corpus
    ml_clf_json = BASE_DIR / "backend" / "data" / "ml_classifier_training_corpus.json"
    if ml_clf_json.exists():
        with open(ml_clf_json, "r", encoding="utf-8") as f:
            ml_data = json.load(f)
    else:
        from backend.modules.ml_classifier import _TRAINING_DATA
        ml_data = [{"text": r[0], "label": r[1]} for r in _TRAINING_DATA]

    ml_texts = [r["text"] for r in ml_data]
    ml_labels = np.array([r["label"] for r in ml_data])

    logger.info("Loaded datasets: Baseline (%d), Laya (%d), ML Classifier (%d)",
                len(baseline_texts), len(laya_texts), len(ml_texts))

    return {
        "baseline": (baseline_texts, baseline_labels),
        "laya": (laya_texts, laya_fraud_labels, laya_categories, laya_continuous),
        "ml_classifier": (ml_texts, ml_labels),
    }


# ─────────────────────────────────────────────────────────────
# 2. BENCHMARK LATENCY
# ─────────────────────────────────────────────────────────────
def benchmark_inference_latency(vectorizer, model, sample_texts, n_iters=500):
    """Accurately measure single-inference execution latency in milliseconds."""
    # Warmup
    for _ in range(20):
        vec = vectorizer.transform([sample_texts[0]])
        if hasattr(model, "predict_proba"):
            _ = model.predict_proba(vec)
        else:
            _ = model.predict(vec)

    latencies_ms = []
    num_samples = len(sample_texts)
    for i in range(n_iters):
        txt = sample_texts[i % num_samples]
        t0 = time.perf_counter_ns()
        vec = vectorizer.transform([txt])
        if hasattr(model, "predict_proba"):
            _ = model.predict_proba(vec)
        else:
            _ = model.predict(vec)
        t1 = time.perf_counter_ns()
        latencies_ms.append((t1 - t0) / 1_000_000.0)

    latencies_ms = np.array(latencies_ms)
    return {
        "mean_ms": float(np.mean(latencies_ms)),
        "std_ms": float(np.std(latencies_ms)),
        "p50_ms": float(np.percentile(latencies_ms, 50)),
        "p95_ms": float(np.percentile(latencies_ms, 95)),
        "p99_ms": float(np.percentile(latencies_ms, 99)),
        "min_ms": float(np.min(latencies_ms)),
        "max_ms": float(np.max(latencies_ms)),
    }


# ─────────────────────────────────────────────────────────────
# 3. TRAINING & VALIDATION LOSS OVER ITERATIONS (CONVERGENCE)
# ─────────────────────────────────────────────────────────────
def compute_loss_convergence(X_train, y_train, X_val, y_val, max_iter=200):
    """
    Measure train loss and val loss across iterations using warm_start Logistic Regression
    to track true empirical convergence rate and overfitting progression.
    """
    train_losses = []
    val_losses = []
    clf = LogisticRegression(C=2.0, warm_start=True, max_iter=1, solver="saga", random_state=42)

    for it in range(1, max_iter + 1):
        clf.max_iter = it
        clf.fit(X_train, y_train)

        prob_train = clf.predict_proba(X_train)
        prob_val = clf.predict_proba(X_val)

        train_loss = log_loss(y_train, prob_train)
        val_loss = log_loss(y_val, prob_val)

        train_losses.append(train_loss)
        val_losses.append(val_loss)

    # Compute convergence rate: iteration where relative loss change < 0.001
    loss_diffs = np.abs(np.diff(train_losses))
    converged_iter = len(train_losses)
    for i, d in enumerate(loss_diffs):
        if d < 1e-4:
            converged_iter = i + 1
            break

    return {
        "train_losses": train_losses,
        "val_losses": val_losses,
        "final_train_loss": train_losses[-1],
        "final_val_loss": val_losses[-1],
        "converged_iteration": converged_iter,
        "iterations_evaluated": max_iter,
    }


# ─────────────────────────────────────────────────────────────
# 4. EVALUATE BINARY CLASSIFIER
# ─────────────────────────────────────────────────────────────
def evaluate_binary_classifier(name, texts, labels, vectorizer_builder, C_param=2.0):
    logger.info("Evaluating Binary Classifier: %s ...", name)

    X_train_txt, X_val_txt, y_train, y_val = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    vectorizer = vectorizer_builder()
    X_train = vectorizer.fit_transform(X_train_txt)
    X_val = vectorizer.transform(X_val_txt)

    # Model training
    model = LogisticRegression(C=C_param, max_iter=500, class_weight="balanced", random_state=42)
    model.fit(X_train, y_train)

    # Inference predictions
    train_preds = model.predict(X_train)
    val_preds = model.predict(X_val)
    val_probs = model.predict_proba(X_val)[:, 1]

    # Metrics
    train_acc = accuracy_score(y_train, train_preds)
    val_acc = accuracy_score(y_val, val_preds)
    val_prec = precision_score(y_val, val_preds, zero_division=0)
    val_rec = recall_score(y_val, val_preds, zero_division=0)
    val_f1 = f1_score(y_val, val_preds, zero_division=0)

    val_auc = roc_auc_score(y_val, val_probs)
    val_pr_auc = average_precision_score(y_val, val_probs)

    cm = confusion_matrix(y_val, val_preds)
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # Convergence Loss Analysis
    loss_stats = compute_loss_convergence(X_train, y_train, X_val, y_val, max_iter=100)

    # Latency
    latency_stats = benchmark_inference_latency(vectorizer, model, texts, n_iters=300)

    # Cross-validation stability (5-Fold)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    X_full = vectorizer.fit_transform(texts)
    cv_accs, cv_f1s, cv_aucs = [], [], []

    for fold_train, fold_val in skf.split(X_full, labels):
        m_fold = LogisticRegression(C=C_param, max_iter=500, class_weight="balanced", random_state=42)
        m_fold.fit(X_full[fold_train], labels[fold_train])
        p_fold = m_fold.predict(X_full[fold_val])
        pr_fold = m_fold.predict_proba(X_full[fold_val])[:, 1]
        cv_accs.append(accuracy_score(labels[fold_val], p_fold))
        cv_f1s.append(f1_score(labels[fold_val], p_fold, zero_division=0))
        cv_aucs.append(roc_auc_score(labels[fold_val], pr_fold))

    # ROC curve points
    fpr_curve, tpr_curve, _ = roc_curve(y_val, val_probs)
    pr_prec, pr_rec, _ = precision_recall_curve(y_val, val_probs)

    # Learning curve
    train_sizes, train_scores, val_scores = learning_curve(
        LogisticRegression(C=C_param, max_iter=500, class_weight="balanced", random_state=42),
        X_full, labels, cv=5, scoring="accuracy",
        train_sizes=np.linspace(0.2, 1.0, 5), random_state=42
    )

    return {
        "name": name,
        "type": "Binary Classification (TF-IDF + LogisticRegression)",
        "train_samples": len(y_train),
        "val_samples": len(y_val),
        "total_samples": len(labels),
        "features_dim": X_train.shape[1],
        "train_accuracy": float(train_acc),
        "val_accuracy": float(val_acc),
        "generalization_gap": float(train_acc - val_acc),
        "precision": float(val_prec),
        "recall": float(val_rec),
        "f1_score": float(val_f1),
        "auc_roc": float(val_auc),
        "pr_auc": float(val_pr_auc),
        "fpr": float(fpr),
        "fnr": float(fnr),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "cv_5fold": {
            "accuracy_mean": float(np.mean(cv_accs)),
            "accuracy_std": float(np.std(cv_accs)),
            "f1_mean": float(np.mean(cv_f1s)),
            "f1_std": float(np.std(cv_f1s)),
            "auc_mean": float(np.mean(cv_aucs)),
            "auc_std": float(np.std(cv_aucs)),
        },
        "convergence": {
            "converged_iteration": loss_stats["converged_iteration"],
            "final_train_loss": float(loss_stats["final_train_loss"]),
            "final_val_loss": float(loss_stats["final_val_loss"]),
            "train_losses": loss_stats["train_losses"],
            "val_losses": loss_stats["val_losses"],
        },
        "latency": latency_stats,
        "roc_curve": {"fpr": fpr_curve.tolist(), "tpr": tpr_curve.tolist()},
        "pr_curve": {"precision": pr_prec.tolist(), "recall": pr_rec.tolist()},
        "learning_curve": {
            "train_sizes": train_sizes.tolist(),
            "train_scores_mean": np.mean(train_scores, axis=1).tolist(),
            "val_scores_mean": np.mean(val_scores, axis=1).tolist(),
        }
    }


# ─────────────────────────────────────────────────────────────
# 5. EVALUATE MULTI-CLASS CATEGORY CLASSIFIER (LAYA HEAD 2)
# ─────────────────────────────────────────────────────────────
def evaluate_laya_multiclass(texts, categories, vectorizer_builder):
    logger.info("Evaluating Multi-Class Threat Category Classifier (Laya Head 2)...")

    X_train_txt, X_val_txt, y_train, y_val = train_test_split(
        texts, categories, test_size=0.20, random_state=42, stratify=categories
    )

    vectorizer = vectorizer_builder()
    X_train = vectorizer.fit_transform(X_train_txt)
    X_val = vectorizer.transform(X_val_txt)

    clf = LogisticRegression(C=2.0, max_iter=500, class_weight="balanced", random_state=42)
    clf.fit(X_train, y_train)

    train_preds = clf.predict(X_train)
    val_preds = clf.predict(X_val)
    val_probs = clf.predict_proba(X_val)

    classes = clf.classes_
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y_val_indices = np.array([class_to_idx[c] for c in y_val])

    # Top-K Accuracies
    top1 = float(accuracy_score(y_val, val_preds))
    top3 = float(top_k_accuracy_score(y_val_indices, val_probs, k=min(3, len(classes))))
    top5 = float(top_k_accuracy_score(y_val_indices, val_probs, k=min(5, len(classes))))

    # Multi-class F1 & Precision / Recall
    macro_prec = float(precision_score(y_val, val_preds, average="macro", zero_division=0))
    macro_rec = float(recall_score(y_val, val_preds, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_val, val_preds, average="macro", zero_division=0))

    weighted_f1 = float(f1_score(y_val, val_preds, average="weighted", zero_division=0))

    # Multi-class ROC AUC (One-vs-Rest)
    try:
        mc_auc = float(roc_auc_score(y_val, val_probs, multi_class="ovr", average="macro"))
    except Exception:
        mc_auc = 0.0

    cm = confusion_matrix(y_val, val_preds, labels=classes)

    latency_stats = benchmark_inference_latency(vectorizer, clf, texts, n_iters=300)

    return {
        "name": "Laya Head 2: Multi-Class Threat Category Classifier",
        "type": "Multi-Class (13 Classes, One-vs-Rest Balanced Logistic Regression)",
        "classes": list(classes),
        "total_classes": len(classes),
        "train_samples": len(y_train),
        "val_samples": len(y_val),
        "top1_accuracy": top1,
        "top3_accuracy": top3,
        "top5_accuracy": top5,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "multiclass_roc_auc": mc_auc,
        "confusion_matrix": cm.tolist(),
        "latency": latency_stats,
    }


# ─────────────────────────────────────────────────────────────
# 6. EVALUATE CONTINUOUS HEADS (LAYA RIDGE REGRESSION HEADS 3-6)
# ─────────────────────────────────────────────────────────────
def evaluate_laya_continuous_heads(texts, continuous_targets, vectorizer_builder):
    logger.info("Evaluating Laya Continuous Heads (Ridge Regression)...")
    vectorizer = vectorizer_builder()
    X = vectorizer.fit_transform(texts)

    results = {}
    for head_name, targets in continuous_targets.items():
        X_train, X_val, y_train, y_val = train_test_split(X, targets, test_size=0.20, random_state=42)
        ridge = Ridge(alpha=3.0)
        ridge.fit(X_train, y_train)
        preds = ridge.predict(X_val)

        mae = float(mean_absolute_error(y_val, preds))
        rmse = float(np.sqrt(mean_squared_error(y_val, preds)))
        r2 = float(r2_score(y_val, preds))

        results[head_name] = {
            "head": f"Laya Head: {head_name}",
            "type": "Ridge Regression (alpha=3.0, Closed-Form Analytical Matrix Solver)",
            "mae": mae,
            "rmse": rmse,
            "r2_score": r2,
            "applicable_metrics_note": (
                "Closed-form analytical normal equation (X^T X + alpha*I)^(-1) X^T y. "
                "No iterative gradient descent epochs; AUC-ROC and top-k are not applicable to continuous real targets."
            ),
        }
    return results


# ─────────────────────────────────────────────────────────────
# 7. GENERATE VISUALIZATIONS
# ─────────────────────────────────────────────────────────────
def generate_all_plots(binary_results, multiclass_res):
    logger.info("Generating evaluation plots in %s...", PLOTS_DIR)

    # 1. ROC Curves
    plt.figure(figsize=(8, 6), dpi=300)
    for res in binary_results:
        fpr = res["roc_curve"]["fpr"]
        tpr = res["roc_curve"]["tpr"]
        auc = res["auc_roc"]
        plt.plot(fpr, tpr, lw=2.2, label=f"{res['name']} (AUC = {auc:.3f})")
    plt.plot([0, 1], [0, 1], color="gray", lw=1.5, linestyle="--", label="Chance (AUC = 0.500)")
    plt.xlim([-0.02, 1.02])
    plt.ylim([-0.02, 1.02])
    plt.xlabel("False Positive Rate (FPR)", fontsize=11, fontweight="bold")
    plt.ylabel("True Positive Rate (TPR / Recall)", fontsize=11, fontweight="bold")
    plt.title("ROC Curves - CyberKawach ML Detection Engines", fontsize=13, fontweight="bold", pad=12)
    plt.legend(loc="lower right", frameon=True, fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "roc_curves.png")
    plt.close()

    # 2. Precision-Recall Curves
    plt.figure(figsize=(8, 6), dpi=300)
    for res in binary_results:
        rec = res["pr_curve"]["recall"]
        prec = res["pr_curve"]["precision"]
        pr_auc = res["pr_auc"]
        plt.plot(rec, prec, lw=2.2, label=f"{res['name']} (PR-AUC = {pr_auc:.3f})")
    plt.xlim([-0.02, 1.02])
    plt.ylim([-0.02, 1.02])
    plt.xlabel("Recall", fontsize=11, fontweight="bold")
    plt.ylabel("Precision", fontsize=11, fontweight="bold")
    plt.title("Precision-Recall Curves - CyberKawach ML Engines", fontsize=13, fontweight="bold", pad=12)
    plt.legend(loc="lower left", frameon=True, fontsize=10)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "pr_curves.png")
    plt.close()

    # 3. Loss & Convergence Curves over Iterations
    plt.figure(figsize=(10, 5), dpi=300)
    colors = ["#1f77b4", "#ff7f0e", "#2ca02c"]
    for i, res in enumerate(binary_results):
        t_loss = res["convergence"]["train_losses"]
        v_loss = res["convergence"]["val_losses"]
        iters = range(1, len(t_loss) + 1)
        plt.plot(iters, t_loss, linestyle="-", color=colors[i], label=f"{res['name']} (Train Loss)")
        plt.plot(iters, v_loss, linestyle="--", color=colors[i], alpha=0.7, label=f"{res['name']} (Val Loss)")
    plt.xlabel("Optimization Iterations / Epochs", fontsize=11, fontweight="bold")
    plt.ylabel("Log-Loss (Binary Cross-Entropy)", fontsize=11, fontweight="bold")
    plt.title("Training Loss vs. Validation Loss (Convergence & Overfitting Analysis)", fontsize=13, fontweight="bold", pad=12)
    plt.legend(frameon=True, fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "loss_convergence_curves.png")
    plt.close()

    # 4. Learning Curves (Performance vs Dataset Size)
    plt.figure(figsize=(10, 5), dpi=300)
    for i, res in enumerate(binary_results):
        sizes = res["learning_curve"]["train_sizes"]
        t_acc = res["learning_curve"]["train_scores_mean"]
        v_acc = res["learning_curve"]["val_scores_mean"]
        plt.plot(sizes, t_acc, marker="o", color=colors[i], label=f"{res['name']} (Train Acc)")
        plt.plot(sizes, v_acc, marker="s", linestyle="--", color=colors[i], label=f"{res['name']} (Val Acc)")
    plt.xlabel("Training Set Size (Samples)", fontsize=11, fontweight="bold")
    plt.ylabel("5-Fold Cross-Validation Accuracy", fontsize=11, fontweight="bold")
    plt.title("Learning Curves: Generalization Performance vs. Dataset Size", fontsize=13, fontweight="bold", pad=12)
    plt.legend(frameon=True, fontsize=9)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "learning_curves.png")
    plt.close()

    # 5. Confusion Matrices (Binary Models)
    fig, axes = plt.subplots(1, len(binary_results), figsize=(5 * len(binary_results), 4), dpi=300)
    if len(binary_results) == 1:
        axes = [axes]
    for ax, res in zip(axes, binary_results):
        cm = np.array([
            [res["confusion_matrix"]["tn"], res["confusion_matrix"]["fp"]],
            [res["confusion_matrix"]["fn"], res["confusion_matrix"]["tp"]]
        ])
        im = ax.imshow(cm, cmap="Blues", interpolation="nearest")
        ax.set_title(f"{res['name']}\n(Total Val: {cm.sum()})", fontsize=11, fontweight="bold")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Benign", "Fraud"], fontweight="bold")
        ax.set_yticklabels(["Benign", "Fraud"], fontweight="bold")
        ax.set_xlabel("Predicted Label", fontweight="bold")
        ax.set_ylabel("True Label", fontweight="bold")
        for r in range(2):
            for c in range(2):
                val = cm[r, c]
                color = "white" if val > cm.max() / 2 else "black"
                ax.text(c, r, f"{val}", ha="center", va="center", color=color, fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "confusion_matrices.png")
    plt.close()

    # 6. Multi-class Confusion Matrix for Laya Head 2
    cm_mc = np.array(multiclass_res["confusion_matrix"])
    classes = multiclass_res["classes"]
    plt.figure(figsize=(10, 8), dpi=300)
    plt.imshow(cm_mc, cmap="Purples", interpolation="nearest")
    plt.title("Multi-Class Threat Category Confusion Matrix (Laya Head 2)", fontsize=13, fontweight="bold", pad=12)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45, ha="right", fontsize=9)
    plt.yticks(tick_marks, classes, fontsize=9)
    for i in range(len(classes)):
        for j in range(len(classes)):
            v = cm_mc[i, j]
            color = "white" if v > cm_mc.max() / 2 else "black"
            if v > 0:
                plt.text(j, i, f"{v}", ha="center", va="center", color=color, fontsize=8)
    plt.xlabel("Predicted Category", fontsize=11, fontweight="bold")
    plt.ylabel("True Category", fontsize=11, fontweight="bold")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "multiclass_confusion_matrix.png")
    plt.close()

    # 7. Latency Benchmark Comparison
    all_models = [b["name"] for b in binary_results] + [multiclass_res["name"]]
    p50s = [b["latency"]["p50_ms"] for b in binary_results] + [multiclass_res["latency"]["p50_ms"]]
    p95s = [b["latency"]["p95_ms"] for b in binary_results] + [multiclass_res["latency"]["p95_ms"]]

    x = np.arange(len(all_models))
    width = 0.35
    plt.figure(figsize=(10, 5), dpi=300)
    plt.bar(x - width/2, p50s, width, label="P50 Latency (Median)", color="#2ca02c")
    plt.bar(x + width/2, p95s, width, label="P95 Latency (95th percentile)", color="#d62728")
    plt.xticks(x, [m.replace("Classifier", "Clf").replace("Engine", "Eng") for m in all_models], rotation=15, ha="right", fontsize=9)
    plt.ylabel("Latency (milliseconds / inference)", fontsize=11, fontweight="bold")
    plt.title("Inference Latency Benchmark across ML Detection Engines", fontsize=13, fontweight="bold", pad=12)
    plt.legend(frameon=True)
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "latency_benchmark.png")
    plt.close()

    logger.info("All visualization plots generated successfully in %s", PLOTS_DIR)


# ─────────────────────────────────────────────────────────────
# 8. MASTER EVALUATION RUNNER
# ─────────────────────────────────────────────────────────────
def main():
    logger.info("Starting Senior ML Engineer Evaluation of CyberKawach...")
    datasets = load_all_datasets()

    # 1. Evaluate Module 1: ML Baseline
    def build_baseline_vec():
        return TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=250,
            lowercase=True,
            sublinear_tf=True,
            stop_words="english"
        )
    baseline_res = evaluate_binary_classifier(
        "ML Baseline (ml_baseline.py)",
        datasets["baseline"][0],
        datasets["baseline"][1],
        build_baseline_vec,
        C_param=1.0
    )

    # 2. Evaluate Module 2: Scikit-Learn ML Classifier
    def build_ml_clf_vec():
        return TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=400,
            min_df=2,
            sublinear_tf=True,
            lowercase=True,
            token_pattern=r"(?u)\b\w+\b|https?://\S+",
        )
    ml_clf_res = evaluate_binary_classifier(
        "Scikit-Learn ML Classifier (ml_classifier.py)",
        datasets["ml_classifier"][0],
        datasets["ml_classifier"][1],
        build_ml_clf_vec,
        C_param=2.0
    )

    # 3. Evaluate Module 3: Laya Head 1 (Binary Fraud)
    def build_laya_vec():
        return TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=350,
            min_df=2,
            sublinear_tf=True,
            lowercase=True,
            stop_words="english",
        )
    laya_fraud_res = evaluate_binary_classifier(
        "Laya Head 1: Fraud Classifier (laya.py)",
        datasets["laya"][0],
        datasets["laya"][1],
        build_laya_vec,
        C_param=2.0
    )

    # 4. Evaluate Module 3: Laya Head 2 (Multi-Class Category)
    laya_multiclass_res = evaluate_laya_multiclass(
        datasets["laya"][0],
        datasets["laya"][2],
        build_laya_vec
    )

    # 5. Evaluate Module 3: Laya Continuous Risk Heads 3-6
    laya_continuous_res = evaluate_laya_continuous_heads(
        datasets["laya"][0],
        datasets["laya"][3],
        build_laya_vec
    )

    # 6. Generate All Plots
    binary_results = [baseline_res, ml_clf_res, laya_fraud_res]
    generate_all_plots(binary_results, laya_multiclass_res)

    # 7. Save Clean JSON Metrics Summary (stripping bulky curves)
    summary_json = {
        "evaluation_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary_classifiers": [
            {k: v for k, v in res.items() if k not in ("roc_curve", "pr_curve", "convergence", "learning_curve")}
            for res in binary_results
        ],
        "multiclass_classifier": {
            k: v for k, v in laya_multiclass_res.items() if k != "confusion_matrix"
        },
        "continuous_heads": laya_continuous_res,
        "convergence_and_loss": {
            res["name"]: {
                "converged_iteration": res["convergence"]["converged_iteration"],
                "final_train_loss": res["convergence"]["final_train_loss"],
                "final_val_loss": res["convergence"]["final_val_loss"],
                "generalization_gap": res["generalization_gap"],
            }
            for res in binary_results
        }
    }

    metrics_file = EVAL_DIR / "metrics_summary.json"
    with open(metrics_file, "w", encoding="utf-8") as f:
        json.dump(summary_json, f, indent=2)

    logger.info("Saved structured metrics to %s", metrics_file)
    logger.info("Evaluation complete!")

if __name__ == "__main__":
    main()

