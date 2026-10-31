"""
NetGuard AI - Phase 1: train an intrusion detection model on CIC-IDS2017.

Steps:
  1. Load every CSV in the dataset folder
  2. Clean it (column names, inf, NaN, duplicates, constant columns)
  3. Group attack labels into 6 families
  4. Train a Random Forest and evaluate it (Precision / Recall / F1 / FPR)
  5. Save the model, confusion matrix, feature importance and a report

Usage:
  python train_ids.py --data MachineLearningCVE
  python train_ids.py --data MachineLearningCVE --sample 0.3   # faster (30% of rows)
"""
import argparse
import glob
import json
import os
import time

import joblib
import matplotlib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# Group the many CIC-IDS2017 labels into clear attack families
GROUPS = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS", "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Bot": "Other", "Infiltration": "Other", "Heartbleed": "Other",
}


def group_label(lbl: str) -> str:
    lbl = str(lbl).strip()
    if lbl in GROUPS:
        return GROUPS[lbl]
    if "Web Attack" in lbl:
        return "WebAttack"
    return "Other"


def load(folder: str, sample: float) -> pd.DataFrame:
    files = sorted(glob.glob(os.path.join(folder, "**", "*.csv"), recursive=True))
    if not files:
        raise SystemExit(f"❌ No CSV files found in: {folder}")
    parts = []
    for f in files:
        df = pd.read_csv(f, low_memory=False, encoding="latin-1")
        df.columns = df.columns.str.strip()
        if sample < 1:
            df = df.sample(frac=sample, random_state=42)
        parts.append(df)
        print(f"  ✓ {os.path.basename(f)}: {len(df):,} rows")
    return pd.concat(parts, ignore_index=True)


def clean(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    before = len(df)
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    df = df.drop_duplicates()
    y = df.pop("Label").map(group_label)
    # drop constant columns (no information for the model)
    X = df.select_dtypes(include="number")
    X = X.loc[:, X.nunique() > 1].astype("float32")
    print(f"🧹 After cleaning: {len(X):,} rows (removed {before - len(X):,}) | {X.shape[1]} features")
    return X, y


def plot_confusion(cm, labels, path):
    cm_norm = cm / cm.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(8, 6.5))
    im = ax.imshow(cm_norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=45, ha="right")
    ax.set_yticks(range(len(labels)), labels)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm_norm[i, j]:.2f}\n({cm[i, j]:,})", ha="center", va="center",
                    fontsize=8, color="white" if cm_norm[i, j] > 0.5 else "black")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("NetGuard AI - Confusion Matrix (row-normalized)")
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_importance(model, cols, path, top=15):
    imp = pd.Series(model.feature_importances_, index=cols).sort_values().tail(top)
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.barh(imp.index, imp.values, color="#2563eb")
    ax.set_title(f"Top {top} features")
    ax.set_xlabel("Importance")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return imp.sort_values(ascending=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="folder with the CIC-IDS2017 CSV files")
    ap.add_argument("--sample", type=float, default=1.0, help="fraction of rows to use (0.3 = faster)")
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    print("📂 Loading data...")
    X, y = clean(load(a.data, a.sample))
    print("\n📊 Class distribution:")
    print(y.value_counts().to_string())

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    print("\n🌲 Training Random Forest...")
    t = time.time()
    model = RandomForestClassifier(
        n_estimators=100, n_jobs=-1, random_state=42,
        class_weight="balanced_subsample",  # so rare attacks are not ignored
    )
    model.fit(X_tr, y_tr)
    print(f"   done in {time.time() - t:.0f} s")

    pred = model.predict(X_te)
    labels = sorted(y.unique(), key=lambda s: (s != "Normal", s))
    report = classification_report(y_te, pred, labels=labels, digits=4, zero_division=0)
    print("\n" + report)

    cm = confusion_matrix(y_te, pred, labels=labels)
    # False Positive Rate: normal traffic wrongly flagged (the key IDS metric)
    n = labels.index("Normal")
    fpr = 1 - cm[n, n] / cm[n].sum()
    # Detection Rate: attacks flagged as any attack class
    attack_rows = [i for i in range(len(labels)) if i != n]
    detected = sum(cm[i].sum() - cm[i, n] for i in attack_rows)
    dr = detected / sum(cm[i].sum() for i in attack_rows)
    print(f"🎯 Detection Rate: {dr:.4%}   |   ⚠️ False Positive Rate: {fpr:.4%}")

    plot_confusion(cm, labels, os.path.join(a.out, "confusion_matrix.png"))
    top = plot_importance(model, X.columns, os.path.join(a.out, "feature_importance.png"))
    joblib.dump({"model": model, "features": list(X.columns), "labels": labels},
                os.path.join(a.out, "netguard_rf.joblib"), compress=3)
    with open(os.path.join(a.out, "report.txt"), "w", encoding="utf-8") as fh:
        fh.write(report + f"\nDetection Rate: {dr:.4%}\nFalse Positive Rate: {fpr:.4%}\n")
        fh.write("\nTop features:\n" + top.to_string())
    with open(os.path.join(a.out, "metrics.json"), "w") as fh:
        json.dump({"detection_rate": dr, "false_positive_rate": fpr, "test_rows": int(len(y_te))}, fh, indent=2)
    print(f"\n✅ Results saved to {a.out}/")


if __name__ == "__main__":
    main()
