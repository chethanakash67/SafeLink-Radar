# SPDX-License-Identifier: MIT
# Copyright (c) 2026 chethanakash67
"""
Train a RandomForest classifier on URL features and export to ONNX.

Steps:
  1. Generate (or load) dataset
  2. Extract 16-dim feature vectors
  3. Train RandomForest with cross-validation
  4. Evaluate on held-out test set
  5. Export model to ONNX  →  ../public/model.onnx
  6. Export feature scaler →  ../public/scaler.json
  7. Export model metadata →  ../public/model_meta.json

Usage:
    python train.py                     # generate fresh data + train
    python train.py --csv dataset.csv   # use existing CSV
    python train.py --csv dataset.csv --no-scale   # skip StandardScaler
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import (
        classification_report, confusion_matrix,
        roc_auc_score, accuracy_score
    )
    from sklearn.pipeline import Pipeline
    import skl2onnx
    from skl2onnx import convert_sklearn
    from skl2onnx.common.data_types import FloatTensorType
except ImportError as e:
    print(f"\n❌  Missing dependency: {e}")
    print("   Run:  pip install -r requirements.txt")
    sys.exit(1)

from features import extract_features, FEATURE_NAMES
from generate_dataset import generate_dataset, save_csv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ML_DIR   = Path(__file__).parent
ROOT_DIR = ML_DIR.parent
PUBLIC_DIR = ROOT_DIR / "public"
PUBLIC_DIR.mkdir(exist_ok=True)

ONNX_PATH   = PUBLIC_DIR / "model.onnx"
SCALER_PATH = PUBLIC_DIR / "scaler.json"
META_PATH   = PUBLIC_DIR / "model_meta.json"


# ---------------------------------------------------------------------------
# Dataset loading
# ---------------------------------------------------------------------------

def load_or_generate(
    csv_path: Optional[Path],
    n_each: int = 8000,
    url_col: str = "url",
    label_col: str = "label",
) -> pd.DataFrame:
    if csv_path and csv_path.exists():
        print(f"📂  Loading dataset from {csv_path}")
        df = pd.read_csv(csv_path)

        # Rename user-specified columns to standard names
        if url_col in df.columns and url_col != "url":
            df = df.rename(columns={url_col: "url"})
        if label_col in df.columns and label_col != "label":
            df = df.rename(columns={label_col: "label"})

        # Fallback: auto-detect by common aliases if still missing
        cols = df.columns.tolist()
        if "url" not in cols:
            for alias in ["URL", "link", "domain", "address"]:
                if alias in cols:
                    df = df.rename(columns={alias: "url"})
                    break
        if "label" not in cols:
            for alias in ["Label", "class", "type", "target",
                          "malicious", "phishing", "is_phishing", "category"]:
                if alias in cols:
                    df = df.rename(columns={alias: "label"})
                    break

        if "url" not in df.columns or "label" not in df.columns:
            raise ValueError(
                f"CSV must have 'url' and 'label' columns.\n"
                f"Found columns: {cols}\n"
                f"Use --url-col and --label-col to specify column names."
            )

        # Normalise labels: accept 0/1, "benign"/"malicious", "phishing"/"legitimate" etc.
        if df["label"].dtype == object:
            MALICIOUS_VALUES = {"1", "malicious", "phishing", "bad", "spam",
                                "defacement", "malware", "true"}
            df["label"] = df["label"].apply(
                lambda x: 1 if str(x).strip().lower() in MALICIOUS_VALUES else 0
            )
        else:
            df["label"] = df["label"].astype(int).clip(0, 1)

        # Drop rows with missing URLs
        df = df.dropna(subset=["url"])
        df["url"] = df["url"].astype(str).str.strip()
        df = df[df["url"].str.len() > 4]

        print(f"     Loaded {len(df)} rows  |  "
              f"benign={int((df['label']==0).sum())}  "
              f"malicious={int((df['label']==1).sum())}")
    else:
        print(f"🔨  Generating synthetic dataset ({n_each} samples/class)…")
        rows = generate_dataset(n_each=n_each)
        csv_out = ML_DIR / "dataset.csv"
        save_csv(rows, csv_out)
        df = pd.DataFrame(rows, columns=["url", "label"])
    return df


def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    print("⚙️   Extracting features…")
    X = np.array([extract_features(url) for url in df["url"]], dtype=np.float32)
    y = df["label"].values.astype(np.int64)
    print(f"     Feature matrix: {X.shape}  |  classes: {np.bincount(y)}")
    return X, y


# ---------------------------------------------------------------------------
# Scaler helpers
# ---------------------------------------------------------------------------

def scaler_to_json(scaler: StandardScaler) -> dict:
    return {
        "mean": scaler.mean_.tolist(),
        "scale": scaler.scale_.tolist(),
        "feature_names": FEATURE_NAMES,
    }


# ---------------------------------------------------------------------------
# ONNX export
# ---------------------------------------------------------------------------

def export_onnx(pipeline: Pipeline, n_features: int, path: Path) -> None:
    initial_type = [("float_input", FloatTensorType([None, n_features]))]
    onnx_model = convert_sklearn(
        pipeline,
        initial_types=initial_type,
        target_opset=17,
        options={RandomForestClassifier: {"zipmap": False}},
    )
    with open(path, "wb") as f:
        f.write(onnx_model.SerializeToString())
    size_kb = path.stat().st_size / 1024
    print(f"✅  ONNX model saved → {path}  ({size_kb:.1f} KB)")


# ---------------------------------------------------------------------------
# Main training routine
# ---------------------------------------------------------------------------

def train(args: argparse.Namespace) -> None:
    # 1. Data
    csv_path = Path(args.csv) if args.csv else None
    df = load_or_generate(
        csv_path,
        n_each=args.size,
        url_col=args.url_col,
        label_col=args.label_col,
    )
    X, y = build_feature_matrix(df)

    # 2. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Build pipeline
    steps = []
    if not args.no_scale:
        steps.append(("scaler", StandardScaler()))

    rf = RandomForestClassifier(
        n_estimators=100,       # fewer trees → smaller model.onnx (~2 MB)
        max_depth=8,            # shallower → less overfitting, better generalisation
        min_samples_split=20,   # require more samples to split → smoother boundaries
        min_samples_leaf=10,    # minimum leaf size → reduces noise
        max_features="sqrt",    # only sqrt(n_features) per split
        class_weight="balanced",# compensate for 66% benign / 34% malicious imbalance
        random_state=42,
        n_jobs=-1,
    )
    steps.append(("clf", rf))
    pipeline = Pipeline(steps)

    # 4. Cross-validation
    print("\n📊  5-fold cross-validation…")
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=cv,
                                scoring="roc_auc", n_jobs=-1)
    print(f"     CV AUC: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

    # 5. Final fit
    print("\n🏋️   Training final model…")
    pipeline.fit(X_train, y_train)

    # 6. Evaluate
    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    acc  = accuracy_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)

    print(f"\n📈  Test Accuracy : {acc:.4f}")
    print(f"    Test AUC      : {auc:.4f}")
    print(f"    Confusion Matrix:\n{cm}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['benign','malicious'])}")

    # 7. Feature importances
    clf_step = pipeline.named_steps["clf"]
    importances = sorted(
        zip(FEATURE_NAMES, clf_step.feature_importances_),
        key=lambda x: x[1], reverse=True
    )
    print("🔑  Top feature importances:")
    for name, imp in importances[:10]:
        bar = "█" * int(imp * 40)
        print(f"     {name:<30} {imp:.4f}  {bar}")

    # 8. Export ONNX
    print("\n📦  Exporting ONNX model…")
    export_onnx(pipeline, X.shape[1], ONNX_PATH)

    # 9. Export scaler JSON (for TS-side normalisation if needed)
    if not args.no_scale:
        scaler = pipeline.named_steps["scaler"]
        with open(SCALER_PATH, "w") as f:
            json.dump(scaler_to_json(scaler), f, indent=2)
        print(f"✅  Scaler saved      → {SCALER_PATH}")

    # 10. Export metadata
    meta = {
        "feature_names": FEATURE_NAMES,
        "n_features": len(FEATURE_NAMES),
        "n_estimators": rf.n_estimators,
        "max_depth": rf.max_depth,
        "test_accuracy": round(float(acc), 4),
        "test_auc": round(float(auc), 4),
        "cv_auc_mean": round(float(cv_scores.mean()), 4),
        "cv_auc_std": round(float(cv_scores.std()), 4),
        "classes": ["benign", "malicious"],
        "output_index_malicious": 1,
        "model_file": "model.onnx",
        "scaler_file": "scaler.json" if not args.no_scale else None,
        "trained_on": str(pd.Timestamp.now()),
    }
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"✅  Metadata saved    → {META_PATH}")

    print("\n🎉  Done! Files ready in public/:")
    print(f"      model.onnx  ({ONNX_PATH.stat().st_size / 1024:.1f} KB)")
    if not args.no_scale:
        print(f"      scaler.json ({SCALER_PATH.stat().st_size / 1024:.1f} KB)")
    print(f"      model_meta.json")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Train phishing-URL classifier and export to ONNX"
    )
    parser.add_argument("--csv",       default=None,
                        help="Path to existing dataset CSV")
    parser.add_argument("--url-col",   default="url",
                        help="Name of the URL column in your CSV (default: 'url')")
    parser.add_argument("--label-col", default="label",
                        help="Name of the label column in your CSV (default: 'label')")
    parser.add_argument("--size",      type=int, default=8000,
                        help="Samples per class when generating data (default 8000)")
    parser.add_argument("--no-scale",  action="store_true",
                        help="Skip StandardScaler in pipeline")
    train(parser.parse_args())
