# SPDX-License-Identifier: MIT
# Copyright (c) 2026 chethanakash67
"""
Quick sanity-check script: loads model.onnx and runs inference on
a handful of known-benign and known-malicious URLs.

Usage:
    python validate_model.py
"""

import sys
import json
from pathlib import Path

try:
    import numpy as np
    import onnxruntime as ort
except ImportError:
    print("❌  Run: pip install -r requirements.txt")
    sys.exit(1)

from features import extract_features

# ---------------------------------------------------------------------------
ROOT   = Path(__file__).parent.parent
PUBLIC = ROOT / "public"

ONNX_PATH = PUBLIC / "model.onnx"
META_PATH = PUBLIC / "model_meta.json"

# ---------------------------------------------------------------------------
TEST_URLS = [
    # (url, expected_label)  1 = malicious, 0 = benign
    ("https://www.google.com/search?q=python",        0),
    ("https://github.com/chethanakash67",              0),
    ("https://www.amazon.com/dp/B08N5WRWNW",           0),
    ("http://192.168.1.1/login?token=abc123",          1),
    ("http://paypal-secure.xyz/signin",                1),
    ("http://amazon.verify-account.tk/update",         1),
    ("http://10.0.0.1/banking/confirm?redirect=xyz",   1),
    ("http://paypal.com.suspicious.ml/login",          1),
    ("https://stackoverflow.com/questions/tagged/ml",  0),
    ("http://free-prize-winner.buzz/claim?id=abc",     1),
]


def run_validation() -> None:
    if not ONNX_PATH.exists():
        print(f"❌  {ONNX_PATH} not found — run train.py first")
        sys.exit(1)

    # Load metadata
    meta = {}
    if META_PATH.exists():
        with open(META_PATH) as f:
            meta = json.load(f)
        print(f"📋  Model metadata:")
        print(f"    Accuracy : {meta.get('test_accuracy', 'n/a')}")
        print(f"    AUC      : {meta.get('test_auc', 'n/a')}")
        print(f"    CV AUC   : {meta.get('cv_auc_mean', 'n/a')} ± {meta.get('cv_auc_std', 'n/a')}")
        print()

    sess = ort.InferenceSession(str(ONNX_PATH))
    input_name  = sess.get_inputs()[0].name
    output_name = sess.get_outputs()[1].name  # probabilities

    print(f"{'URL':<55} {'PRED':>8}  {'PROB%':>6}  {'EXPECTED':>9}  STATUS")
    print("-" * 95)

    correct = 0
    for url, expected in TEST_URLS:
        feat = np.array([extract_features(url)], dtype=np.float32)
        proba = sess.run([output_name], {input_name: feat})[0][0]   # shape (2,)
        malicious_prob = float(proba[1]) * 100
        pred = 1 if malicious_prob >= 50 else 0
        status = "✅" if pred == expected else "❌"
        label  = "malicious" if pred == 1 else "benign"
        if pred == expected:
            correct += 1
        display_url = url[:53] + ".." if len(url) > 55 else url
        print(f"{display_url:<55} {label:>9}  {malicious_prob:5.1f}%  "
              f"{'malicious' if expected else 'benign':>9}  {status}")

    print("-" * 95)
    print(f"\nSample accuracy: {correct}/{len(TEST_URLS)} ({correct/len(TEST_URLS)*100:.0f}%)")


if __name__ == "__main__":
    run_validation()
