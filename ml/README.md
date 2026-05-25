# SafeLink-Radar — ML Pipeline

Trains a **RandomForest** phishing-URL classifier in Python,  
exports it to **ONNX**, and loads it in the browser extension via **onnxruntime-web**.

---

## How It Works

```
                        ┌─────────────────────────────────────┐
                        │         PYTHON  (offline)           │
                        │                                     │
  dataset.csv ──────►  features.py  ──►  train.py            │
  (url, label)          (16 features)     RandomForest        │
                                          + StandardScaler    │
                                          ↓                   │
                                     model.onnx  ────────────►│
                                     scaler.json              │
                                     model_meta.json          │
                        └─────────────────────────────────────┘
                                          │
                                          │  copied to dist/ by vite
                                          ▼
                        ┌─────────────────────────────────────┐
                        │       BROWSER EXTENSION (live)      │
                        │                                     │
  URL hover ──────►  urlAnalyzer.ts  ──►  mlModel.ts          │
                        (rule features)    loads model.onnx   │
                             │             runs inference      │
                             │             → mlScore 0-100    │
                             ▼                   │            │
                        riskEngine.ts ◄──────────┘            │
                        blends scores:                        │
                        0.45 × ruleScore + 0.55 × mlScore     │
                             │                                │
                             ▼                                │
                        tooltip / safety panel                │
                        └─────────────────────────────────────┘
```

---

## Files

| File | Purpose |
|------|---------|
| `features.py` | Extracts 16 numeric features from any URL string |
| `generate_dataset.py` | Generates synthetic benign + malicious URL pairs |
| `train.py` | Trains RandomForest, evaluates, exports ONNX + metadata |
| `validate_model.py` | Quick sanity-check on known good/bad URLs |
| `requirements.txt` | Python dependencies |

---

## Quickstart — No Dataset Needed

```bash
# 1. Install Python deps
pip install -r ml/requirements.txt

# 2. Train on auto-generated synthetic data (takes ~30s)
cd ml
python train.py

# 3. Validate the model
python validate_model.py

# 4. Build the extension (copies model.onnx into dist/)
cd ..
npm run build
```

After training you'll find these in `public/`:
- `model.onnx` — the trained model (~200 KB)
- `scaler.json` — feature normalisation parameters
- `model_meta.json` — accuracy / AUC metrics

---

## Training With a Real Dataset (Recommended)

Real datasets make the model **significantly more accurate**.

### Recommended Datasets

| Dataset | Size | Labels | Download |
|---------|------|--------|----------|
| **Kaggle Malicious URLs** ⭐ | 651k rows | benign / phishing / malware / defacement | [kaggle.com/datasets/sid321axn/malicious-urls-dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) |
| **PhishTank** | ~50k | phishing only | [phishtank.com/developer_info.php](https://www.phishtank.com/developer_info.php) |
| **OpenPhish feed** | ~10k | phishing only | `curl https://openphish.com/feed.txt > phish.txt` |
| **ISCX-URL-2016** | 36k | 4 classes | [unb.ca/cic/datasets/url-2016.html](https://www.unb.ca/cic/datasets/url-2016.html) |
| **Tranco top-1M** (benign) | 1M | benign domains | [tranco-list.eu](https://tranco-list.eu/) |

---

### Option 1 — Kaggle Dataset (easiest, best quality)

```bash
# Install Kaggle CLI
pip install kaggle

# Download (requires free Kaggle account + API token at ~/.kaggle/kaggle.json)
kaggle datasets download -d sid321axn/malicious-urls-dataset
unzip malicious-urls-dataset.zip -d ml/

# The CSV has columns: url, type
# 'type' values: benign | phishing | malware | defacement
# train.py auto-maps: phishing/malware/defacement → 1 (malicious), benign → 0
cd ml
python train.py --csv malicious-urls-dataset.csv --url-col url --label-col type
```

---

### Option 2 — PhishTank CSV

```bash
# Download from https://www.phishtank.com/developer_info.php
# Choose "CSV" format, unzip it

cd ml
python train.py --csv verified_online.csv --url-col url --label-col verified
```

---

### Option 3 — OpenPhish (phishing only) + Tranco (benign)

```bash
# Download phishing URLs
curl https://openphish.com/feed.txt -o phish_urls.txt

# Download benign top-1M
curl https://tranco-list.eu/top-1m.csv.zip -o tranco.zip
unzip tranco.zip

# Merge into one CSV (run this helper)
cd ml
python - <<'EOF'
import pandas as pd, random

phish  = pd.read_csv("phish_urls.txt", header=None, names=["url"])
phish["label"] = 1

tranco = pd.read_csv("top-1m.csv", header=None, names=["rank","domain"])
benign = tranco.head(len(phish)).copy()
benign["url"]   = "https://" + benign["domain"]
benign["label"] = 0

df = pd.concat([phish[["url","label"]], benign[["url","label"]]]).sample(frac=1)
df.to_csv("combined_dataset.csv", index=False)
print(f"Saved {len(df)} rows")
EOF

python train.py --csv combined_dataset.csv
```

---

### Option 4 — Any Custom CSV

Your CSV just needs a URL column and a label column.  
Labels can be `0/1`, `benign/malicious`, `phishing/legitimate`, etc. — `train.py` handles it automatically.

```bash
python train.py \
  --csv  /path/to/your_data.csv \
  --url-col   your_url_column_name \
  --label-col your_label_column_name \
  --size 10000   # ignored when using a CSV
```

---

## Training Output

```
📊  5-fold cross-validation…
     CV AUC: 0.9812 ± 0.0031

🏋️   Training final model…

📈  Test Accuracy : 0.9734
    Test AUC      : 0.9891

🔑  Top feature importances:
     entropy                        0.1823  ███████
     url_length                     0.1541  ██████
     brand_squatting                0.1203  █████
     suspicious_keyword_count       0.0981  ████
     has_ip_address                 0.0876  ███
     ...

✅  ONNX model saved → public/model.onnx  (187.3 KB)
✅  Scaler saved      → public/scaler.json
✅  Metadata saved    → public/model_meta.json
```

---

## The 16 Features

```
 0  url_length               — total URL character count
 1  dot_count                — dots in the full URL
 2  subdomain_count          — subdomains beyond www
 3  has_ip_address           — IP used instead of domain name
 4  suspicious_keyword_count — "login","verify","paypal" etc.
 5  suspicious_tld           — .xyz .tk .ml .buzz etc.
 6  has_suspicious_port      — :8080 :3000 :8888 etc.
 7  path_depth               — /a/b/c → depth 3
 8  query_param_count        — ?a=1&b=2 → 2
 9  https                    — 1 if https, 0 if http
10  digit_ratio              — fraction of digits in hostname
11  hyphen_count             — hyphens in hostname
12  at_symbol                — @ in URL (spoofing signal)
13  double_slash_in_path     — //redirect// pattern
14  brand_squatting          — known brand in non-brand domain
15  entropy                  — Shannon entropy of hostname
```

---

## Score Blending in the Extension

```
finalScore = 0.45 × ruleScore + 0.55 × mlScore
```

- **ruleScore** — fast synchronous rule engine (always available)
- **mlScore** — async ONNX inference (available after first load)
- If the model hasn't loaded yet, **falls back to rule-only** seamlessly
