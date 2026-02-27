# Phishing Warning Prototype (Flask + Chrome Extension)

Hybrid phishing detection prototype with:
- Flask backend API for analysis
- Rule-based checks for URL/sender/attachments
- Heuristic NLP module with pluggable Transformers interface
- Chrome Manifest V3 extension UI

## Project structure

```text
.
├── app.py
├── config.py
├── requirements.txt
├── .env.example
├── routes/
│   └── analyze.py
├── services/
│   ├── preprocess.py
│   ├── url_checks.py
│   ├── sender_checks.py
│   ├── attachment_checks.py
│   ├── model_inference.py
│   └── risk_scoring.py
├── models/
│   └── schemas.py
├── utils/
│   └── logger.py
├── extension/
│   ├── manifest.json
│   ├── background.js
│   ├── content.js
│   ├── popup.html
│   ├── popup.css
│   ├── popup.js
│   └── README.md
├── tests/
│   ├── test_url_checks.py
│   ├── test_attachment_checks.py
│   └── test_risk_scoring.py
├── samples/
│   ├── request.json
│   └── response_example.json
├── evaluation.py
├── data/
│   ├── raw/
│   └── processed/
└── notebooks/
```

## Backend setup

1. Create virtual env and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Configure env vars (optional):

```bash
cp .env.example .env
```

Set `ENABLE_TRANSFORMER=true` only when your runtime supports tokenizer/model loading.

3. Run backend:

```bash
python app.py
```

4. Health check:

```bash
curl http://127.0.0.1:5000/health
```

Expected:

```json
{"status":"ok"}
```

## API usage

### Endpoint
- `POST /analyze-email`

### Request example

```bash
curl -X POST http://127.0.0.1:5000/analyze-email \
  -H "Content-Type: application/json" \
  -d @samples/request.json
```

### Response shape

```json
{
  "risk_score": 0,
  "risk_level": "low",
  "reasons": ["..."],
  "indicators": {
    "text": 0,
    "url": 0,
    "sender": 0,
    "attachment": 0
  },
  "recommended_action": "..."
}
```

## Extension setup (Chrome)

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `extension/` folder
5. Open Gmail email thread and click extension popup
6. Confirm **Backend API base URL** (default: `http://127.0.0.1:5000`)
7. Extension auto-analyzes each newly opened email/page
8. Optional: click **Analyze current email** for manual re-check

Notes:
- Extension supports `http://127.0.0.1:5000` and `http://localhost:5000` fallback
- Popup includes local allow-list and blocklist storage for sender domains
- Extension badge shows `LOW`, `MED`, or `HIGH` based on the latest auto-analysis
- Works on Gmail and regular webpages (non-email pages use webpage context extraction)
- Shows Chrome notifications for regular webpages when risk is `medium` or `high`

## Tests

Run unit tests:

```bash
pytest -q
```

## Evaluation scaffold

For future model evaluation:

```bash
python evaluation.py --csv path/to/preds.csv
```

CSV columns required: `y_true,y_pred`

## GitHub test set workflow

This project now includes a GitHub-sourced phishing URL feed in:
- `data/raw/phishing_links_active.txt`

Build a local URL test set:

```bash
python scripts/build_testset_from_github.py
```

Run URL checks over that set and generate predictions:

```bash
python scripts/score_url_testset.py
```

Evaluate:

```bash
python evaluation.py --csv data/processed/github_eval_predictions.csv
```

Notes:
- `data/processed/github_url_testset.csv` has `url,y_true`
- `data/processed/github_eval_predictions.csv` has `url,y_true,y_pred,url_score`
- Default score threshold in `scripts/score_url_testset.py` is `40.0` (you should tune this based on your latest URL scoring logic)

## Implementation notes

- Prototype is deterministic and works without a trained model.
- `services/model_inference.py` uses heuristic scoring now.
- Transformer tokenization path is opt-in via `ENABLE_TRANSFORMER=true`.
- TODO markers indicate where to load a fine-tuned BERT checkpoint.
- TODO future improvements:
  - Add domain reputation APIs
  - Add sandboxed attachment analysis
  - Replace heuristics with calibrated fine-tuned model

## Email CSV format for training

Use this CSV schema for email model training:

`sender_email,sender_name,subject,body_text,urls,attachments,label`

- `urls`: semicolon-delimited list or plain string
- `attachments`: plain string summary (or filenames list)
- `label`: `1` phishing, `0` legitimate

Sample file:
- `samples/email_training_format.csv`

## Train BERT (NLP model)

```bash
python scripts/train_bert_email.py \
  --csv samples/email_training_format.csv \
  --model-name distilbert-base-uncased \
  --output-dir models/checkpoints/email-bert \
  --epochs 2
```

After training, activate model-backed NLP in backend:

1. Set env:
   - `ENABLE_TRANSFORMER=true`
   - `MODEL_PATH=models/checkpoints/email-bert`
2. Restart Flask (`python app.py`)

`services/model_inference.py` will then run transformer inference, with heuristic fallback if model load fails.

## Train classical ML baseline

```bash
python scripts/train_email_ml.py --csv samples/email_training_format.csv
```

This produces baseline metrics at:
- `models/checkpoints/email-ml-metrics.json`

## Import `phishing_pot` dataset and train

1. Clone dataset repo:

```bash
git clone --depth 1 https://github.com/rf-peixoto/phishing_pot.git /tmp/phishing_pot
```

2. Convert `.eml` samples into training CSV format (with synthetic benign class for balance):

```bash
python scripts/import_phishing_pot_dataset.py \
  --eml-dir /tmp/phishing_pot/email \
  --out data/processed/phishing_pot_email_training.csv \
  --limit 2500 \
  --benign-ratio 1.0
```

3. Train classical ML baseline:

```bash
python scripts/train_email_ml.py \
  --csv data/processed/phishing_pot_email_training.csv \
  --output models/checkpoints/phishing_pot_email_ml_metrics.json
```

4. (Optional fast run) Build a smaller BERT training subset:

```bash
python - <<'PY'
import pandas as pd
df = pd.read_csv("data/processed/phishing_pot_email_training.csv")
small = pd.concat([df[df.label==1].head(300), df[df.label==0].head(300)]).sample(frac=1, random_state=42)
small.to_csv("data/processed/phishing_pot_email_training_small.csv", index=False)
PY
```

5. Train BERT checkpoint:

```bash
python scripts/train_bert_email.py \
  --csv data/processed/phishing_pot_email_training_small.csv \
  --model-name distilbert-base-uncased \
  --output-dir models/checkpoints/phishing_pot_email_bert \
  --epochs 1 \
  --batch-size 8
```

6. Activate model-backed NLP in app:
- `ENABLE_TRANSFORMER=true`
- `MODEL_PATH=models/checkpoints/phishing_pot_email_bert`
- restart Flask (`python app.py`)
