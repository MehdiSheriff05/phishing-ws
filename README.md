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
