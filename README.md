# Undergraduate Phishing Email Detection System

This project includes:
- `backend/`: FastAPI service for prediction, evaluation logging, feedback, and model training
- `extension/`: Chrome Extension (Manifest V3) that extracts visible text and links, then calls the FastAPI `/predict` endpoint

The system works in two phases:
- pretraining mode: heuristic-only phishing detection, with no trained model loaded
- trained mode: TF-IDF + Logistic Regression prediction, while still returning explanation flags

The training workflow is designed to avoid data leakage:
- training uses a balanced set of `900 phishing + 900 non-phishing` emails
- emails already used in `test_data/` are excluded from the training pool

## Project Structure

```
phishing/
├── backend/
│   ├── app/
│   │   ├── feedback.py
│   │   ├── flags.py
│   │   ├── evaluation.py
│   │   ├── main.py
│   │   ├── model_io.py
│   │   ├── reputation.py
│   │   └── schemas.py
│   ├── artifacts/                # Saved model + metrics generated after training
│   │   └── reputation/
│   │       ├── trusted_domains.txt
│   │       └── flagged_domains.txt
│   ├── evaluate_test_data.py
│   ├── prepare_test_data.py
│   ├── train.py
│   ├── Dockerfile
│   └── .dockerignore
├── extension/
│   ├── manifest.json
│   ├── content.js
│   ├── service_worker.js
│   ├── icon128.png
│   ├── popup.html
│   ├── popup.js
│   ├── options.html
│   └── options.js
├── requirements.txt
└── README.md
```

## 1) Python Virtual Environment (Required)

All backend development should run inside a venv.

### Create venv

```bash
cd /Users/mehdisheriff/Desktop/phishing
python3 -m venv .venv
```

### Activate venv

macOS/Linux:
```bash
source .venv/bin/activate
```

Windows (PowerShell):
```powershell
.venv\Scripts\Activate.ps1
```

### Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Deactivate when done

```bash
deactivate
```

## 2) Train the Model

Make sure your venv is active, then run:

```bash
python backend/train.py
```

What this does:
- Downloads Kaggle dataset `naserabdullahalam/phishing-email-dataset` using `kagglehub`
- excludes emails already present in `test_data/` so training does not reuse your evaluation emails
- samples a balanced training pool of `900 phishing + 900 non-phishing` by default
- trains TF-IDF + Logistic Regression
- Computes and saves metrics:
  - precision
  - recall
  - F1
  - confusion matrix
  - PR-AUC
- Saves artifacts to `backend/artifacts/`:
  - `vectorizer.joblib`
  - `classifier.joblib`
  - `metrics.json`
  - `confusion_matrix.csv`

Useful training options:

```bash
python backend/train.py --samples-per-class 900
python backend/train.py --samples-per-class 900 --allow-synthetic-non-phishing
python backend/train.py --samples-per-class 900 --include-feedback
```

Notes:
- default behavior is now aligned with evaluation safety: test emails in `test_data/` are excluded from training
- if the Kaggle source does not contain enough non-phishing emails, training will stop with an error unless you add `--allow-synthetic-non-phishing`
- `--include-feedback` is optional and off by default
- `metrics.json` records how many test-overlap rows were excluded

## 3) Pre-Training vs Trained Mode (for documentation)

You can run the system in two phases:

### Phase A: Pre-training (no artifacts yet)

Start backend before running training:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

In this phase:
- `/health` returns `"model_loaded": false`
- `/predict` still works using heuristic flags only (baseline behavior)
- response includes a flag: `Model artifacts not loaded; returning heuristic-only estimate.`

This is useful to document system behavior before model training.

### Phase B: Trained mode

Run training:

```bash
python backend/train.py
```

Restart backend:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Now:
- `/health` returns `"model_loaded": true`
- `/predict` uses TF-IDF + Logistic Regression probabilities

## 4) Run Backend Locally

With venv active and model artifacts present:

```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Optional: enable Google Safe Browsing reputation checks:

```bash
export GOOGLE_SAFE_BROWSING_API_KEY="your_api_key_here"
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Predict example:

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "visible_text": "Urgent! Verify your account immediately",
    "links": [{"text": "Click here", "href": "http://suspicious-example.com/login"}]
  }'
```

Expected response shape:

```json
{
  "label": "phishing",
  "probability_phishing": 0.93,
  "flags": ["..."]
}
```

## 5) Reputation API (trusted/flagged domain intelligence)

Create local lists:

```bash
mkdir -p backend/artifacts/reputation
cat > backend/artifacts/reputation/trusted_domains.txt <<'EOF'
google.com
microsoft.com
apple.com
amazon.com
paypal.com
EOF

cat > backend/artifacts/reputation/flagged_domains.txt <<'EOF'
example-phish-domain.com
another-malicious-domain.net
EOF
```

Reload lists without restarting backend:

```bash
curl -X POST http://127.0.0.1:8000/reputation/reload
```

Check reputation service status:

```bash
curl http://127.0.0.1:8000/reputation/status
```

Check URLs against reputation providers:

```bash
curl -X POST http://127.0.0.1:8000/reputation/check \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://accounts.google.com",
      "http://example-phish-domain.com/login"
    ]
  }'
```

`/predict` now uses this reputation layer for domain-based flags.

## 6) User Feedback + Preferences API

Users can provide feedback from the extension popup:
- `Report Spam` -> stores a phishing-labeled training example
- `Report Not Spam` -> stores a legitimate-labeled training example
- `Block Domain` -> adds domain to user blocklist (forces high phishing risk)
- `Allow Domain` -> adds domain to user allowlist (reduces phishing risk)

Data is persisted under:
- `backend/artifacts/feedback/user_preferences.json`
- `backend/artifacts/feedback/feedback_events.jsonl`
- `backend/artifacts/feedback/training_feedback.csv`

Endpoints:

```bash
curl http://127.0.0.1:8000/preferences
curl http://127.0.0.1:8000/feedback/stats

curl -X POST http://127.0.0.1:8000/preferences/block \
  -H "Content-Type: application/json" \
  -d '{"domain":"bad-domain.com"}'

curl -X POST http://127.0.0.1:8000/preferences/allow \
  -H "Content-Type: application/json" \
  -d '{"domain":"trusted-domain.com"}'

curl -X POST http://127.0.0.1:8000/feedback/report-spam \
  -H "Content-Type: application/json" \
  -d '{"visible_text":"urgent verify account","links":[{"text":"Verify","href":"http://bad-domain.com"}],"source":"manual_test"}'

curl -X POST http://127.0.0.1:8000/feedback/report-not-spam \
  -H "Content-Type: application/json" \
  -d '{"visible_text":"team meeting at 2pm","links":[],"source":"manual_test"}'
```

### Retraining with user feedback

`python backend/train.py --include-feedback` merges:
- base Kaggle dataset sample
- user feedback examples from `backend/artifacts/feedback/training_feedback.csv`

So the model gradually adapts when you retrain periodically.

## 7) Run Backend with Docker

From project root:

```bash
docker build -f backend/Dockerfile -t phishing-backend .
docker run --rm -p 8000:8000 phishing-backend
```

Note:
- Ensure `backend/artifacts/vectorizer.joblib` and `backend/artifacts/classifier.joblib` exist before running container.

## 8) Load and Use Chrome Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select:
   - `/Users/mehdisheriff/Desktop/phishing/extension`
4. Open extension **Options** page and set API URL (default: `http://127.0.0.1:8000`)
5. Open an email/webpage tab and wait for page load:
   - extension auto-scans on launch/reload
   - a browser notification shows the result and includes a **Scan Again** action
6. Click extension icon and press **Scan Current Page** for manual scan at any time
7. Popup shows:
   - predicted `label` (`phishing` or `legitimate`)
   - `probability_phishing`
   - heuristic `flags`
8. Optional actions in popup:
   - **Report Spam**
   - **Report Not Spam**
   - **Block Domain**
   - **Allow Domain**

## 9) Evaluate Against `test_data` Automatically

The project includes ready-made HTML test emails under:
- `test_data/phishing/`
- `test_data/non_phishing/`

The evaluation CSV is:
- `test_data/evaluation_log_template.csv`

Recommended workflow:

1. Start the backend before training:
```bash
uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```
2. Serve the folder locally:
```bash
python -m http.server 8010 --directory test_data
```
3. Open `http://127.0.0.1:8010/` if you want to inspect the test pages in the browser.
4. Run the standalone evaluation script:
```bash
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000
```
5. After baseline testing is complete, train the model:
```bash
python backend/train.py
```
6. Restart the backend and run the same evaluation script again.
7. The same CSV will now fill the `posttraining_*` columns automatically.

This is the primary evaluation path now:

```bash
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000
```

What this script does:
- reads every HTML email in `test_data/phishing/` and `test_data/non_phishing/`
- extracts the email text and links
- sends each email to `/predict`
- writes the result into `test_data/evaluation_log_template.csv` through `/evaluation/log`
- prints a simple summary at the end

Use it twice:
- once before training to fill the `pretraining_*` columns
- once after training to fill the `posttraining_*` columns

## Notes

- The extension extracts visible text and links (`text` + `href`) from the current page.
- The backend combines page text and links for inference.
- If `/predict` returns errors, verify:
  - backend is running
  - API URL in extension options is correct
  - model artifacts exist in `backend/artifacts/`
