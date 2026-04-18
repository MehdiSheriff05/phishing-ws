# Undergraduate Phishing Email Detection System

This project is a phishing email detection system built as a Chrome Extension with a FastAPI backend. The extension scans Gmail or normal webpages, extracts visible text and links, sends that content to the backend, and displays a phishing label, phishing probability score, and explanation flags.

The system supports two phases:

- **Pretraining mode**: the backend has no trained model loaded and uses a deliberately weak heuristic baseline.
- **Post-training mode**: the backend loads a trained TF-IDF + Logistic Regression model and uses it to calculate phishing probability.

The training workflow is designed to avoid data leakage:

- Training uses a balanced set of `900 phishing + 900 non-phishing` emails.
- Emails already used inside `test_data/` are excluded from the training pool.
- The same test set can be evaluated before and after training to show improvement.

## Project Structure

```text
phishing/
├── backend/
│   ├── app/
│   │   ├── evaluation.py
│   │   ├── feedback.py
│   │   ├── flags.py
│   │   ├── main.py
│   │   ├── model_io.py
│   │   ├── reputation.py
│   │   └── schemas.py
│   ├── artifacts/
│   │   ├── classifier.joblib
│   │   ├── vectorizer.joblib
│   │   ├── metrics.json
│   │   └── confusion_matrix.csv
│   ├── evaluate_test_data.py
│   ├── prepare_test_data.py
│   ├── train.py
│   └── Dockerfile
├── extension/
│   ├── manifest.json
│   ├── content.js
│   ├── service_worker.js
│   ├── popup.html
│   ├── popup.js
│   ├── options.html
│   ├── options.js
│   └── icon128.png
├── test_data/
│   ├── phishing/
│   ├── non_phishing/
│   ├── evaluation_log_template.csv
│   └── fixed_evaluation_log_template.csv
├── requirements.txt
└── README.md
```

## Application Architecture UML

```text
+-----------------------------+          +-------------------------------+
|        Chrome Browser       |          |        FastAPI Backend         |
|-----------------------------|          |-------------------------------|
| Gmail / Website Page        |          | /predict                      |
| visible text + links        |          | /health                       |
+-------------+---------------+          | /preferences/block            |
              |                          | /preferences/allow            |
              v                          | /reputation/check             |
+-----------------------------+          +---------------+---------------+
| extension/content.js        |                          |
|-----------------------------|                          |
| isVisible()                 |                          |
| getGmailScanRoot()          |                          |
| extractVisibleText()        |                          |
| extractLinks()              |                          |
| detects page changes        |                          |
+-------------+---------------+                          |
              | chrome.runtime message                   |
              v                                          |
+-----------------------------+      HTTP POST /predict  |
| extension/service_worker.js |------------------------->|
|-----------------------------|                          |
| runScanForTab()             |                          v
| requestPageData()           |          +-------------------------------+
| maybeAutoScan()             |          | backend/app/main.py           |
| saveLastScanResult()        |          |-------------------------------|
| showScanNotification()      |          | startup_event()               |
+-------------+---------------+          | predict()                     |
              |                          | apply_user_domain_policy()    |
              |                          | has_strong_heuristic_evidence |
              v                          +---------------+---------------+
+-----------------------------+                          |
| extension/popup.js          |                          |
|-----------------------------|                          |
| renderResult()              |                          |
| Scan button                 |                          |
| Block Domain button         |                          |
| Allow Domain button         |                          |
+-----------------------------+                          |
                                                         |
                      +----------------------------------+----------------------------------+
                      |                                  |                                  |
                      v                                  v                                  v
        +-----------------------------+    +-----------------------------+    +-----------------------------+
        | backend/app/flags.py        |    | backend/app/model_io.py     |    | backend/app/reputation.py   |
        |-----------------------------|    |-----------------------------|    |-----------------------------|
        | detect_flags()              |    | load_artifacts()            |    | DomainReputationService     |
        | keyword checks              |    | vectorizer.joblib           |    | trusted domains             |
        | money scam checks           |    | classifier.joblib           |    | flagged domains             |
        | pressure checks             |    +-------------+---------------+    | Google Safe Browsing opt.   |
        | link checks                 |                  |                    +-----------------------------+
        +-----------------------------+                  |
                                                         v
                                           +-----------------------------+
                                           | backend/artifacts/          |
                                           |-----------------------------|
                                           | vectorizer.joblib           |
                                           | classifier.joblib           |
                                           | metrics.json                |
                                           | confusion_matrix.csv        |
                                           +-----------------------------+
```

## Training Pipeline UML

```text
+-----------------------------+
| backend/train.py            |
+-------------+---------------+
              |
              v
+-----------------------------+
| Kaggle phishing dataset     |
| naserabdullahalam/...       |
+-------------+---------------+
              |
              v
+-----------------------------+
| Clean and normalize text    |
| Convert labels to 0 or 1    |
+-------------+---------------+
              |
              v
+-----------------------------+
| Exclude test_data emails    |
| Prevents training leakage   |
+-------------+---------------+
              |
              v
+-----------------------------+
| Sample balanced data        |
| 900 phishing                |
| 900 non-phishing            |
+-------------+---------------+
              |
              v
+-----------------------------+
| Split training/validation   |
| 80% train, 20% validation   |
+-------------+---------------+
              |
              v
+-----------------------------+
| TfidfVectorizer             |
| Converts words to numbers   |
| max_features=30000          |
| ngram_range=(1,2)           |
+-------------+---------------+
              |
              v
+-----------------------------+
| LogisticRegression          |
| Learns phishing patterns    |
| class_weight=balanced       |
+-------------+---------------+
              |
              v
+-----------------------------+
| Save model artifacts        |
| vectorizer.joblib           |
| classifier.joblib           |
| metrics.json                |
+-----------------------------+
```

## High-Level Implementation Explanation

The project has three main parts:

- The **Chrome Extension** is the user-facing layer. It scans Gmail or a normal webpage, extracts visible text and links, and displays the result.
- The **FastAPI backend** is the decision engine. It receives text and links, applies rule-based phishing checks, checks domain reputation, applies allowlist/blocklist policy, and runs the trained machine learning model when available.
- The **training pipeline** is separate from the live app. It downloads a phishing email dataset, removes test-data overlap, trains the model, and saves the model artifacts.

## How Scanning Works

When Gmail or a webpage changes, `extension/content.js` detects the page change and extracts visible page text and links.

`extension/service_worker.js` receives the scan trigger, asks `content.js` for the page data, then sends this request to the backend:

```text
POST http://127.0.0.1:8000/predict
```

The backend returns a response like this:

```json
{
  "label": "phishing",
  "probability_phishing": 0.630395,
  "flags": ["Risky words found: beneficiary, investment, transfer"]
}
```

The popup displays:

- `label`: either `phishing` or `legitimate`
- `probability_phishing`: a score from `0.0` to `1.0`
- `flags`: human-readable explanation of what looked suspicious

If the result is medium or high risk, the extension also shows a browser notification.

## How Training Occurs

Training happens by running:

```bash
python backend/train.py
```

The script uses the Kaggle dataset:

```text
naserabdullahalam/phishing-email-dataset
```

The training script performs these steps:

1. Loads email text and labels from the dataset.
2. Converts labels into `1 = phishing` and `0 = legitimate`.
3. Extracts email text from `test_data`.
4. Removes matching test emails from the training dataset.
5. Randomly samples `900` phishing and `900` non-phishing emails.
6. Splits the `1800` examples into training and validation sets.
7. Converts email text into numeric TF-IDF features.
8. Trains a Logistic Regression classifier.
9. Saves the trained files into `backend/artifacts`.

Current saved training metrics:

```text
Training examples: 1800
Phishing examples: 900
Non-phishing examples: 900
Precision: 95.48%
Recall: 93.89%
F1 score: 94.68%
PR AUC: 98.56%
Validation confusion matrix:
actual legitimate predicted legitimate: 172
actual legitimate predicted phishing: 8
actual phishing predicted legitimate: 11
actual phishing predicted phishing: 169
```

## How The Score Is Calculated

There are two scoring modes.

Before training, the backend has no machine learning files. It uses a deliberately weak heuristic baseline:

```text
pretraining_score = 0.15 * number_of_flags
maximum score = 0.45
```

Because the heuristic phishing threshold is `0.50`, pretraining mode records explanations but does not overstate confidence. This makes the trained model's improvement clearer during evaluation.

After training, the backend loads:

```text
backend/artifacts/vectorizer.joblib
backend/artifacts/classifier.joblib
```

The trained model score is calculated as:

```text
probability_phishing = classifier.predict_proba(vectorized_email_text)[0][1]
```

The backend marks a page as phishing when:

```text
probability_phishing >= 0.60
```

The threshold is `0.60` instead of `0.50` because earlier testing showed that the lower threshold produced too many false positives.

## Weighting And Decision Logic

The pretraining heuristic baseline uses manual scoring:

```text
Each detected flag adds 0.15
Maximum pretraining score is 0.45
Heuristic phishing threshold is 0.50
```

The trained model uses learned weighting:

```text
TF-IDF gives importance to words and two-word phrases.
Logistic Regression learns which words and phrases increase or decrease phishing probability.
class_weight="balanced" prevents the model from favoring one class too strongly.
```

There are also domain policy overrides:

```text
Blocklisted domain: force phishing, score at least 0.98.
Allowlisted clean domain: force legitimate, score at most 0.10.
Allowlisted risky page: still warn if the ML score is high or strong phishing rules appear.
```

## How The ML Model Connects To The User

The user does not directly interact with the ML model. The extension hides that complexity.

```text
User opens Gmail/email/page
Extension extracts text and links
Extension sends content to FastAPI
FastAPI converts text into ML features
ML model calculates phishing probability
FastAPI returns label, score, and explanation flags
Extension displays warning to user
```

## Quick Start

Use the command set that matches your operating system.

## macOS / Linux Setup

Open Terminal.

```bash
cd /Users/mehdisheriff/Desktop/phishing
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run the backend:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Stop the backend with `Control + C`.

Deactivate the virtual environment:

```bash
deactivate
```

## Windows PowerShell Setup

Open PowerShell in the project folder.

```powershell
cd C:\path\to\phishing
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, run this once for the current user:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate again:

```powershell
.\.venv\Scripts\Activate.ps1
```

Run the backend:

```powershell
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Stop the backend with `Ctrl + C`.

Deactivate the virtual environment:

```powershell
deactivate
```

## Windows CMD Setup

Open Command Prompt in the project folder.

```cmd
cd C:\path\to\phishing
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run the backend:

```cmd
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check:

```cmd
curl http://127.0.0.1:8000/health
```

Stop the backend with `Ctrl + C`.

Deactivate the virtual environment:

```cmd
deactivate
```

## Train The Model

Activate your virtual environment first, then run:

macOS / Linux:

```bash
python backend/train.py
```

Windows PowerShell:

```powershell
python backend/train.py
```

Windows CMD:

```cmd
python backend\train.py
```

Useful options:

```bash
python backend/train.py --samples-per-class 900
python backend/train.py --samples-per-class 900 --allow-synthetic-non-phishing
```

Training outputs:

```text
backend/artifacts/vectorizer.joblib
backend/artifacts/classifier.joblib
backend/artifacts/metrics.json
backend/artifacts/confusion_matrix.csv
```

After training, restart the backend so it loads the new model artifacts.

## Run Pretraining And Post-Training Evaluation

The project includes test emails under:

```text
test_data/phishing/
test_data/non_phishing/
```

The main fixed evaluation CSV is:

```text
test_data/fixed_evaluation_log_template.csv
```

### macOS / Linux Evaluation

Start the backend before training if you want to record pretraining results:

```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second Terminal window:

```bash
source .venv/bin/activate
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data/fixed_evaluation_log_template.csv --reset-results
```

Train the model:

```bash
python backend/train.py
```

Restart the backend, then run post-training evaluation:

```bash
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data/fixed_evaluation_log_template.csv
```

### Windows PowerShell Evaluation

Start the backend before training:

```powershell
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second PowerShell window:

```powershell
.\.venv\Scripts\Activate.ps1
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data/fixed_evaluation_log_template.csv --reset-results
```

Train the model:

```powershell
python backend/train.py
```

Restart the backend, then run post-training evaluation:

```powershell
python backend/evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data/fixed_evaluation_log_template.csv
```

### Windows CMD Evaluation

Start the backend before training:

```cmd
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second CMD window:

```cmd
.venv\Scripts\activate.bat
python backend\evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data\fixed_evaluation_log_template.csv --reset-results
```

Train the model:

```cmd
python backend\train.py
```

Restart the backend, then run post-training evaluation:

```cmd
python backend\evaluate_test_data.py --api-base-url http://127.0.0.1:8000 --evaluation-csv test_data\fixed_evaluation_log_template.csv
```

The current fixed evaluation result is:

```text
Pretraining accuracy: 50.00%
Post-training accuracy: 97.50%
```

## Serve Test Emails In A Browser

This is optional. It is useful if you want to manually open the test emails and see how the Chrome extension reacts.

macOS / Linux:

```bash
python -m http.server 8010 --directory test_data
```

Windows PowerShell:

```powershell
python -m http.server 8010 --directory test_data
```

Windows CMD:

```cmd
python -m http.server 8010 --directory test_data
```

Then open:

```text
http://127.0.0.1:8010/
```

## Load The Chrome Extension

1. Open Chrome.
2. Go to `chrome://extensions`.
3. Turn on **Developer mode**.
4. Click **Load unpacked**.
5. Select the `extension` folder inside this project.
6. Open the extension options page.
7. Confirm the API URL is:

```text
http://127.0.0.1:8000
```

Usage:

1. Open Gmail or a test email page.
2. Wait for the automatic scan or click the extension icon.
3. Click **Scan Current Page** for a manual scan.
4. Review the label, score, and flags.
5. Use **Block Domain** if a linked domain should always warn.
6. Use **Allow Domain** if a linked domain is trusted, while still allowing risky content to trigger warnings.

## API Endpoints

Health:

```bash
curl http://127.0.0.1:8000/health
```

Prediction:

```bash
curl -X POST http://127.0.0.1:8000/predict \
  -H "Content-Type: application/json" \
  -d '{
    "visible_text": "Urgent! Verify your account immediately",
    "links": [{"text": "Click here", "href": "http://suspicious-example.com/login"}]
  }'
```

Preferences:

```bash
curl http://127.0.0.1:8000/preferences
curl http://127.0.0.1:8000/feedback/stats
```

Block a domain:

```bash
curl -X POST http://127.0.0.1:8000/preferences/block \
  -H "Content-Type: application/json" \
  -d '{"domain":"bad-domain.com"}'
```

Allow a domain:

```bash
curl -X POST http://127.0.0.1:8000/preferences/allow \
  -H "Content-Type: application/json" \
  -d '{"domain":"trusted-domain.com"}'
```

## Domain Reputation

The backend can use local reputation files:

```text
backend/artifacts/reputation/trusted_domains.txt
backend/artifacts/reputation/flagged_domains.txt
```

Reload reputation lists without restarting:

```bash
curl -X POST http://127.0.0.1:8000/reputation/reload
```

Check reputation status:

```bash
curl http://127.0.0.1:8000/reputation/status
```

Google Safe Browsing is optional. If you have an API key, set it before starting the backend.

macOS / Linux:

```bash
export GOOGLE_SAFE_BROWSING_API_KEY="your_api_key_here"
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Windows PowerShell:

```powershell
$env:GOOGLE_SAFE_BROWSING_API_KEY="your_api_key_here"
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Windows CMD:

```cmd
set GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

## Docker Deployment

Build the backend image from the project root:

```bash
docker build -f backend/Dockerfile -t phishing-backend .
```

Run the backend container:

```bash
docker run --rm -p 8000:8000 phishing-backend
```

Important: make sure these files exist before building or deploying the container:

```text
backend/artifacts/vectorizer.joblib
backend/artifacts/classifier.joblib
```

## Deployment Plan

For a real deployment:

1. Host the FastAPI backend on a service such as Render, Railway, Fly.io, AWS, Azure, or a university server.
2. Include `vectorizer.joblib` and `classifier.joblib` with the backend deployment.
3. Use HTTPS for the deployed backend.
4. Change the extension API URL from `http://127.0.0.1:8000` to the deployed backend URL.
5. Restrict CORS so only the Chrome extension can call the backend.
6. Add production logging for predictions, errors, false positives, and false negatives.
7. Retrain the model periodically with newer phishing and legitimate examples.
8. Version each trained model so evaluation results can be linked to the exact model used.
9. Package the Chrome extension and submit it to the Chrome Web Store if public release is required.
10. Keep training data and test data separate for every retraining cycle.

## Troubleshooting

If the extension shows an error:

- Confirm the backend is running on `http://127.0.0.1:8000`.
- Confirm the extension options page uses the same API URL.
- Confirm the page is not a restricted Chrome page such as `chrome://extensions`.
- Open `http://127.0.0.1:8000/health` and check that the API responds.

If `/health` says `"model_loaded": false`:

- The backend did not find model artifacts.
- Run `python backend/train.py`.
- Restart the backend.

If PowerShell blocks virtual environment activation:

- Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- Then run `.\.venv\Scripts\Activate.ps1` again.

## Dissertation Summary

This project implements a Chrome extension that extracts email and webpage text, sends it to a FastAPI backend, combines explainable phishing rules with a trained TF-IDF Logistic Regression model, and returns a phishing probability, label, and human-readable explanation to warn users about suspicious content.
