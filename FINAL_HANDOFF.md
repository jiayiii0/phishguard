# PhishGuard Final Handoff

## Current Status

PhishGuard is a runnable full-stack phishing detection platform with:

- React + Tailwind frontend
- FastAPI backend
- SQLite local database and PostgreSQL Docker deployment
- XGBoost as the primary prediction engine
- URL feature engineering for modern phishing signals
- Risk score, confidence score, indicators, and explainable factors
- Threat dashboard with stored scan history and charts
- REST API documentation at `/docs`
- Premium dark cybersecurity SaaS interface with glass panels, hero scanner, animated threat visuals, and responsive dashboard
- Clear History action, dashboard filters, JSON scan report export, risk severity levels, model evidence, confusion matrix, and feature importance chart
- Public URL safety validation, API rate limiting, and browser security headers

The local website runs at:

```text
http://127.0.0.1:8000
```

## Verified Training Status

The current saved model is a real-mode XGBoost model, not the earlier demo model.

```text
algorithm: XGBoost
mode: real
training sources:
- Phishing.Database: 789,052 rows from phishing_database_urls.csv
- OpenPhish: 300 rows from openphish_urls.csv
- Legitimate URL dataset: 50,000 rows from legitimate_urls.csv
training/evaluation dataset size: 99,994 balanced URLs
feature count: 63
train/test split: 80:20 stratified
cross-validation folds: 3
selected decision threshold: 0.24
training seconds: 1.8775
prediction time per URL: 0.0015 ms
accuracy: 0.9287
precision: 0.9095
recall: 0.9523
f1 score: 0.9304
cross-validation F1 mean: 0.9382
confusion matrix: [[9052, 948], [477, 9522]]
```

The current local data files are:

```text
backend/ml/data/phishing_database_urls.csv
backend/ml/data/openphish_urls.csv
backend/ml/data/legitimate_urls.csv
```

Phishing.Database is the main free large phishing source used in the current model. PhishTank support is implemented in the training pipeline, but the latest live attempt returned HTTP 429 rate limiting without an application key. To train with PhishTank, register a PhishTank application key or manually download the PhishTank database, then import it and retrain.

## Machine Learning Design

The prediction flow is:

```text
URL input
-> URL normalization
-> lightweight feature extraction
-> XGBoost probability prediction
-> indicator-based safety guardrails
-> risk score and confidence calculation
-> explainable factors returned to the UI
```

The feature extractor covers:

- URL length and hostname length
- Path and query length
- Digit, letter, and special-character ratios
- HTTPS usage
- IP-address URLs
- Subdomain count
- Suspicious keyword count
- Shortened URL services
- Optional shortened URL redirect expansion with SSRF blocking, redirect depth limit, and request timeout
- Redirect count, redirect domain changes, final-domain difference, and redirect loop detection
- Redirect-style symbols
- Punycode and homograph patterns
- Unicode and homoglyph similarity against known brands
- Suspicious top-level domains
- Brand impersonation
- Typosquatting similarity
- Encoded characters
- Obfuscation score, embedded URL count, @ symbol abuse, excessive hyphens, Unicode count, and high-entropy token count
- Optional DNS and WHOIS related signals

## Training Data

The training pipeline supports these sources:

- PhishTank
- Phishing.Database
- OpenPhish
- UCI phishing URL CSV export
- Kaggle phishing URL datasets
- Legitimate URL CSV datasets

PhishTank official import options:

```powershell
$env:PHISHTANK_APP_KEY="your_phishtank_key"
python -m backend.ml.train --download-phishtank --download-only
```

```powershell
python -m backend.ml.train --phishtank-file C:\path\to\online-valid.csv.bz2 --download-only
```

Expected CSV format:

```csv
url,label
https://www.google.com,0
http://example-login-alert.test,1
```

Use label `1` for phishing and `0` for legitimate.

## Recommended Final Training Steps

Run from the project folder:

```powershell
cd C:\Users\1234\Downloads\phishguard_fullstack_polished\phishguard_platform
$env:PYTHONPATH=(Get-Location).Path
python -m backend.ml.train --download-phishtank --download-openphish --build-legitimate-seed --download-only
```

Recommended large free-dataset command:

```powershell
python -m backend.ml.train --download-phishing-database --download-openphish --download-umbrella-legitimate --legitimate-limit 50000 --download-only
python -m backend.ml.train --balance --cv-folds 3
```

Then add these files if available:

```text
backend/ml/data/uci_phishing_urls.csv
backend/ml/data/kaggle_phishing_urls.csv
backend/ml/data/legitimate_urls.csv
```

Train the final model:

```powershell
python -m backend.ml.train --tune --cv-folds 3
```

If only OpenPhish and the legitimate seed dataset are available, the command above still trains a real-mode model. Add PhishTank, UCI, and Kaggle CSVs before this command to broaden the training set.

The final artifacts are saved here:

```text
backend/ml/artifacts/xgboost_model.joblib
backend/ml/artifacts/scaler.joblib
backend/ml/artifacts/feature_columns.joblib
backend/ml/artifacts/metrics.json
```

## Local Run

```powershell
cd C:\Users\1234\Downloads\phishguard_fullstack_polished\phishguard_platform
.\run_windows.bat
```

Keep the terminal open while using the website.

## Verification Commands

```powershell
cd C:\Users\1234\Downloads\phishguard_fullstack_polished\phishguard_platform
$env:PYTHONPATH=(Get-Location).Path
python -m pytest -q
```

```powershell
cd C:\Users\1234\Downloads\phishguard_fullstack_polished\phishguard_platform\frontend
npm.cmd run build
```

## Docker Deployment

```powershell
cd C:\Users\1234\Downloads\phishguard_fullstack_polished\phishguard_platform
docker compose up --build
```

This starts:

- `postgres`: PostgreSQL database
- `app`: FastAPI app serving the React production build

## Presentation Points

Use these points when explaining the system:

- XGBoost is the core classification algorithm.
- The system uses lightweight URL-based features for fast scanning.
- DNS and WHOIS checks are available but optional because they slow down real-time response.
- SHAP can be enabled for model-level explainability, while the default UI still returns understandable risk factors instantly.
- PostgreSQL is used in Docker production deployment, while SQLite keeps local development simple.
- The UI is written as a real public cybersecurity product with professional wording.
- The model evidence panel is useful for FYP2 and competition judging because it shows data sources, dataset size, cross-validation result, confusion matrix, and feature importance directly inside the product.
- Security maturity was improved with input validation, local/internal URL blocking, rate limiting, security headers, scan history controls, and report export.
- Modern evasion handling was added before XGBoost prediction: canonical normalization, percent-decoding, shortened URL detection, redirect metadata, obfuscation detection, punycode detection, Unicode/homoglyph checks, and brand impersonation scoring.
