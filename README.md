# PhishGuard

PhishGuard is a phishing website detection platform powered by XGBoost. It provides this real-time scan workflow:

URL Input -> Feature Extraction -> XGBoost Prediction -> Risk Rules and Threat Feed -> Explanation Factors -> Result Dashboard

SHAP is optional and disabled by default. Without SHAP, explanation factors are heuristic indicators, not SHAP values. The displayed risk/confidence includes runtime rules and is not a calibrated model probability.

The current interface is designed as a premium cybersecurity SaaS product: dark glass panels, hero-first URL scanning, animated threat visuals, instant risk cards, model evidence, and dashboard analytics.

## Stack

- React + Tailwind frontend
- FastAPI backend
- PostgreSQL in Docker deployment
- SQLite fallback for quick local development
- XGBoost as the primary prediction engine
- SHAP explainable AI
- Framer Motion animations
- Recharts dashboard visualizations

## Competition-Grade Features

- Real-time URL scanner in the hero section
- Risk severity levels: Safe, Low Risk, Suspicious, High Risk, and Phishing
- Risk score and confidence score for every scan
- Detection summary and explainable top factors
- JSON scan report export
- Clear History action for stored scans
- Dashboard filters for Safe, Low Risk, Suspicious, High Risk, and Phishing
- Model Evidence section with training summary, confusion matrix, and feature importance chart
- Public URL safety validation to block localhost, internal IP, reserved IP, and non-HTTP schemes
- API rate limiting and security headers
- Modern evasion preprocessing for percent-encoding, obfuscation, punycode, Unicode/homoglyph domains, brand impersonation, suspicious TLDs, shortened URLs, and redirect metadata

## Project Structure

```text
backend/app/                  FastAPI application, database, API, prediction service
backend/app/services/         URL feature engineering and XGBoost prediction logic
backend/ml/train.py           XGBoost training pipeline
backend/ml/data/              Included training CSVs and local threat-feed snapshots
backend/ml/artifacts/         Saved model, scaler, columns, and metrics
frontend/src/                 React + Tailwind user interface
tests/                        Backend feature and API tests
Dockerfile                    Full-stack application image
docker-compose.yml            App + PostgreSQL deployment
```

## Run Locally

From the extracted project folder, install Python 3.11 dependencies once:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start from PowerShell using the installed environment:

```powershell
$env:PYTHONPATH=(Get-Location).Path
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

The included `frontend/dist` is served by FastAPI; Node.js is only needed to rebuild the frontend. To rebuild, run `npm.cmd ci` and `npm.cmd run build` from `frontend/`.

Alternatively, if the `python` command already has the required packages installed, double-click:

```text
run_windows.bat
```

Then open:

```text
http://127.0.0.1:8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

## Verification and Evidence

Run tests from the project folder with the same Python environment:

```powershell
.\.venv\Scripts\python.exe -m pip install httpx
.\.venv\Scripts\python.exe -m pytest -q
```

`httpx` is required by FastAPI TestClient but is not listed in the current requirements file.

The final saved model uses `backend/ml/artifacts/metrics.json` (threshold 0.48; final test size 60,231). `error_analysis.json` is historical evidence from an earlier model (threshold 0.38; test size 60,933), not the final model evaluation. `FINAL_MODEL_REPORT.md` contains several chronological runs; use its last final-retraining section for the final results. External-validation results are documented, but the external collector and per-URL result files are not included in this source package.

This ZIP-style submission includes CSV datasets and the frontend build. Both are ignored by Git, so a Git-only export will not contain the same files.

## Train Demo Model

The demo model is useful for local testing when real datasets are not available yet.

```bash
python -m backend.ml.train --demo
```

## Real Dataset Training

Phishing sources:

- PhishTank: `python -m backend.ml.train --download-phishtank`
- Phishing.Database: `python -m backend.ml.train --download-phishing-database`
- OpenPhish: `python -m backend.ml.train --download-openphish`
- UCI dataset: place CSV at `backend/ml/data/uci_phishing_urls.csv`
- Kaggle URL dataset: place CSV at `backend/ml/data/kaggle_phishing_urls.csv`

Legitimate source:

- generate a curated seed: `python -m backend.ml.train --build-legitimate-seed --download-only`
- or place CSV at `backend/ml/data/legitimate_urls.csv`

Every CSV must contain:

```csv
url,label
https://example.com,0
http://phishing-example.test,1
```

Notes:

- Label `1` means phishing.
- Label `0` means legitimate.
- The training code uses all available rows by default and applies XGBoost class weighting for imbalanced data.
- Add `--balance` only if you explicitly want equal class downsampling.
- Add `--tune` to run RandomizedSearchCV hyperparameter tuning.
- The saved XGBoost artifacts replace the previous model in `backend/ml/artifacts`.
- Real phishing feed files can trigger endpoint protection alerts because they contain malicious URL strings. That is expected for cybersecurity dataset work; keep the files inside the project training folder and do not execute anything from the dataset.

Then train:

```bash
python -m backend.ml.train --balance --cv-folds 3
```

The generated metrics file records accuracy, precision, recall, F1 score, cross-validation F1, confusion matrix, dataset size, feature count, and training sources.

Current checked-in local training status:

```text
mode: real
sources: Phishing.Database 789,052 rows + OpenPhish 300 rows + legitimate URL dataset 200,000 rows + legitimate hard negatives 37 rows + broad legitimate hard negatives 8,702 rows + targeted external hard negatives 542 rows + targeted missed phishing 20 rows
cleaned rows before balancing: 997,787
balanced training/evaluation dataset: 418,540 URLs
split: hostname-grouped 70:15:15 with zero host overlap across train/validation/test
training size: 295,441
validation size: 62,868
final test size: 60,231
feature_count: 73
selected_threshold: 0.48, selected on validation data only
accuracy: 0.942970
precision: 0.976079
recall: 0.908307
f1_score: 0.940974
false_positive_rate: 0.022302
false_negative_rate: 0.091693
roc_auc: 0.982870
pr_auc: 0.986487
confusion_matrix: [[29416, 671], [2764, 27380]]
```

Full final model report:

```text
FINAL_MODEL_REPORT.md
```
Phishing recall is intentionally prioritized because false negatives are dangerous in phishing detection. PhishTank download support is implemented, but the public feed can return HTTP 429 rate limiting without an application key. To train with as much PhishTank data as possible, register a PhishTank application key, set it before training, and run:

```powershell
$env:PHISHTANK_APP_KEY="your_phishtank_key"
$env:PYTHONPATH=(Get-Location).Path
python -m backend.ml.train --download-phishtank --download-only
python -m backend.ml.train --tune --cv-folds 3
```

If you manually download the PhishTank database, import it with:

```powershell
python -m backend.ml.train --phishtank-file C:\path\to\online-valid.csv.bz2 --download-only
python -m backend.ml.train --tune --cv-folds 3
```

## Docker Deployment

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8000
```

## API Documentation

When the server is running:

```text
http://127.0.0.1:8000/docs
```

## Environment Variables

```text
DATABASE_URL=postgresql+psycopg2://phishguard:phishguard_password@postgres:5432/phishguard
ENABLE_SHAP=false
ENABLE_NETWORK_INTEL=false
ENABLE_SHORTENER_EXPANSION=false
ENABLE_THREAT_FEED_LOOKUP=true
URL_RESOLVE_TIMEOUT_SECONDS=1.5
CORS_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
PHISHTANK_APP_KEY=optional_phishtank_application_key
```

`ENABLE_NETWORK_INTEL=true` enables live DNS/WHOIS checks. Keep it disabled for the fastest scan response.
`ENABLE_SHORTENER_EXPANSION=true` enables live redirect expansion for known shorteners with SSRF checks, redirect depth limit, and timeout. It is disabled by default locally so scans remain instant even when external network calls are blocked or slow.

## Report Notes To Highlight

- The platform was upgraded from a basic detector into a deployable cybersecurity SaaS-style product.
- XGBoost remains the primary prediction engine and the selected threshold prioritizes phishing recall while reducing legitimate false positives.
- The current checked-in model was trained and evaluated on 418,540 balanced URLs after cleaning 998,653 raw rows from Phishing.Database, OpenPhish, a legitimate URL dataset, hard legitimate negatives, broad legitimate hard negatives, and targeted external error samples.
- PhishTank, UCI, and Kaggle import support is implemented, but those datasets were not included in this saved training run because no local files/API access were available.
- The feature set contains 73 engineered signals, including shortened URL, redirect, obfuscation, punycode, Unicode/homoglyph, suspicious TLD, brand impersonation, known-platform context, and encoded URL features.
- Threat-feed exact URL matches strongly increase risk. Domain-only feed matches on shared reputable platforms are treated as contextual evidence instead of automatic phishing verdicts.
- The system exposes model evidence directly in the UI: dataset size, source list, metrics, confusion matrix, threshold, and feature importance.
- Practical safety controls were added: input validation, private-network blocking, rate limiting, security headers, scan history management, and report export.
