# PhishGuard

PhishGuard is a phishing website detection platform powered by XGBoost. It provides this real-time scan workflow:

URL Input -> Feature Extraction -> XGBoost Prediction -> SHAP Explanation -> Result Dashboard

The current interface is designed as a premium cybersecurity SaaS product: dark glass panels, hero-first URL scanning, animated threat visuals, instant risk cards, model evidence, and dashboard analytics. The UI does not mention FYP, coursework, university, or academic project wording.

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

## Project Structure

```text
backend/app/                  FastAPI application, database, API, prediction service
backend/app/services/         URL feature engineering and XGBoost prediction logic
backend/ml/train.py           XGBoost training pipeline
backend/ml/data/              Optional real training CSV files
backend/ml/artifacts/         Saved model, scaler, columns, and metrics
frontend/src/                 React + Tailwind user interface
tests/                        Backend feature and API tests
Dockerfile                    Full-stack application image
docker-compose.yml            App + PostgreSQL deployment
```

## Run Locally

Double-click:

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
sources: Phishing.Database 789,052 rows + OpenPhish 300 rows + legitimate URL dataset 50,000 rows
training/evaluation sample: 99,994 balanced URLs
split: 80:20 stratified
cross_validation_folds: 3
selected_threshold: 0.21
accuracy: 0.9185
precision: 0.8914
recall: 0.9531
f1_score: 0.9212
cv_f1_mean: 0.9346
prediction_ms_per_url: 0.0015
confusion_matrix: [[8839, 1161], [469, 9530]]
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
CORS_ORIGINS=http://127.0.0.1:8000,http://localhost:8000
PHISHTANK_APP_KEY=optional_phishtank_application_key
```

`ENABLE_NETWORK_INTEL=true` enables live DNS/WHOIS checks. Keep it disabled for the fastest scan response.

## FYP2 Report Notes To Highlight

- The platform was upgraded from a basic detector into a deployable cybersecurity SaaS-style product.
- XGBoost remains the primary prediction engine and the selected threshold prioritizes phishing recall.
- The current model was trained and evaluated on 99,994 balanced URLs using 789,052 raw Phishing.Database URLs, 300 OpenPhish URLs, and 50,000 legitimate URLs.
- The system exposes model evidence directly in the UI: dataset size, source list, metrics, confusion matrix, and feature importance.
- Practical safety controls were added: input validation, rate limiting, security headers, scan history management, and report export.
