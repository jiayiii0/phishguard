@echo off
cd /d "%~dp0"
set PYTHONPATH=%CD%
if not exist "backend\ml\artifacts\xgboost_model.joblib" (
  echo Training demo XGBoost model...
  python -m backend.ml.train --demo
)
echo Starting PhishGuard on http://127.0.0.1:8000
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
pause
