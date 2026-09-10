# PhishGuard Final Model Report

Generated: 2026-09-05

Submission reading note (2026-09-07): This document is a chronological development record containing several model runs. The final saved-model results are in the last final-retraining section (418,540 URLs, 73 features, threshold 0.48, final test size 60,231). Earlier metrics and backup/rollback paths are historical, not submission setup instructions. Use README.md to run this portable submission. The packaged error_analysis.json is from an earlier model (threshold 0.38); do not present it as final-model evidence. External-validation collector scripts and per-URL results are not included in this package. The outer train/validation/test split is hostname-grouped; inner cross-validation and optional tuning use ordinary classifier CV, not hostname-grouped CV. Runtime prediction also applies heuristic/contextual rules and threat-feed evidence; its results differ from model-only evaluation. SHAP is optional and off by default.

## 1. Backup

Original working project backup:

```text
C:\phishing_detection_backup_before_final_improvement_20260901_111956
```

Backup verification performed before modifications:

- Source project file count: 13,625
- Backup file count: 13,625
- Backup includes frontend, backend, tests, training code, model artifacts, local database file, documentation, and configuration files.
- Backup was not modified during the final improvement work.

Git checkpoint before major modifications:

```text
2e8fc88 Checkpoint before final detection improvement
```

## 2. Root Cause

The previous false-positive issue was real. SHAP/audit testing showed long legitimate Google URLs could be pushed toward phishing mainly by URL path structure features.

Evidence from the previous model audit:

- `path_length` feature importance was approximately 0.616798, far higher than other features.
- Representative Google Forms URL raw XGBoost phishing probability was approximately 99.78% before improvement.
- Representative Google account URL raw XGBoost phishing probability was approximately 99.76% before improvement.
- Current dataset also had random train/test host overlap, so evaluation was less realistic than a hostname-grouped split.

The final system reduces this issue with additional contextual features, a larger legitimate dataset, hard-negative examples, grouped splitting, and validation-based threshold calibration.

## 3. Dataset

Training sources successfully available locally:

- Phishing.Database: 789,052 phishing URLs
- OpenPhish: 300 phishing URLs
- Legitimate top-domain dataset: 200,000 legitimate URLs
- Legitimate hard-negative dataset: 37 rows (33 official/public legitimate URLs and 4 clearly marked synthetic structural templates)

PhishTank support exists in the importer, but no PhishTank local file/API-key download was available during this run. UCI and Kaggle importer support exists, but no local UCI/Kaggle CSV files were present during this run.

Final cleaned data before balancing:

- Raw rows: 989,389
- Exact duplicate URLs removed: 10
- Normalized duplicate URLs removed: 854
- Conflicting normalized URLs removed: 1
- Missing rows removed: 0
- Malformed rows removed: 0
- Rows after cleaning: 988,523
- Legitimate rows after cleaning: 200,026
- Phishing rows after cleaning: 788,497

Final balanced training/evaluation dataset:

- Total: 400,052 URLs
- Legitimate: 200,026
- Phishing: 200,026

## 4. Data Split

Final split method:

- Method: hostname-grouped split with stratified group labels
- Random seed: 42
- Training size: 278,725
- Validation size: 60,394
- Final test size: 60,933
- Train/validation host overlap: 0
- Train/test host overlap: 0
- Validation/test host overlap: 0

The threshold was selected using validation data only. The final test set was used once for final evaluation.

## 5. Features

Original feature count: 63
Final feature count: 69

Key added/improved features:

- `registered_domain_length`
- `brand_matches_registered_domain`
- `known_platform_domain`
- `credential_terms_on_unrelated_domain`
- `embedded_external_url_count`
- `embedded_same_registered_domain_count`
- improved embedded URL detection after percent-decoding
- expanded brand vocabulary for GitHub, Zoom, Canva, Dropbox, Cloudflare, and LinkedIn

No automatic trusted-domain whitelist was added. Known/reputable platform detection is contextual evidence only and can be overridden by severe signals such as brand mismatch, IP address, punycode, suspicious TLD, external embedded URL, or `@` abuse.

Final top model importance:

1. `path_length`: 0.487835
2. `count_slash`: 0.249192
3. `has_https`: 0.053732
4. `has_suspicious_tld`: 0.027445
5. `special_char_ratio`: 0.020833
6. `subdomain_count`: 0.017677
7. `suspicious_tld_flag`: 0.015552
8. `count_dot`: 0.014638
9. `registered_domain_length`: 0.009950
10. `tld_length`: 0.009159

`path_length` is still important, but it no longer dominates as strongly as before.

## 6. Final XGBoost Model

Model artifacts:

```text
backend/ml/artifacts/xgboost_model.joblib
backend/ml/artifacts/scaler.joblib
backend/ml/artifacts/feature_columns.joblib
backend/ml/artifacts/metrics.json
backend/ml/artifacts/error_analysis.json
```

Important hyperparameters:

- `n_estimators`: 240
- `max_depth`: 4
- `learning_rate`: 0.05
- `subsample`: 0.9
- `colsample_bytree`: 0.9
- `min_child_weight`: 3
- `gamma`: 0.1
- `reg_alpha`: 0.05
- `reg_lambda`: 1.2
- `scale_pos_weight`: 1.0093356882817288
- `random_state`: 42

## 7. Threshold

Validation thresholds from 0.20 to 0.81 were evaluated. The selected threshold is:

```text
0.38
```

Reason: selected from validation data before final testing, preferring recall >= 0.93 and false-positive rate <= 0.07, then strongest F1/precision trade-off.

Validation result at selected threshold:

- Accuracy: 0.946485
- Precision: 0.961215
- Recall: 0.931232
- F1: 0.945986
- FPR: 0.038064
- FNR: 0.068768
- Confusion matrix: [[28860, 1142], [2090, 28302]]

## 8. Final Real Metrics

Final untouched test set result:

- Accuracy: 0.946728
- Precision: 0.960373
- Recall: 0.933536
- F1-score: 0.946764
- False Positive Rate: 0.039681
- False Negative Rate: 0.066464
- ROC-AUC: 0.985201
- PR-AUC: 0.988387
- Test observations: 60,933
- Legitimate test count: 30,014
- Phishing test count: 30,919
- Confusion matrix: [[28823, 1191], [2055, 28864]]

Compared with the previous reference values, false-positive rate improved from about 9.48% to 3.97%, while phishing recall remained above 93%.

## 9. Hard Legitimate Test

Regression hard legitimate cases tested: 5
Correctly classified: 5
Falsely flagged: 0
False-positive rate on this focused regression set: 0%

Representative cases:

- Long Google Forms `formResponse`: Low Risk, risk score 22
- Google account login with encoded continuation: Low Risk, risk score 22
- GitHub login return URL: Low Risk, risk score 22
- PayPal sign-in return URL: Low Risk, risk score 22
- Long Microsoft support URL: Low Risk, risk score 22

## 10. Malicious / Suspicious Test

Regression suspicious cases tested: 6
Detected: 6
Missed: 0
Detection rate on this focused regression set: 100%

Representative cases:

- fake Google login domain: Phishing, risk score 100
- `paypal.com@...` user-info abuse: Phishing, risk score 100
- punycode PayPal-like domain: Phishing, risk score 100
- IP-address PayPal verification URL: Phishing, risk score 100
- fake Microsoft `.xyz` login URL: Phishing, risk score 100
- fake Maybank suspicious TLD URL: Phishing, risk score 100

## 11. Google Forms / Long URL Issue

The Google Forms / long legitimate URL false-positive problem was materially improved at the final risk-assessment level.

Important detail: the raw XGBoost probability for the long Google Forms example is still 79.53%, showing the model still treats long path structure as risky. The final risk system reduces the user-facing risk to 22/100 because contextual evidence shows a known platform registered domain, matching brand/registered-domain context, HTTPS, and no severe brand-mismatch/evasion signals.

This is not a blind whitelist. A fake Google domain still receives Phishing with risk score 100.

## 12. Threat Intelligence

Threat-feed sources used:

- Phishing.Database local snapshot
- OpenPhish local snapshot

The system now uses local snapshots first for faster real-time scans. If no local snapshot exists, it can fall back to remote public feeds. Threat-feed failures do not mean safe; they produce no feed match and the XGBoost/contextual engine still evaluates the URL.

A verified local threat-feed exact URL match strongly increases risk. A domain-only feed match still adds evidence, but it no longer forces a phishing verdict by itself when the submitted URL is on a known shared platform and the exact URL is not listed. Not found in the feed is not interpreted as safe.

## 13. Website Verification

Verified locally on `http://127.0.0.1:8000`:

- Frontend root returned HTTP 200 in the browser
- API docs `/docs` returned HTTP 200
- Health API returned ok / XGBoost
- Dashboard API returned scan statistics and stored history
- Prediction API worked for a long Google Forms URL: Low Risk, risk score 22
- Prediction API worked for an Amazon tracking/search URL that previously exposed a domain-feed false positive: Low Risk, risk score 22
- Prediction API worked for fake Google login, punycode, encoded, and shortened suspicious URLs: Phishing, risk score 100
- Localhost/private-network/file URL inputs returned HTTP 400 instead of being scanned
- Browser UI scanner submitted a phishing URL and a long Google Forms URL successfully
- Browser console errors during the checked flows: 0
- Backend and frontend tests: 25 passed
- Frontend production build passed

Warnings observed:

- Vite reports a large JS chunk warning because the UI includes charting and animation libraries; build passed.

## 14. Remaining Limitations

- The model cannot guarantee that a URL is safe. It performs URL-level risk analysis only.
- Some phishing URLs hosted on reputable platforms can still be difficult because the domain itself may be legitimate.
- Some clean-looking phishing domains are still missed, especially short HTTPS domains with few lexical warning signs.
- WHOIS/DNS intelligence is optional and disabled by default for speed.
- PhishTank, UCI, and Kaggle data were not included in this specific final training run because local files/API access were not available.
- The raw XGBoost model still uses path/slash structure heavily, although less severely than before.

## 15. Rollback

Improved project folder:

```text
C:\FYP2_ProjectCode
```

Backup folder:

```text
C:\phishing_detection_backup_before_final_improvement_20260901_111956
```

To restore by folder copy:

1. Close the running server.
2. Rename `C:\FYP2_ProjectCode` to something like `C:\FYP2_ProjectCode_final_attempt`.
3. Copy `C:\phishing_detection_backup_before_final_improvement_20260901_111956` to `C:\FYP2_ProjectCode`.
4. Run:

```powershell
cd C:\FYP2_ProjectCode
$env:PYTHONPATH=(Get-Location).Path
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

To restore through Git to the pre-final checkpoint inside the improved folder:

```powershell
cd C:\FYP2_ProjectCode
git reset --hard 2e8fc88
```

Use the Git command only if you intentionally want to discard the final improvement changes.

---

## 16. Targeted Retrain Update - 2026-09-06

A targeted retrain was performed after external validation found excessive false positives on legitimate long documentation, university, and payment-related URLs, plus several missed phishing samples.

### Backup Before Targeted Retrain

The model artifacts were backed up before retraining:

```text
C:\phishguard_model_backup_before_targeted_retrain_20260906_221050
```

The backup contains the previous `xgboost_model.joblib`, `scaler.joblib`, `feature_columns.joblib`, `metrics.json`, and `error_analysis.json` files.

### Targeted Data Added

Additional training files were created from the previous external validation errors:

- `backend/ml/data/targeted_hard_negatives.csv`: 542 legitimate hard-negative URLs
- `backend/ml/data/targeted_missed_phishing.csv`: 20 missed phishing URLs

These files are kept in the local project folder for submission/retraining, but raw dataset CSV files remain ignored by Git because they may contain live phishing URLs and can be large.

### Retrained Model

The XGBoost model was retrained with the existing architecture and feature pipeline preserved.

Training command:

```powershell
python -m backend.ml.train --balance --cv-folds 3
```

Saved artifacts:

```text
backend/ml/artifacts/xgboost_model.joblib
backend/ml/artifacts/scaler.joblib
backend/ml/artifacts/feature_columns.joblib
backend/ml/artifacts/metrics.json
```

Updated training sources recorded in `metrics.json`:

- Phishing.Database: 789,052 rows
- OpenPhish: 300 rows
- Legitimate URL dataset: 200,000 rows
- Legitimate hard-negative URL set: 37 rows
- Targeted external hard-negative URL set: 542 rows
- Targeted missed phishing URL set: 20 rows

Data cleaning/balancing summary:

- Raw rows: 989,951
- Rows after cleaning: 989,085
- Exact duplicate URLs removed: 10
- Normalized duplicate URLs removed: 854
- Conflicting normalized URLs removed: 1
- Balanced final dataset size: 401,136
- Legitimate: 200,568
- Phishing: 200,568

Split:

- Method: hostname-grouped 70:15:15 split with stratified group labels
- Random seed: 42
- Training size: 280,731
- Validation size: 59,253
- Final test size: 61,152
- Train/validation/test hostname overlap: 0

Selected threshold:

```text
0.35
```

Validation metrics at selected threshold:

- Accuracy: 0.939750
- Precision: 0.944966
- Recall: 0.931444
- F1-score: 0.938156
- False Positive Rate: 0.052250
- False Negative Rate: 0.068556
- Confusion matrix: [[28605, 1577], [1993, 27078]]

Final internal test metrics:

- Accuracy: 0.945529
- Precision: 0.952603
- Recall: 0.939508
- F1-score: 0.946010
- False Positive Rate: 0.048255
- False Negative Rate: 0.060492
- ROC-AUC: 0.985022
- PR-AUC: 0.988220
- Confusion matrix: [[28638, 1452], [1879, 29183]]

Top feature importance after retraining:

1. `path_length`: 0.500350
2. `count_slash`: 0.178577
3. `has_https`: 0.063862
4. `has_suspicious_tld`: 0.029809
5. `special_char_ratio`: 0.027446

`path_length` remains the strongest feature, so URL path structure still has a large effect on the model.

### Fresh Unseen External Test After Retraining

A fresh offset external test was created after retraining. It did not reuse the same external URLs used to create the targeted supplemental training files.

External test summary:

- Final external test size: 904
- Legitimate external URLs: 672
- Phishing external URLs: 232
- Accuracy: 0.540929
- Precision: 0.358578
- Recall: 1.000000
- F1-score: 0.527873
- False Positive Rate: 0.617560
- False Negative Rate: 0.000000
- ROC-AUC: 0.943776
- PR-AUC: 0.765282
- Confusion matrix: [[257, 415], [0, 232]]
- API errors: 0
- Average latency: 141.52 ms

External legitimate breakdown:

- Google Forms: 12 tested, 12 correct, 0 false positives
- Google account: 1 tested, 1 correct, 0 false positives
- Dropbox: 89 tested, 89 correct, 0 false positives
- E-commerce long-path cases: 62 tested, 62 correct, 0 false positives
- Long-path category: 89 tested, 89 correct, 0 false positives
- Payment category: 91 tested, 90 false positives
- Sitemap deep URL category: 242 tested, 241 false positives
- University category: 84 tested, 84 false positives

External phishing breakdown:

- Brand spoofing: 46 tested, 46 detected
- Credential harvesting: 12 tested, 12 detected
- Encoded/obfuscated: 3 tested, 3 detected
- Punycode: 2 tested, 2 detected
- Standard phishing: 145 tested, 145 detected
- Suspicious subdomain: 24 tested, 24 detected

### Interpretation

The targeted retrain improved phishing recall on the fresh external test, with no missed phishing URLs in that test set. It also continued to correctly handle the long Google Forms issue.

However, the fresh external test still shows a serious false-positive weakness on legitimate documentation/university/payment-style pages, especially URLs from Stripe Docs, PostgreSQL, Harvard, AWS Docs, FastAPI, and IRS sitemap samples. This means the current model is not yet strong enough to claim robust real-world generalization across all legitimate long structured URLs.

The smallest next improvement should not be another broad architecture redesign. The next focused fix should be to add more diverse hard-negative legitimate examples from the failing categories and re-evaluate threshold/context handling, while preserving the XGBoost pipeline and avoiding any trusted-domain automatic whitelist.

---

## 17. Final Focused Retrain Update - 2026-09-07

This was the final focused retraining cycle to reduce the 61.76% external false-positive rate while preserving strong phishing recall. The frontend, backend architecture, threat-feed design, and XGBoost primary prediction engine were preserved.

### Backup Before Final Retrain

Current model artifacts were backed up before retraining:

```text
C:\phishguard_model_backup_before_final_retrain_20260906_234341
```

Git checkpoint before this final cycle:

```text
e9f9f52 Retrain model with targeted external samples
```

### Root Cause Confirmed

The 61.76% external FPR was caused mainly by legitimate HTTPS documentation, university, government, and payment/developer URLs whose hostnames were not represented by contextual features. They had deep paths, many slashes/hyphens, and documentation/news-style structure, so the XGBoost model over-weighted path and URL structure. Median external false-positive `path_length` was 27 and median `count_slash` was 5, with no IP, punycode, suspicious TLD, brand impersonation, or obfuscation flags in the median case.

### Data Added

A broader real legitimate hard-negative dataset was collected from public sitemaps and added locally:

```text
backend/ml/data/broad_legitimate_hard_negatives.csv
```

Broad hard-negative dataset quality:

- Rows: 8,702
- Unique hostnames: 20
- Categories: 6
- Technical documentation: 2,700
- Cloud/developer: 2,221
- Government: 1,350
- University: 1,081
- Payment/fintech: 900
- E-commerce: 450
- Median URL length: 68
- Maximum URL length: 330
- Deep-path URLs: 80.96%
- Documentation-context URLs: 46.21%
- Education/government URLs: 27.94%

The collector excluded exact normalized overlaps with existing project CSVs and previous external validation files where practical.

### Feature Changes

Feature count increased from 69 to 73.

Added contextual features:

- `shared_hosting_domain`
- `documentation_hostname_context`
- `education_or_government_domain`
- `safe_structured_context`

Shared-hosting handling was corrected so user-controlled platforms such as `github.io`, `pages.dev`, `netlify.app`, and `vercel.app` are neutral/weak context rather than strong known-platform safe evidence. A `paypal-login-alert.github.io` style URL is no longer treated as first-party GitHub context.

No automatic trusted-domain whitelist was added.

### Final XGBoost Training

Training command:

```powershell
python -m backend.ml.train --balance --cv-folds 3
```

Training sources:

- Phishing.Database: 789,052 rows
- OpenPhish: 300 rows
- Legitimate URL dataset: 200,000 rows
- Legitimate hard-negative URL set: 37 rows
- Broad legitimate hard-negative URL set: 8,702 rows
- Targeted external hard-negative URL set: 542 rows
- Targeted missed phishing URL set: 20 rows

Dataset summary:

- Raw rows: 998,653
- Rows after cleaning: 997,787
- Balanced final dataset: 418,540
- Legitimate: 209,270
- Phishing: 209,270
- Exact duplicate URLs removed: 10
- Normalized duplicate URLs removed: 854
- Conflicting normalized URLs removed: 1

Split:

- Method: hostname-grouped 70:15:15 split with stratified group labels
- Random seed: 42
- Training size: 295,441
- Validation size: 62,868
- Final internal test size: 60,231
- Train/validation/test hostname overlap: 0

### Threshold

The selected threshold is:

```text
0.48
```

It was selected using validation data only, preferring recall >= 0.92 with false-positive rate <= 0.03 and strongest precision.

Validation metrics at threshold 0.48:

- Accuracy: 0.949625
- Precision: 0.979314
- Recall: 0.920154
- F1-score: 0.948813
- False Positive Rate: 0.020020
- False Negative Rate: 0.079846
- Confusion matrix: [[30349, 620], [2547, 29352]]

### Internal Test Metrics

Final internal test metrics at threshold 0.48:

- Accuracy: 0.942970
- Precision: 0.976079
- Recall: 0.908307
- F1-score: 0.940974
- False Positive Rate: 0.022302
- False Negative Rate: 0.091693
- ROC-AUC: 0.982870
- PR-AUC: 0.986487
- Confusion matrix: [[29416, 671], [2764, 27380]]

### Final External Validation

A balanced final external validation was run through the production FastAPI prediction pipeline after retraining.

Overlap handling:

- Excluded existing project training CSV URLs.
- Excluded previous external validation candidate/result URLs for phishing candidates.
- Blocked overlap set size: 999,493 normalized URLs.

Final external test:

- Total: 890
- Legitimate: 390
- Phishing: 500
- Accuracy: 0.957303
- Precision: 0.930970
- Recall: 0.998000
- F1-score: 0.963320
- False Positive Rate: 0.094872
- False Negative Rate: 0.002000
- ROC-AUC: 0.999687
- PR-AUC: 0.999783
- Confusion matrix: [[353, 37], [1, 499]]

Legitimate category results:

- Dropbox: 90 tested, 0 false positives, FPR 0.00%
- Long path: 100 tested, 11 false positives, FPR 11.00%
- Payment: 60 tested, 1 false positive, FPR 1.67%
- Sitemap/deep URL: 140 tested, 25 false positives, FPR 17.86%

Phishing category results:

- Brand spoofing: 44 tested, 43 detected, recall 97.73%
- Credential harvesting: 6 tested, 6 detected, recall 100.00%
- IP-host phishing: 120 tested, 120 detected, recall 100.00%
- Shared-hosting phishing: 66 tested, 66 detected, recall 100.00%
- Shortened phishing: 24 tested, 24 detected, recall 100.00%
- Standard phishing: 120 tested, 120 detected, recall 100.00%
- Suspicious subdomain: 120 tested, 120 detected, recall 100.00%

Google Forms remained correctly handled in the external legitimate validation: 12 tested, 12 correct, 0 false positives in the preceding final legitimate-only external run.

### Remaining Limitations

The final external FPR improved from 61.76% to 9.49%, which meets the practical target of below 10%. However, long PostgreSQL-style news/documentation URLs still account for most remaining false positives. One phishing URL in the final external set was missed: a Google Docs published-document phishing URL with low model probability.

Verdict: MOSTLY READY - ONLY SMALL FIXES REMAIN.
