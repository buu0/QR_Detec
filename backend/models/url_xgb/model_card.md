# Model Card: QRDetec URL XGBoost (qrdetec-url-xgb), bundle v3 (scheme-invariant)

- **Trained at:** 2026-10-27T01:34:39.220323+00:00
- **Task:** binary malicious-URL risk scoring from the URL string only (no target fetching)
- **Features:** 81-feature schema; the 4 scheme indicators (scheme_is_https, scheme_is_http, scheme_is_other, scheme_missing) are constant during training and unused by the trees; train/val URLs duplicated with the opposite scheme
- **Split:** domain-disjoint 60/15/10/15 (train 54,943 / val 13,397 / calib 9,174 / test 14,492; 60,836 eTLD+1 groups)
- **Training:** early stopping on val (log-loss, 50 rounds); best_iteration = 675; 726 rounds stored
- **Calibration:** plain isotonic regression on calib (96 knots), no manual edits
- **Operating threshold:** 0.597483, selected on calibrated val scores (max recall s.t. FPR <= 5%)

## Test partition (14,492 URLs, unseen registrable domains)
- Recall 0.8080 (95% CI [0.7975, 0.8182]), Precision 0.9380 (95% CI [0.9308, 0.9445])
- FPR 0.0334 (95% CI [0.0299, 0.0374]), F1 0.8682, ROC-AUC 0.9598, PR-AUC 0.9461
- ECE 0.0046, Brier 0.0703

## Validation partition
- Recall 0.8463, FPR 0.0427, F1 0.8923

## Known limitations
- Static, non-chronological benchmark; malicious class mixes phishing and malware-distribution URLs.
- Labels come from public feeds; performance on URLs decoded from real QR codes has not been measured.
