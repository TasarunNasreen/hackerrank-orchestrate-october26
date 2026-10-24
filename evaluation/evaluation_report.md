# Evaluation report

## Scope and method

The evaluator ran locally with participant-facing files only. It generated predictions for all 32 rows in `dataset/sample_deletion_requests.csv`, matched them by `case_id` to `dataset/sample_output.csv`, and parsed the actual schema `case_id,deletion_status,steps_json`. It also validated the generated root `output.csv` against all 518 rows in `dataset/deletion_requests.csv`.

## Public sample metrics

| Metric | Result |
| --- | ---: |
| Cases evaluated | 32 |
| Case-level status accuracy | 23 / 32 = 71.875% |
| Row-level exact match | 0 / 32 = 0% |
| Step-level accuracy | 12 / 331 = 3.625% |
| Field-level accuracy | 537 / 2,317 = 23.177% |
| Sequence accuracy | 0 / 32 = 0% |

Step accuracy counts equal step objects at the same position; field accuracy compares the seven required fields for aligned steps. Exact row and sequence comparisons include array order.

## Contract and evidence diagnostics

- Root `output.csv`: 518 data rows, exact header, valid JSON arrays, allowed statuses and operations, consecutive step numbers, and valid evidence references.
- Invalid evidence references: 0.
- Unsupported evidence references in predictions: 0.
- Evidence files unreadable: 11 PNG files because local Tesseract tooling is unavailable.
- Evidence captured after a case's `audit_at` used in a cited step: 0.
- Authorized sample cases with unresolved identity: 0.
- Conflicting-evidence markers: 0.
- Public cases whose expected status differs from the reported workflow claim: 22. Workflow claims were not used as proof.

## Synthetic evaluation cases

These cases are implemented in `code/evaluation/main.py` and are not written to `output.csv`:

1. **SYNTHETIC_UNAUTHORIZED_DELETION**: a login-reset request explicitly says not to close the account; expected result is non-deletion handling.
2. **SYNTHETIC_SURVIVING_REPLICA_BACKUP**: a present account record plus an active backup requires an incomplete result, a remaining-record finding, a restore-risk finding, and a `BLOCK_RESTORE` action.
3. **SYNTHETIC_LATER_SYNC_RESTORE_RISK**: an active data flow requires an active-flow finding followed by `DISABLE_DATA_FLOW` and future verification.

All three synthetic cases passed.

## Failures and improvements

The first public-sample run exposed two demonstrated bugs: English-only deletion-intent detection and broad resource extraction from dense evidence documents. The implementation added observed multilingual deletion markers and limited resource extraction to IDs near the matched identifier. Public status accuracy improved from 59.375% to 71.875%, and the final evaluator completed with zero invalid evidence references.

The remaining low step and sequence scores show that evidence-to-resource association and policy reconstruction are not yet fully accurate. Image OCR remains unavailable, and the evaluator does not claim hidden-test accuracy.
