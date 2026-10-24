
# Ghost Data Still Exists

**HackerRank Orchestrate — October 2026**

A Python-based solution to the *Ghost Data Still Exists* challenge, focused on evaluating data-deletion outcomes using available evidence, identity information, policy logic, and remediation planning.

## Overview

Deleting data from one location does not necessarily mean that all copies have been removed. Data may remain in backups, replicas, logs, caches, or other systems.

This project processes challenge inputs and generates structured predictions about deletion status, together with a JSON-encoded sequence of associated remediation steps.

The implementation uses a modular Python architecture to separate input loading, evidence processing, identity analysis, policy evaluation, auditing, remediation planning, and output validation.

## Output Format

The solution generates `output.csv` using the required schema:

```csv
case_id,deletion_status,steps_json
```

Each row contains:

- **`case_id`** — Identifier of the challenge case.
- **`deletion_status`** — Predicted deletion status.
- **`steps_json`** — JSON-encoded sequence of steps associated with the case.

The output must follow the required schema and contain one prediction row per input case.

## Architecture

```text
Challenge Inputs
       |
       v
Input Loading
  code/loaders.py
       |
       v
Evidence Processing
  code/evidence.py
       |
       v
Identity Analysis
  code/identity.py
       |
       v
Policy Evaluation
  code/policy.py
       |
       v
Audit and Decision Logic
  code/audit.py
       |
       v
Remediation Planning
  code/planner.py
       |
       v
Output Generation
  code/main.py
       |
       v
Output Validation
  code/validate.py
       |
       v
output.csv
```

The diagram summarizes the intended responsibilities of the modules; the exact execution flow depends on the implementation.

## Project Structure

```text
hackerrank-orchestrate-october26/
├── README.md
├── output.csv
├── code.zip
├── log.txt
├── code/
│   ├── main.py
│   ├── loaders.py
│   ├── evidence.py
│   ├── identity.py
│   ├── audit.py
│   ├── policy.py
│   ├── planner.py
│   ├── validate.py
│   ├── test_prompt3.py
│   └── evaluation/
│       └── main.py
└── evaluation/
    ├── evaluation_report.md
    └── usage_report.md
```

*Note: This is the intended high-level layout. Actual file locations should be verified against the repository.*

## Key Components

| Module | Responsibility |
|---|---|
| `main.py` | Coordinates execution and output generation. |
| `loaders.py` | Loads and prepares challenge inputs. |
| `evidence.py` | Handles evidence-related processing. |
| `identity.py` | Handles identity-related analysis. |
| `audit.py` | Supports auditing and decision processing. |
| `policy.py` | Handles policy-related logic. |
| `planner.py` | Organizes remediation steps. |
| `validate.py` | Validates output structure and consistency. |

## Validation

The solution includes structural validation and testing intended to check:

- Required CSV header and column order.
- Expected output row count.
- Valid JSON in `steps_json`.
- Remediation-step structure and ordering.
- Evidence-reference validity, where applicable.
- Compliance with the challenge's output requirements.

Structural correctness and prediction accuracy are different. Valid output formatting does not guarantee correct predictions.

## Evaluation

The previously reported sample evaluation produced the following results:

| Metric | Result |
|---|---:|
| Deletion-status accuracy | 71.88% (23/32) |
| Exact row match | 0/32 |
| Step accuracy | 3.63% (12/331) |
| Field accuracy | 23.18% (537/2,317) |
| Sequence accuracy | 0/32 |
| Structural validation | 12/12 checks passed |

These figures represent the reported sample evaluation, not an official HackerRank score or leaderboard ranking.

The results indicate that remediation-step generation, semantic correctness, and exact prediction matching remain areas for improvement.

## Testing and Future Improvements

Potential improvements include:

1. Analyzing incorrect predictions individually.
2. Improving evidence interpretation.
3. Strengthening identity-resolution logic.
4. Improving remediation-step completeness and ordering.
5. Adding regression tests for previously incorrect cases.
6. Re-running evaluations after changes to measure accuracy.

## Challenge Submission

The challenge submission artifacts are provided separately:

- `code.zip` — Solution source code.
- `output.csv` — Generated predictions.
- `log.txt` — AI-assisted development conversation transcript.

The challenge dataset and evidence files are excluded from the source-code archive.

## Acknowledgements

Developed for the HackerRank Orchestrate October 2026 challenge, *Ghost Data Still Exists*.

This README documents the implementation and reported sample evaluation. It does not claim an official challenge rank or score.

