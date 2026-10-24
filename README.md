# Ghost Data Still Exists

**HackerRank Orchestrate · October 2026**

A Python-based solution to the HackerRank Orchestrate challenge
*Ghost Data Still Exists*, focused on evaluating data-deletion
outcomes using available evidence, identity information, policy
logic, and remediation planning.

## Overview

Deleting data from one location does not necessarily mean that all
copies have been removed. Data may remain in backups, replicas,
logs, caches, or other systems.

This project processes challenge inputs and generates structured
predictions about deletion status, together with a sequence of
associated remediation steps.

The implementation uses a modular Python architecture to separate
input loading, evidence processing, identity analysis, policy
evaluation, auditing, planning, and output validation.

## Output Format

The solution generates `output.csv` using the required schema:

```csv
case_id,deletion_status,steps_json
