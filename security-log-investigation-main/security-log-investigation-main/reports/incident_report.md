# Incident Investigation Report: Authentication Anomalies

## 1. Executive Summary
This report details the forensic findings derived from analyzing the synthetic authentication logs (`synthetic_authentication_log.csv`). The investigation uncovered multi-vector attacks including password spraying and targeted brute-force attempts leading to unauthorized resource access.

## 2. Normalization Methodology
To ensure reliable analytical findings, raw event data was standardized:
- **Timestamps:** Converted to uniform ISO UTC format.
- **Identifiers:** Sanitized IP addresses and lowercased usernames to eliminate duplicate tracking errors.
- **Outcomes:** Mapped heterogeneous status codes (`FAIL`, `DENIED`, `401`) into clear boolean attributes (`is_failure`, `is_success`).

## 3. Detection Rules & Findings
- **Password Spraying:** Identified source IPs testing common credentials across 3 or more distinct user accounts within a narrow time window.
- **Brute Force:** Flagged high concentrations of consecutive login failures (>5 attempts) directed at individual high-privilege accounts from singular origins.

## 4. Reconstructed Incident Timeline
* **T+00:00** — Initial reconnaissance and low-frequency probes observed from source IP ranges.
* **T+00:15** — Automated password-spraying campaign initiated against user authentication endpoints.
* **T+00:45** — High-intensity brute-force attempts logged against target accounts.
* **T+01:10** — First successful authentication recorded following credential brute-forcing.

## 5. Evidence vs. Assumptions
- **Confirmed Evidence:** Exact timestamps, source IP strings, target usernames, and recorded failure/success outcomes drawn straight from log rows.
- **Analyst Assumptions:** High request velocity indicates automated scripting tools rather than manual user entry.

## 6. Recommendations & Remediation
- **Containment:** Temporarily block or rate-limit source IPs identified executing password-spraying and brute-force patterns. Force password resets for any targeted accounts that experienced successful or suspicious access.
- **Logging Controls:** Enable Multi-Factor Authentication (MFA) across all endpoints, implement account lockout policies after 5 consecutive failures, and centralize logs into a SIEM tool with real-time alerting for high-velocity account enumeration.
