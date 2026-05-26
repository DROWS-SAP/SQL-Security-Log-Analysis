# 🔍 Relational Database Analysis: SQL Security Log Triage
## 📊 Investigation Overview
```yaml
Target Database:     Enterprise Log Schema (`log_in_attempts`, `employees`)
Objective:           Investigate Unauthorized Authentications & Machine Audits
Query Language:      SQL (Structured Query Language)
Analytical Filters:  Conditional Operators (AND, OR, NOT), Pattern Matching (LIKE)
```
## 📝 1. Executive Summary
 * **Scenario:** The Security Operations Center (SOC) identified multiple operational anomalies involving unauthorized after-hours login attempts and potential endpoint non-compliance.
 * **Action Taken:** Executed a series of structured SQL queries against core relational database tables to isolate suspicious authentication timestamps, identify rogue localized source patterns, and audit cross-departmental workstation distributions.
 * **Impact:** Extracted explicit actionable indicators (employee IDs and machine groups) required for system patching and forensic containment, demonstrating database visibility capabilities.
## 🛠️ 2. Targeted Database Queries & Log Investigations
### Triage 1: Isolating After-Hours Authentication Failures
**Objective:** Identify potential brute-force or unauthorized access attempts occurring outside standard business operations (after 18:00) that resulted in connection failures.
**SQL Query Syntax:**
```sql
SELECT employee_id, device_id, login_time, success
FROM log_in_attempts
WHERE login_time > '18:00' AND success = 0;
```
 * **Security Rationale:** Filtering for success = 0 (or FALSE) isolates failed attempts, while combining it with an iterative time restriction highlights high-risk out-of-hours anomalies that require immediate account auditing.
### Triage 2: Chronological Analysis of Suspicious Events
**Objective:** Extract all authentication metrics across a critical 48-hour window (2022-05-08 and 2022-05-09) to map attacker lateral movement or systemic exposure during a known breach window.
**SQL Query Syntax:**
```sql
SELECT *
FROM log_in_attempts
WHERE login_date = '2022-05-08' OR login_date = '2022-05-09';
```
 * **Security Rationale:** Utilizing the OR conditional operator enables the collection of adjacent logging dates, ensuring full visibility into multi-day attack timelines without splitting the dataset.
### Triage 3: Perimeter Reconnaissance Detection via Pattern Matching
**Objective:** Identify unauthorized off-site or rogue localized logins originating from a specific suspected network infrastructure area (the "East" office facility).
**SQL Query Syntax:**
```sql
SELECT *
FROM employees
WHERE office LIKE 'East%';
```
 * **Security Rationale:** Implementing the LIKE operator alongside the wildcard character (%) allows the query to parse and return all variations of the target location (e.g., East-170, East-320), successfully auditing geographic access consistency.
### Triage 4: Auditing Departmental Software Exposures
**Objective:** Generate targeted machine lists for critical software updates restricted to specific high-risk corporate groups (Sales and Finance), as well as broad baseline updates for all groups excluding IT.
**Query A (Sales/Finance Segment):**
```sql
SELECT *
FROM employees
WHERE department = 'Sales' OR department = 'Finance';
```
**Query B (Non-IT Global Audit):**
```sql
SELECT *
FROM employees
WHERE NOT department = 'Information Technology';
```
 * **Security Rationale:** Using the NOT filter effectively isolates unpatched endpoints across peripheral organizational structures while safely omitting engineering machines that have already received automated administrative updates.
## 📈 3. Analytical Capabilities Matrix
The investigation successfully demonstrated proficiency across core security data manipulation tasks:

| Target Vector | SQL Operator Employed | Security Triage Utility |
| :--- | :--- | :--- |
| Temporal Outliers | > / < Comparison | Isolates traffic outside operational baselines. |
| Logic Intersections | AND / OR | Cross-references multiple indicators of compromise (IoCs). |
| Schema Exclusion | NOT | Segments compliant assets from remediation queues. |
| String Parsing | LIKE + % Wildcard | Maps loose or obfuscated layout trends across assets. |

### 🛡️ Hardening & Optimization Recommendations:
To scale database analysis, the analyst recommends establishing **Structured Views** for high-risk access logs and implementing parameterized query functions to prevent potential SQL injection (SQLi) vectors during manual forensic triage operations.
