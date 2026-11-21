# waf-modsecurity-lab: ModSecurity v3 & OWASP CRS Paranoia Level Evaluation Lab

**Problem:** Security teams deploying the **OWASP Core Rule Set (CRS)** behind Nginx/ModSecurity must balance attack detection against false positives on legitimate user input. Switching from **Paranoia Level 1 (`configs/pl1.conf`)** to **Paranoia Level 3 (`configs/pl3.conf`)** catches obfuscated injection vectors (such as URL-encoded boolean operator chains `10%26%261%3D%3D1`), but also triggers strict metacharacter rules (`942430`/`942431`) on benign names (`O'Connor & Sons`) and math expressions unless scoped exclusions (`configs/custom_exclusions.conf`) are applied.

## Architecture Diagram

```text
+--------------------------------------------------------------------------+
| Test Harness: tests/waf_eval.py (20 Attack Payloads + 5 Benign Requests) |
+------------------------------------+-------------------------------------+
                                     |
                                     | HTTP localhost:8080
                                     v
+--------------------------------------------------------------------------+
| Frontend Proxy: Nginx + ModSecurity v3 + OWASP CRS                       |
|   - Mode A: make up-pl1  --> configs/pl1.conf (Paranoia Level 1)         |
|   - Mode B: make up-pl3  --> configs/pl3.conf (Paranoia Level 3)         |
|   - Tuning: configs/custom_exclusions.conf (ctl:ruleRemoveTargetById)    |
+------------------------------------+-------------------------------------+
                                     |
                                     | Internal Docker Bridge (waf_internal)
                                     v
+--------------------------------------------------------------------------+
| Backend Application: waf-lab-backend (172.29.0.10:5000 - Not Exposed)    |
+--------------------------------------------------------------------------+
```

## Summary Metrics (`reports/evaluation_results.md`)

| Metric | CRS Paranoia Level 1 (`pl1.conf`) | CRS Paranoia Level 3 (`pl3.conf`) | Technical Takeaway |
|---|---|---|---|
| **Attack Payloads Tested** | 20 | 20 | 5 SQLi, 4 XSS, 4 LFI, 4 CMDi, 2 SSRF, 1 Obfuscated Boolean |
| **Attacks Blocked (HTTP 403)** | `19 / 20` (**95.0%**) | **`20 / 20` (100.0%)** | PL3 blocks obfuscated boolean `10&&1==1` (`ATK-20`) missed by PL1 |
| **Benign Requests Tested** | 5 | 5 | Normal queries + apostrophes (`O'Connor`) + math symbols |
| **False Positives (Benign Blocked)** | **`0 / 5` (0.0%)** | `2 / 5` (**40.0%** on untuned `/profile` & `/note`) | `/api/feedback` (`BEN-05`) passes at PL3 thanks to `configs/custom_exclusions.conf` |

## Visual Proof

![waf-eval](docs/screenshots/01_waf_pl1_vs_pl3.png)

Full generated report: [reports/evaluation_results.md](reports/evaluation_results.md)

## Quick Start & Makefile Usage

```bash
# Start WAF with Paranoia Level 1 or Paranoia Level 3
make up-pl1
make up-pl3

# Run 25-request evaluation and generate reports/evaluation_results.md
make eval

# Tear down containers
make down
```
