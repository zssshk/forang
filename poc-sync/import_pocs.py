#!/usr/bin/env python3
"""poc-collection README -> FORANG PoC 库 增量导入（幂等）。

解析 README 的目录表格（| 目录 | 描述 | 上游 |），按 CVE 去重后调
POST /api/pocs 建条目。已有条目（cve 命中，cve 空则 title 命中）跳过。

用法: python3 import_pocs.py <repo_dir> <forang_base> <token_file>
"""
import json
import os
import re
import sys
import urllib.request

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
GATE_COOKIE = "/tmp/forang.gate"


def cvss_to_severity(desc):
    m = re.search(r"CVSS\s*([0-9]+(?:\.[0-9])?)", desc)
    if not m:
        return ""
    score = float(m.group(1))
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def parse_rows(readme_path):
    rows = []
    for line in open(readme_path, encoding="utf-8"):
        line = line.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0] in ("", "目录"):
            continue
        d = cells[0].strip("`* ")
        if d.startswith("-") or d.lower() in ("---", ":---"):
            continue
        desc = cells[1]
        src = cells[2]
        rows.append((d, desc, src))
    return rows


def entry_from_row(d, desc, src):
    m = CVE_RE.search(desc) or CVE_RE.search(d)
    cve = m.group(0).upper() if m else ""
    title = re.sub(r"^\s*[-*]+\s*|\*\*|`", "", desc).strip()
    cut = title.find("；")
    if cut > 10:
        title = title[:cut]
    if len(title) > 100:
        title = title[:97] + "..."
    component = d
    dm = re.match(r"(?i)cve-\d{4}-\d+[-.]?(.*)", d)
    if dm and dm.group(1):
        component = dm.group(1).replace("-", " ")
    elif not m:
        component = d
    return {
        "title": title,
        "component": component,
        "cve": cve,
        "severity": cvss_to_severity(desc),
        "template": "",
        "source": src if src.startswith("http") else "",
        "_dir": d,
    }


def api(base, path, token, method="GET", body=None):
    hdrs = {"Authorization": "Bearer " + token,
            "Content-Type": "application/json"}
    # gate 开启时 gateMiddleware 在最外层，无 cookie 一律裸 404（与路由不存在无法区分）。
    # cookie 值由 poc-sync.sh 用 jwt.key + gate.token 复算后写入 GATE_COOKIE 文件。
    if GATE_COOKIE and os.path.exists(GATE_COOKIE):
        val = open(GATE_COOKIE, encoding="utf-8").read().strip()
        if val:
            hdrs["Cookie"] = "artex-gate=" + val
    req = urllib.request.Request(base + path, method=method,
                                 data=json.dumps(body).encode() if body else None,
                                 headers=hdrs)
    return json.load(urllib.request.urlopen(req, timeout=30))


def main():
    repo, base, token_file = sys.argv[1], sys.argv[2], sys.argv[3]
    token = open(token_file).read().strip()
    entries = [entry_from_row(*r) for r in parse_rows(os.path.join(repo, "README.md"))]
    if not entries:
        raise SystemExit("README 未解析出条目")

    existing = api(base, "/api/pocs", token).get("pocs", [])
    have = set()
    for p in existing:
        if p.get("cve"):
            have.add(p["cve"].upper())
        have.add("t:" + p.get("title", ""))

    created = skipped = 0
    for e in entries:
        key = e["cve"] or "t:" + e["title"]
        if key in have:
            skipped += 1
            continue
        payload = {k: v for k, v in e.items() if not k.startswith("_")}
        api(base, "/api/pocs", token, method="POST", body=payload)
        have.add(key)
        created += 1
        print("+ %s %s" % (e["cve"] or "-", e["title"][:60]))
    print("导入 %d，跳过 %d（库共 %d）" % (created, skipped, len(existing)))


if __name__ == "__main__":
    main()
