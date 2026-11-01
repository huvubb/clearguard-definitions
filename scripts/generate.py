#!/usr/bin/env python3
"""
Generate ClearGuard virus definition data from upstream open-source IOC sources.

Each source entry points to a directory in a public repo that contains a
``samples.sha256`` file listing known-malicious file hashes.  We only collect
hash lines from files explicitly named ``samples.sha256`` (never scrape hashes
out of prose or documentation), normalize to lowercase hex, dedupe, and emit
one JSON object per line.

Usage:
    python3 scripts/generate.py --out data/

Output:
    data/apk-sha256.jsonl   one record per line:
        {"hash": "<sha256_hex>", "family": "<dir_name>",
         "source": "<repo>", "source_commit": "<sha>", "platform": "android"}
    data/manifest.json       version, generated_at, count, data_sha256
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.request
import ssl

# ---------------------------------------------------------------------------
# Source registry.  Each entry is an Android-relevant malware family whose
# samples.sha256 lists known-malicious APK hashes.
# upstream_commit is the expected commit SHA at generation time; if the repo
# moves, the script fetches the master branch head and records that instead.
# ---------------------------------------------------------------------------
SOURCES = [
    {
        "repo": "ESET/malware-ioc",
        "branch": "master",
        "license": "BSD-2-Clause",
        "platform": "android",
        "families": [
            "ghostchat",
            "aridspy",
            "vajraspy",
            "promptspy",
            "ngate",
            "gref",
            "gravityrat",
            "evilvideo",
            "hamkombat",
        ],
    },
]

RAW_BASE = "https://raw.githubusercontent.com/{repo}/{branch}/{family}/samples.sha256"
API_HEAD = "https://api.github.com/repos/{repo}/commits/{branch}"


def fetch(url: str) -> str:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "clearguard-definitions/1.0"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return r.read().decode("utf-8", errors="replace")


def get_commit(repo: str, branch: str) -> str:
    try:
        data = json.loads(fetch(API_HEAD.format(repo=repo, branch=branch)))
        return data.get("sha", "")
    except Exception:
        return branch  # fallback: record branch name instead


def parse_sha256(text: str):
    """Yield valid 64-char hex SHA-256 lines only."""
    for line in text.splitlines():
        h = line.strip().split()[0] if line.strip() else ""
        if len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
            yield h.lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    records = {}  # hash -> record (dedupe across sources)
    for src in SOURCES:
        commit = get_commit(src["repo"], src["branch"])
        for family in src["families"]:
            url = RAW_BASE.format(repo=src["repo"], branch=src["branch"], family=family)
            try:
                text = fetch(url)
            except Exception as e:
                print(f"WARN  {family}: {e}", file=sys.stderr)
                continue
            n = 0
            for h in parse_sha256(text):
                if h not in records:
                    records[h] = {
                        "hash": h,
                        "family": family,
                        "source": src["repo"],
                        "source_commit": commit,
                        "platform": src["platform"],
                    }
                    n += 1
            print(f"OK    {family}: +{n} hashes (total unique: {len(records)})")

    # sort by hash for deterministic output
    out_path = os.path.join(args.out, "apk-sha256.jsonl")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        for h in sorted(records):
            f.write(json.dumps(records[h], separators=(",", ":")) + "\n")

    data_sha = hashlib.sha256(open(out_path, "rb").read()).hexdigest()
    manifest = {
        "version": "1.0.0",
        "format": "apk-sha256-jsonl",
        "generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(records),
        "data_sha256": data_sha,
        "sources": [
            {
                "repo": s["repo"],
                "license": s["license"],
                "commit": get_commit(s["repo"], s["branch"]),
                "families": s["families"],
            }
            for s in SOURCES
        ],
    }
    with open(os.path.join(args.out, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"\nWrote {out_path} ({len(records)} hashes)")
    print(f"Manifest: data/manifest.json  sha256={data_sha}")


if __name__ == "__main__":
    main()
