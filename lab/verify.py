"""Check apimtk inventory output against what lab/seed.bicep planted.

  python lab/verify.py --phase before --out out/lab
  python lab/verify.py --phase after  --out out/lab

Exit code 0 = every expectation met.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def find(inv, prefix):
    for d in inv:
        if d["instance"]["name"].startswith(prefix):
            return d
    sys.exit(f"instance {prefix}* not found in inventory.json - did seed.bicep finish?")


def has(d, area, item=None, sev=None):
    return any(f["area"] == area and (item is None or f["item"] == item) and (sev is None or f["severity"] == sev)
               for f in d["findings"])


def nv_type(d, name):
    return next((n["type"] for n in d["namedValues"] if n["displayName"] == name), "") or ""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--phase", choices=["before", "after"], required=True)
    p.add_argument("--out", type=Path, default=Path("out/lab"))
    p.add_argument("--prefix", default="apimtk")
    a = p.parse_args()

    assess = json.loads((a.out / "assess.json").read_text())
    inv = json.loads((a.out / "inventory.json").read_text())
    A, B = find(inv, f"{a.prefix}-lab-a"), find(inv, f"{a.prefix}-lab-b")

    checks: list[tuple[str, bool]] = [
        ("assess: both lab instances are Classic",
         all(r["classic"] for r in assess if r["name"].startswith(f"{a.prefix}-lab"))),
        ("A: embedding-api-key flagged as clear-text key", nv_type(A, "embedding-api-key").startswith("Plain value (looks")),
        ("A: tenant-id NOT flagged", nv_type(A, "tenant-id") == "Plain value"),
        ("A: backend-url NOT flagged", nv_type(A, "backend-url") == "Plain value"),
        ("A: llm-api-key is a Key Vault reference", nv_type(A, "llm-api-key") == "KeyVault"),
        ("A: all-access subscription flagged", has(A, "Subscription keys", "Built-in all-access subscription")),
        ("B: both secrets stored in APIM", B["secretsInApim"] == 2),
        ("no secret values stored in inventory.json", all("value" not in n for d in inv for n in d["namedValues"])),
    ]
    if a.phase == "before":
        checks += [
            ("A: gpt-api-key is a secret stored in APIM", nv_type(A, "gpt-api-key") == "Secret (stored in APIM)"),
            ("A: gpt-api-key used by backend aoai",
             any(n["displayName"] == "gpt-api-key" and "backend:aoai" in n.get("usedBy", "") for n in A["namedValues"])),
            ("A: direct management API enabled (High)", has(A, "Management plane", "tenant/access", "High")),
            ("A: portal sign-up enabled", has(A, "Developer portal")),
            ("A: ai-lab product without approval", has(A, "Products", "ai-lab")),
            ("B: no managed identity", has(B, "Identity")),
        ]
    else:
        checks += [
            ("A: gpt-api-key now a Key Vault reference", nv_type(A, "gpt-api-key") == "KeyVault"),
            ("A: direct management API disabled", not has(A, "Management plane", "tenant/access", "High")),
            ("A: portal sign-up disabled", not has(A, "Developer portal")),
            ("B: managed identity enabled", not has(B, "Identity")),
        ]

    ok = True
    for name, passed in checks:
        ok &= bool(passed)
        print(f"  {'PASS' if passed else 'FAIL'}  {name}")
    print(f"\n{'ALL PASSED' if ok else 'SOME CHECKS FAILED'} ({a.phase})")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
