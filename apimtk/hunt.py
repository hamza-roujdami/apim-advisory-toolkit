"""03 - Hunt: run the KQL pack against a Log Analytics workspace.

The advisory's access path was on Microsoft's platform, so customer logs may
not show the read itself. The pack therefore also looks downstream: Key Vault,
service principal sign-ins, gateway sources and Foundry/AOAI usage.
"""
from __future__ import annotations

import csv
from pathlib import Path

import requests

from .arm import get_token

LA_SCOPE = "https://api.loganalytics.io/.default"
KQL_DIR = Path(__file__).resolve().parent.parent / "kql"


def render(text: str, params: dict[str, str]) -> str:
    for k, v in params.items():
        text = text.replace("{" + k + "}", v)
    return text


def query(workspace_id: str, kql: str, token: str) -> list[dict]:
    r = requests.post(f"https://api.loganalytics.io/v1/workspaces/{workspace_id}/query",
                      headers={"Authorization": f"Bearer {token}"}, json={"query": kql}, timeout=180)
    if r.status_code >= 400:
        raise RuntimeError(f"{r.status_code}: {r.text[:300]}")
    t = r.json()["tables"][0]
    cols = [c["name"] for c in t["columns"]]
    return [dict(zip(cols, row)) for row in t["rows"]]


def run(workspace_id: str | None, out_dir: Path, lookback: str, fix_date: str,
        app_ids: list[str], only: list[str] | None = None) -> list[dict]:
    params = {"lookback": lookback, "fix_date": fix_date,
              "app_ids": ", ".join(f'"{a}"' for a in app_ids) or '"00000000-0000-0000-0000-000000000000"'}
    out_dir.mkdir(parents=True, exist_ok=True)
    token = get_token(LA_SCOPE) if workspace_id else None
    summary = []
    for f in sorted(KQL_DIR.glob("*.kql")):
        if only and not any(o in f.name for o in only):
            continue
        kql = render(f.read_text(), params)
        (out_dir / f.name).write_text(kql)  # rendered copy for portal use
        entry = {"query": f.name, "rows": None, "error": None}
        if workspace_id:
            try:
                rows = query(workspace_id, kql, token)
                entry["rows"] = len(rows)
                if rows:
                    with open(out_dir / f"{f.stem}.csv", "w", newline="") as fh:
                        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                        w.writeheader()
                        w.writerows(rows)
            except Exception as e:  # table missing, no permission, etc.
                entry["error"] = str(e)[:200]
        summary.append(entry)
    return summary
