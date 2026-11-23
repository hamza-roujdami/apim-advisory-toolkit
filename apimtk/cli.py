"""apimtk - APIM security advisory toolkit CLI."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import assess, hunt, inventory, remediate, report
from .arm import Arm

DEFAULT_TRACKING = "MZK9-GH0"


def _save(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, default=str))
    print(f"  wrote {path}")


def _load(path: Path):
    return json.loads(path.read_text())


def cmd_assess(a) -> list[dict]:
    rows = assess.run(Arm(), a.subscription, a.tracking_id)
    _save(rows, a.out / "assess.json")
    print(f"\n{'PRI':4} {'INSTANCE':40} {'SKU':12} {'CLASSIC':8} ADVISORY")
    for r in sorted(rows, key=lambda x: (x["priority"], x["name"])):
        print(f"{r['priority']:4} {r['name'][:40]:40} {r['sku']:12} {str(r['classic']):8} {r['inAdvisory']}")
    return rows


def cmd_inventory(a) -> list[dict]:
    rows = _load(a.out / "assess.json")
    if a.instance:
        rows = [r for r in rows if r["name"] in a.instance or r["id"] in a.instance]
    data = inventory.run(Arm(), rows, deep=a.deep, only_classic=not a.include_v2)
    _save(data, a.out / "inventory.json")
    for d in data:
        s = d["summary"]
        print(f"  {d['instance']['name']:40} critical={s['Critical']} high={s['High']} "
              f"secretsInApim={d['secretsInApim']} subs={d['subscriptionCount']}")
    return data


def cmd_report(a):
    rows = _load(a.out / "assess.json")
    inv = _load(a.out / "inventory.json") if (a.out / "inventory.json").exists() else []
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (a.cve or "APIM-advisory"))
    xlsx = report.build_excel(rows, inv, a.out / f"{safe}_{a.customer}_tracker.xlsx", a.customer, a.tracking_id, a.cve)
    md = a.out / f"{a.customer}_report.md"
    md.write_text(report.build_markdown(rows, inv, a.customer, a.tracking_id, a.cve))
    print(f"  wrote {xlsx}\n  wrote {md}")


def cmd_run(a):
    cmd_assess(a)
    a.instance, a.include_v2 = None, False
    cmd_inventory(a)
    cmd_report(a)


def cmd_hunt(a):
    res = hunt.run(a.workspace_id, a.out / "hunt", a.lookback, a.fix_date, a.app_id or [], a.only)
    for r in res:
        state = r["error"] or (f"{r['rows']} rows" if r["rows"] is not None else "rendered only")
        print(f"  {r['query']:36} {state}")
    if not a.workspace_id:
        print("\n  No --workspace-id: queries rendered to out/hunt/ - paste them into Log Analytics / Sentinel.")


def cmd_remediate(a):
    actions = list(a.action or [])
    if a.containment:
        actions = remediate.CONTAINMENT + [x for x in actions if x not in remediate.CONTAINMENT]
    if not actions:
        sys.exit("Choose --action (repeatable) or --containment. Actions: " + ", ".join(remediate.ACTIONS))
    if "link-keyvault" in actions and not (a.named_value and a.secret_uri):
        sys.exit("link-keyvault needs --named-value and --secret-uri")
    arm = Arm(dry_run=not a.apply)
    if a.apply:
        print("!! APPLY MODE - changes will be sent to Azure.")
    remediate.run(arm, a.instance, actions, a.yes, which=a.which, subs=a.sub,
                  include_all_access=not a.skip_all_access, named_value=a.named_value,
                  secret_uri=a.secret_uri, identity_client_id=a.identity_client_id)
    _save(arm.log, a.out / "remediation-log.json")


def cmd_demo(a):
    fx = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / "assess.json").write_text((fx / "assess.json").read_text())
    (a.out / "inventory.json").write_text((fx / "inventory.json").read_text())
    cmd_report(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="apimtk", description=__doc__)
    p.add_argument("--out", type=Path, default=Path("out"), help="output folder (default ./out)")
    sp = p.add_subparsers(dest="cmd", required=True)

    def common_report(x):
        x.add_argument("--customer", default="customer")
        x.add_argument("--tracking-id", default=DEFAULT_TRACKING)
        x.add_argument("--cve", default="", help="reference shown in the report title, e.g. CVE-2026-35425")

    x = sp.add_parser("assess", help="01 find APIM instances, Classic vs v2, advisory membership")
    x.add_argument("--subscription", action="append", help="limit to subscription id (repeatable)")
    x.add_argument("--tracking-id", default=DEFAULT_TRACKING, help="Service Health tracking id ('' to skip)")
    x.set_defaults(fn=cmd_assess)

    x = sp.add_parser("inventory", help="02 secrets, keys and risky settings per instance")
    x.add_argument("--instance", action="append", help="instance name or resource id (repeatable)")
    x.add_argument("--deep", action="store_true", help="also scan global/API/fragment policies for {{named value}} usage")
    x.add_argument("--include-v2", action="store_true")
    x.set_defaults(fn=cmd_inventory)

    x = sp.add_parser("report", help="Excel tracker + Markdown summary from assess/inventory output")
    common_report(x)
    x.set_defaults(fn=cmd_report)

    x = sp.add_parser("run", help="assess + inventory + report in one go (read-only)")
    x.add_argument("--subscription", action="append")
    x.add_argument("--deep", action="store_true")
    common_report(x)
    x.set_defaults(fn=cmd_run)

    x = sp.add_parser("hunt", help="03 render / run the KQL hunting pack")
    x.add_argument("--workspace-id", help="Log Analytics workspace GUID (omit to only render queries)")
    x.add_argument("--lookback", default="90d")
    x.add_argument("--fix-date", default="2026-11-19")
    x.add_argument("--app-id", action="append", help="app registration ids whose secrets sat in APIM")
    x.add_argument("--only", action="append", help="run only queries whose file name contains this")
    x.set_defaults(fn=cmd_hunt)

    x = sp.add_parser("remediate", help="04 guided changes (dry run unless --apply)")
    x.add_argument("--instance", required=True, help="APIM resource id")
    x.add_argument("--action", action="append", choices=list(remediate.ACTIONS))
    x.add_argument("--containment", action="store_true", help="disable-tenant-access + regen-tenant-keys + enable-managed-identity")
    x.add_argument("--apply", action="store_true", help="send changes (default is dry run)")
    x.add_argument("--yes", action="store_true", help="do not prompt per action")
    x.add_argument("--which", default="secondary", choices=["primary", "secondary"], help="for regen-sub-keys")
    x.add_argument("--sub", action="append", help="subscription name(s) for regen-sub-keys (default: all active)")
    x.add_argument("--skip-all-access", action="store_true")
    x.add_argument("--named-value", help="for link-keyvault")
    x.add_argument("--secret-uri", help="versionless Key Vault secret URI for link-keyvault")
    x.add_argument("--identity-client-id", help="user-assigned identity client id for Key Vault access")
    x.set_defaults(fn=cmd_remediate)

    x = sp.add_parser("demo", help="offline: build a sample report from test fixtures")
    common_report(x)
    x.set_defaults(fn=cmd_demo)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
