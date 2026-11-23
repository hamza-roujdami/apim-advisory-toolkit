"""Report: Excel tracker (one row per instance) + findings + named values, and a Markdown summary."""
from __future__ import annotations

from datetime import date
from pathlib import Path

from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.worksheet.datavalidation import DataValidation

FONT = "Arial"
BLUE = "0078D4"
NAVY = "243A5E"
YELLOW = PatternFill("solid", fgColor="FFF2CC")
SEV_FILL = {"Critical": "F8CBAD", "High": "FFC7CE", "Medium": "FFEB9C", "Low": "DDEBF7", "Info": "F2F2F2"}
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)


def _header(ws, row: int, headers: list[str], widths: list[int]):
    for i, (h, w) in enumerate(zip(headers, widths), 1):
        c = ws.cell(row, i, h)
        c.font = Font(name=FONT, bold=True, color="FFFFFF")
        c.fill = PatternFill("solid", fgColor=BLUE)
        c.border = BORDER
        c.alignment = Alignment(wrap_text=True, vertical="center")
        ws.column_dimensions[c.column_letter].width = w
    ws.row_dimensions[row].height = 30


def _cell(ws, r, c, v, wrap=False, fill=None):
    cell = ws.cell(r, c, v)
    cell.font = Font(name=FONT, size=10)
    cell.border = BORDER
    cell.alignment = Alignment(vertical="top", wrap_text=wrap)
    if fill:
        cell.fill = fill
    return cell


def build_excel(assess_rows: list[dict], inv: list[dict], out: Path, customer: str,
                tracking_id: str, cve: str) -> Path:
    inv_by_id = {d["instance"]["id"]: d for d in inv}
    wb = Workbook()
    ws = wb.active
    ws.title = "Tracker"
    title = f"{cve}: Azure API Management advisory - {customer}" if cve else f"APIM security advisory - {customer}"
    ws["A1"] = title
    ws["A1"].font = Font(name=FONT, bold=True, size=14, color=NAVY)
    ws["A2"] = "Service Health tracking ID:"
    ws["C2"] = tracking_id or "-"
    ws["A3"] = "Generated:"
    ws["C3"] = date.today().isoformat()
    for c in ("A2", "A3"):
        ws[c].font = Font(name=FONT, bold=True, size=10)
    ws["A4"] = ("Yellow columns = fill in during remediation. Findings and Named values tabs are generated "
                "by the toolkit - re-run `apimtk inventory` + `apimtk report` to refresh.")
    ws["A4"].font = Font(name=FONT, italic=True, size=9, color="595959")
    hdr = ["Priority", "APIM instance", "Subscription", "Tier", "Classic?", "In advisory?", "Secrets in APIM",
           "Active subs", "Critical", "High", "Actions performed (date - action)", "Owner", "Status", "Next step"]
    _header(ws, 6, hdr, [8, 30, 26, 11, 9, 11, 10, 9, 8, 8, 50, 14, 13, 45])
    r = 7
    for a in sorted(assess_rows, key=lambda x: (x["priority"], x["name"])):
        d = inv_by_id.get(a["id"], {})
        s = d.get("summary", {})
        nxt = ""
        if d:
            top = [f for f in d["findings"] if f["severity"] in ("Critical", "High")][:2]
            nxt = "; ".join(f"{f['item']}: {f['action']}" for f in top)
        elif not a["classic"]:
            nxt = "v2 tier - not in advisory scope"
        vals = [a["priority"], a["name"], f"{a.get('subscriptionName') or ''}\n{a['subscriptionId']}",
                f"{a['sku']} ({a.get('capacity') or 1})", "Yes" if a["classic"] else "No", a["inAdvisory"],
                d.get("secretsInApim", ""), d.get("subscriptionCount", ""), s.get("Critical", ""),
                s.get("High", ""), "", "", "Not started" if a["classic"] else "N/A", nxt]
        for c, v in enumerate(vals, 1):
            _cell(ws, r, c, v, wrap=c in (2, 3, 11, 14), fill=YELLOW if c in (11, 12, 13) else None)
        r += 1
    last = max(r + 20, 30)
    for rr in range(r, last):
        for c in range(1, 15):
            _cell(ws, rr, c, None, fill=YELLOW if c in (11, 12, 13) else None)
    dv = DataValidation(type="list", formula1='"Not started,In progress,Blocked,Done,N/A"', allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"M7:M{last}")
    for t, col in [("Done", "C6EFCE"), ("Blocked", "FFC7CE"), ("In progress", "FFEB9C")]:
        ws.conditional_formatting.add(f"M7:M{last}", CellIsRule(operator="equal", formula=[f'"{t}"'],
                                                                 fill=PatternFill("solid", fgColor=col)))
    ws.freeze_panes = "C7"
    ws.auto_filter.ref = f"A6:N{last}"
    ws.page_setup.orientation = "landscape"
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0

    fs = wb.create_sheet("Findings")
    _header(fs, 1, ["Instance", "Severity", "Area", "Item", "Detail", "Action"], [30, 10, 18, 32, 45, 60])
    r = 2
    for d in inv:
        for f in d["findings"]:
            vals = [d["instance"]["name"], f["severity"], f["area"], f["item"], f["detail"], f["action"]]
            for c, v in enumerate(vals, 1):
                _cell(fs, r, c, v, wrap=c >= 4, fill=PatternFill("solid", fgColor=SEV_FILL[f["severity"]]) if c == 2 else None)
            r += 1
    fs.freeze_panes = "B2"
    fs.auto_filter.ref = f"A1:F{max(r - 1, 2)}"

    nv = wb.create_sheet("Named values")
    _header(nv, 1, ["Instance", "Named value", "Type", "Risk", "Used by", "Key Vault secret", "Rotated at source? (date)"],
            [30, 36, 28, 30, 40, 50, 18])
    r = 2
    for d in inv:
        for n in d["namedValues"]:
            vals = [d["instance"]["name"], n["displayName"], n["type"], n["risk"], n.get("usedBy", ""),
                    n["keyVaultSecretId"], None]
            for c, v in enumerate(vals, 1):
                _cell(nv, r, c, v, wrap=c in (5, 6), fill=YELLOW if c == 7 else None)
            r += 1
    nv.freeze_panes = "C2"
    nv.auto_filter.ref = f"A1:G{max(r - 1, 2)}"

    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out


def build_markdown(assess_rows: list[dict], inv: list[dict], customer: str, tracking_id: str, cve: str) -> str:
    lines = [f"# APIM advisory report - {customer}", "",
             f"- Tracking ID: **{tracking_id or '-'}**" + (f" | Reference: **{cve}**" if cve else ""),
             f"- Generated: {date.today().isoformat()}",
             f"- Instances found: {len(assess_rows)} | Classic: {sum(a['classic'] for a in assess_rows)} | "
             f"In advisory: {sum(a['inAdvisory'] == 'Yes' for a in assess_rows)}", "",
             "| Priority | Instance | Tier | In advisory | Secrets in APIM | Critical | High |",
             "|---|---|---|---|---|---|---|"]
    by_id = {d["instance"]["id"]: d for d in inv}
    for a in sorted(assess_rows, key=lambda x: (x["priority"], x["name"])):
        d = by_id.get(a["id"], {})
        s = d.get("summary", {})
        lines.append(f"| {a['priority']} | {a['name']} | {a['sku']} | {a['inAdvisory']} | "
                     f"{d.get('secretsInApim', '-')} | {s.get('Critical', '-')} | {s.get('High', '-')} |")
    for d in inv:
        crit = [f for f in d["findings"] if f["severity"] in ("Critical", "High")]
        if crit:
            lines += ["", f"## {d['instance']['name']}", ""]
            lines += [f"- **{f['severity']}** - {f['item']}: {f['detail']} -> _{f['action']}_" for f in crit]
    return "\n".join(lines) + "\n"
