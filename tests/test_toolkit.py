import json
from pathlib import Path

import pytest
from openpyxl import load_workbook

from apimtk import assess, hunt, inventory, remediate, report
from apimtk.inventory import looks_like_secret
from fake_arm import APIM1, APIM2, FAKE_KEY, FakeArm

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("name,value,expected", [
    ("embedding-api-key", FAKE_KEY, True),
    ("tenant-id", "00000000-0000-0000-0000-0000000000aa", False),
    ("api-audience", "00000000-0000-0000-0000-0000000000bb", False),
    ("backend-url", "https://x.example/api", False),
    ("required-scope", "api://00000000-0000-0000-0000-0000000000bb/.default", False),
    ("storage-conn", "DefaultEndpointsProtocol=https;AccountKey=abc;", True),
    ("random", "Zx8kQ2pL9vB4nM7cR1tY6wE3uI0oP5aS", True),
    ("region", "uaenorth", False),
])
def test_secret_heuristic(name, value, expected):
    assert looks_like_secret(name, value) is expected


def test_assess_classic_and_advisory():
    rows = {r["name"]: r for r in assess.run(FakeArm(), None, "MZK9-GH0")}
    assert rows["apim-contoso-prod-001"]["classic"] and rows["apim-contoso-prod-001"]["inAdvisory"] == "Yes"
    assert rows["apim-contoso-dev-001"]["inAdvisory"] == "Yes"          # restricted detail -> whole sub listed
    assert "not readable" in rows["apim-contoso-dev-001"]["advisoryNote"]
    assert rows["apim-contoso-v2-001"]["classic"] is False
    assert rows["apim-contoso-v2-001"]["inAdvisory"] == "No"
    assert rows["apim-contoso-prod-001"]["priority"] == "P1"
    assert rows["apim-contoso-v2-001"]["priority"] == "P4"


def test_inventory_findings_and_no_values_leak():
    arm = FakeArm()
    rows = assess.run(arm, None, "MZK9-GH0")
    inv = {d["instance"]["name"]: d for d in inventory.run(arm, rows)}
    assert "apim-contoso-v2-001" not in inv                             # v2 skipped by default
    prod = inv["apim-contoso-prod-001"]
    types = {n["displayName"]: n["type"] for n in prod["namedValues"]}
    assert types["embedding-api-key"].startswith("Plain value (looks")
    assert types["tenant-id"] == "Plain value"
    assert types["gpt-api-key"] == "Secret (stored in APIM)"
    assert types["llm-api-key"] == "KeyVault"
    assert prod["secretsInApim"] == 3
    used = {n["displayName"]: n["usedBy"] for n in prod["namedValues"]}
    assert used["5f1c0e2a9b7d4e3f8a6b1c2d"] == "backend:aoai"
    assert prod["summary"]["Critical"] == 1
    items = [f["item"] for f in prod["findings"]]
    assert "Built-in all-access subscription" in items and "starter" in items
    assert "Username/password sign-up" in items
    dev = inv["apim-contoso-dev-001"]
    assert any(f["item"] == "tenant/access" and f["severity"] == "High" for f in dev["findings"])
    assert any(f["area"] == "Credential manager" for f in dev["findings"])
    assert any(f["area"] == "Identity" for f in dev["findings"])
    assert FAKE_KEY not in json.dumps(list(inv.values()))              # secret values never stored


def test_remediate_dry_run_sends_nothing():
    arm = FakeArm(dry_run=True)
    remediate.run(arm, APIM1, ["disable-tenant-access", "regen-tenant-keys", "regen-sub-keys"], yes=True,
                  which="secondary", subs=None, include_all_access=True)
    assert arm.log and all(not e["applied"] for e in arm.log)
    urls = [e["url"] for e in arm.log]
    assert any(u.endswith("/subscriptions/app-a/regenerateSecondaryKey") for u in urls)
    assert not any("app-b" in u for u in urls)                           # suspended sub untouched
    assert sum("regenerate" in u and "/tenant/" in u for u in urls) == 4


def test_remediate_link_keyvault_and_identity():
    arm = FakeArm(dry_run=True)
    remediate.run(arm, APIM1, ["link-keyvault"], yes=True, named_value="gpt-api-key",
                  secret_uri="https://kv.vault.azure.net/secrets/gpt-api-key")
    put = arm.log[-1]
    assert put["method"] == "PUT" and put["body"]["properties"]["keyVault"]["secretIdentifier"].endswith("/gpt-api-key")
    remediate.run(arm, APIM2, ["enable-managed-identity", "delete-default-products"], yes=True)
    assert arm.log[-1]["body"]["identity"]["type"] == "SystemAssigned"   # no products deleted (404s)


def test_report_outputs(tmp_path):
    arm = FakeArm()
    rows = assess.run(arm, None, "MZK9-GH0")
    inv = inventory.run(arm, rows)
    out = report.build_excel(rows, inv, tmp_path / "t.xlsx", "Contoso", "MZK9-GH0", "CVE-0000-00000")
    wb = load_workbook(out)
    assert wb.sheetnames == ["Tracker", "Findings", "Named values"]
    assert wb["Tracker"]["A1"].value.startswith("CVE-0000-00000")
    assert wb["Tracker"]["B7"].value == "apim-contoso-dev-001" or wb["Tracker"]["B7"].value == "apim-contoso-prod-001"
    md = report.build_markdown(rows, inv, "Contoso", "MZK9-GH0", "")
    assert "apim-contoso-prod-001" in md and "Critical" in md


def test_hunt_renders_without_workspace(tmp_path):
    res = hunt.run(None, tmp_path, "90d", "2026-11-19", ["abc"])
    assert len(res) == 6
    text = (tmp_path / "05-spn-signins.kql").read_text()
    assert '"abc"' in text and "{lookback}" not in text


def test_fixtures_in_sync():
    """Fixtures used by `apimtk demo` are regenerated from the fake tenant."""
    arm = FakeArm()
    rows = assess.run(arm, None, "MZK9-GH0")
    inv = inventory.run(arm, rows)
    assert json.loads((FIX / "assess.json").read_text()) == json.loads(json.dumps(rows, default=str))
    assert json.loads((FIX / "inventory.json").read_text()) == json.loads(json.dumps(inv, default=str))
