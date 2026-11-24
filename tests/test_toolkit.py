import json
from pathlib import Path

import pytest
from openpyxl import load_workbook

from apimtk import assess, hunt, inventory, remediate, report
from apimtk.inventory import looks_like_secret, runtime_status, scan_policy_secrets
from fake_arm import ADVISORY, APIM1, APIM2, FAKE_KEY, FAKE_KEY2, SINCE, FakeArm

FIX = Path(__file__).parent / "fixtures"


def _inventory(arm=None):
    arm = arm or FakeArm()
    rows = assess.run(arm, None, "MZK9-GH0")
    return rows, {d["instance"]["name"]: d for d in inventory.run(arm, rows, since=SINCE)}


@pytest.mark.parametrize("name,value,expected", [
    ("embedding-api-key", FAKE_KEY, True),
    ("tenant-id", "00000000-0000-0000-0000-0000000000aa", False),
    ("api-audience", "00000000-0000-0000-0000-0000000000bb", False),
    ("backend-url", "https://x.example/api", False),
    ("required-scope", "api://00000000-0000-0000-0000-0000000000bb/.default", False),
    ("storage-conn", "DefaultEndpointsProtocol=https;AccountKey=abc;", True),
    ("random", "Zx8kQ2pL9vB4nM7cR1tY6wE3uI0oP5aS", True),
    ("region", "uaenorth", False),
    ("Authorization", f"Bearer {FAKE_KEY}", True),
])
def test_secret_heuristic(name, value, expected):
    assert looks_like_secret(name, value) is expected


@pytest.mark.parametrize("xml,expected", [
    (f'<set-header name="api-key"><value>{FAKE_KEY}</value></set-header>', ['set-header "api-key"']),
    ('<set-header name="api-key"><value>{{llm-api-key}}</value></set-header>', []),
    ('<set-header name="Authorization"><value>@("Bearer " + (string)context.Variables["t"])</value></set-header>', []),
    ('<set-header name="x-env"><value>production</value></set-header>', []),
    (f'<set-query-parameter name="code"><value>{FAKE_KEY2}</value></set-query-parameter>', ['set-query-parameter "code"']),
    ('<authentication-basic username="u" password="p4ss" />', ["authentication-basic password="]),
    ('<authentication-basic username="u" password="{{pwd}}" />', []),
    ('<authentication-certificate body="MIIKcQIBAzCC" password="{{pfx}}" />',
     ["authentication-certificate body= (embedded certificate)"]),
    ('<send-request><set-url>https://x.blob.core.windows.net/c?sv=1&amp;sig=abcd</set-url></send-request>',
     ["text containing &sig="]),
    ('<cache-lookup-value key="token-cache" variable-name="t" />', []),
    ('<set-header name="X-Powered-By" exists-action="delete" />'
     '<set-header name="Authorization" exists-action="override"><value>Basic dXNlcjpwYXNz</value></set-header>',
     ['set-header "Authorization"']),
])
def test_policy_secret_scan(xml, expected):
    assert scan_policy_secrets(f"<policies><inbound>{xml}</inbound></policies>") == expected


@pytest.mark.parametrize("version,affected,status", [
    ("0.53.32050.0", True, "patched"),                 # real Classic Developer gateway after the fix
    ("0.52.31936.0", True, "patched"), ("0.52.31935.0", True, "vulnerable"),
    ("0.53.31938.0", True, "patched"), ("0.53.31937.0", True, "vulnerable"),
    ("0.53.4608.0", False, "not applicable"),          # NSM's v2/Consumption example; real v2 gateway
    ("0.51.40000.0", True, "vulnerable"), ("0.54.1.0", True, "patched"),
    (None, True, "unknown"), ("garbage", True, "unknown"),
])
def test_runtime_status(version, affected, status):
    assert runtime_status(version, affected) == status


def test_assess_tiers_and_advisory():
    rows = {r["name"]: r for r in assess.run(FakeArm(), None, "MZK9-GH0")}
    assert rows["apim-contoso-prod-001"]["inAdvisory"] == "Yes" and rows["apim-contoso-prod-001"]["priority"] == "P1"
    assert rows["apim-contoso-dev-001"]["inAdvisory"] == "Yes"          # restricted detail -> whole sub listed
    assert "not readable" in rows["apim-contoso-dev-001"]["advisoryNote"]
    assert rows["apim-contoso-v2-001"]["affectedTier"] is False and rows["apim-contoso-v2-001"]["priority"] == "P4"
    func = rows["apim-contoso-func-001"]                                 # Consumption: Classic but not affected
    assert func["classic"] is True and func["affectedTier"] is False and func["priority"] == "P4"


def test_assess_tenant_scope_advisory():
    arm = FakeArm(overrides={f"/providers/{ADVISORY}/listSecurityAdvisoryImpactedResources":
                             {"value": [{"properties": {"targetResourceId": APIM2}}]},
                             f"/subscriptions/22222222-2222-2222-2222-222222222222/providers/{ADVISORY}": {}})
    rows = {r["name"]: r for r in assess.run(arm, None, "MZK9-GH0")}
    assert rows["apim-contoso-dev-001"]["inAdvisory"] == "Yes" and rows["apim-contoso-dev-001"]["advisoryNote"] == ""


def test_inventory_covers_every_credential_type():
    _, inv = _inventory()
    assert set(inv) == {"apim-contoso-prod-001", "apim-contoso-dev-001"}  # unaffected tiers skipped
    prod = inv["apim-contoso-prod-001"]
    kinds = {c["kind"] for c in prod["credentials"]}
    assert {"Named value", "Subscription key", "Management API keys", "Identity provider secret",
            "OAuth 2.0 client secret", "OpenID Connect client secret", "Backend credential", "Client certificate",
            "Certificate", "Credential in policy"} <= kinds
    names = {c["name"] for c in prod["credentials"]}
    assert 'policy:global: set-header "api-key"' in names                # literal key in global policy
    assert "operation:orders/create: authentication-basic password=" in names  # operation-level policy
    assert "legacy: header x-api-key" in names                           # literal backend header
    assert "aoai: header api-key" not in names                           # {{named value}} is not a literal
    assert "masked: query code" in names                                 # ARM masks literals as null
    assert "backend:func: ?code" in names                                # key in a backend URL ...
    assert "abcDEF123" not in json.dumps(prod)                           # ... is never stored
    nvs = {n["displayName"]: n for n in prod["namedValues"]}
    assert nvs["embedding-api-key"]["type"].startswith("Plain value (looks")
    assert nvs["tenant-id"]["type"] == "Plain value"
    assert nvs["llm-api-key"]["type"] == "KeyVault" and nvs["llm-api-key"]["risk"] == "Rotate in Key Vault"
    assert nvs["gpt-api-key"]["usedBy"] == "api:orders"
    assert nvs["5f1c0e2a9b7d4e3f8a6b1c2d"]["usedBy"] == "backend:aoai"
    assert nvs["Logger-Credentials--eh01"]["usedBy"] == "logger:eh-logger"
    assert nvs["Logger-Credentials--ai01"]["risk"].startswith("OK")       # App Insights key is ingestion-only
    assert prod["secretsInApim"] == 4
    assert prod["runtimeStatus"] == "patched"
    assert [a["serviceUrl"] for a in prod["apis"]] == ["https://backend.contoso.example/api"]
    dev = inv["apim-contoso-dev-001"]
    assert dev["runtimeStatus"] == "vulnerable" and dev["findings"][0]["area"] == "Runtime"
    assert any(f["item"] == "tenant/access" and f["severity"] == "High" for f in dev["findings"])
    assert any(f["area"] == "Credential manager" for f in dev["findings"])
    dump = json.dumps(list(inv.values()))
    for secret in (FAKE_KEY, FAKE_KEY2, "Sup3rS3cret!"):
        assert secret not in dump                                        # secret values never stored


def test_inventory_flags_recent_changes():
    _, inv = _inventory()
    prod = inv["apim-contoso-prod-001"]
    review = {f["item"] for f in prod["findings"] if f["area"] == "Review changes"}
    assert "user: new.user@example.net" in review and "user: admin@contoso.example" not in review
    assert "subscription: App A" in review and "Secret reads in Activity log" in review
    ops = {g["operation"] for g in prod["recentChanges"]}
    writes = [g for g in prod["recentChanges"] if g["operation"].endswith("subscriptions/write")]
    assert [g["count"] for g in writes] == [1]                           # Started + Succeeded counted once
    reads = next(f for f in prod["findings"] if f["item"] == "Secret reads in Activity log")
    assert "someone@contoso.example" not in reads["detail"]              # apim-...-eu is another instance
    assert "Microsoft.ApiManagement/service/write" not in ops            # other instance in the RG filtered out
    assert not any(o.lower().endswith("/read") for o in ops)             # reads are noise


def test_remediate_dry_run_sends_nothing():
    arm = FakeArm(dry_run=True)
    remediate.run(arm, APIM1, ["disable-tenant-access", "regen-tenant-keys", "regen-sub-keys"], yes=True,
                  which="primary", subs=None, include_all_access=True)
    assert arm.log and all(not e["applied"] for e in arm.log)
    urls = [e["url"] for e in arm.log]
    assert any(u.endswith("/subscriptions/app-a/regeneratePrimaryKey") for u in urls)
    assert not any("app-b" in u for u in urls)                           # suspended sub untouched
    assert sum("regenerate" in u and "/tenant/" in u for u in urls) == 4
    assert any(u.endswith("/tenant/access/git/regenerateSecondaryKey") for u in urls)  # REST path for Git keys
    with pytest.raises(ValueError):
        remediate.regen_sub_keys(arm, APIM1)                             # --which is required


def test_remediate_link_keyvault_and_identity():
    arm = FakeArm(dry_run=True)
    remediate.run(arm, APIM1, ["link-keyvault"], yes=True, named_value="gpt-api-key",
                  secret_uri="https://kv.vault.azure.net/secrets/gpt-api-key")
    put = arm.log[-1]
    assert put["method"] == "PUT" and put["body"]["properties"]["keyVault"]["secretIdentifier"].endswith("/gpt-api-key")
    remediate.run(arm, APIM2, ["enable-managed-identity", "delete-default-products"], yes=True)
    assert arm.log[-1]["body"]["identity"]["type"] == "SystemAssigned"   # no products deleted (404s)


def test_remediate_update_client_secret_never_logs_secret():
    arm = FakeArm(dry_run=False)
    remediate.run(arm, APIM1, ["update-client-secret"], yes=True, provider="oidc:entra-oidc",
                  secret_reader=lambda _: "n3w-s3cret-value")
    entry = arm.log[-1]
    assert entry["method"] == "PATCH" and entry["url"].endswith("/openidConnectProviders/entra-oidc")
    assert entry["body"] == {"properties": {"clientSecret": "***"}}
    with pytest.raises(ValueError):
        remediate.update_client_secret(arm, APIM1, provider="bogus:x")
    remediate.run(arm, APIM1, ["update-client-secret"], yes=True, provider="oidc:missing")  # 404: reported, no crash
    assert arm.failed == ["update-client-secret"] and "error" in arm.log[-1]


def test_report_outputs(tmp_path):
    rows, inv = _inventory()
    out = report.build_excel(rows, list(inv.values()), tmp_path / "t.xlsx", "Contoso", "MZK9-GH0", "CVE-0000-00000")
    wb = load_workbook(out)
    assert wb.sheetnames == ["Tracker", "Credentials", "Findings", "Recent changes", "APIs & backends"]
    assert wb["Tracker"]["A1"].value.startswith("CVE-0000-00000")
    assert wb["Tracker"]["B7"].value in ("apim-contoso-dev-001", "apim-contoso-prod-001")
    assert wb["Credentials"].max_row - 1 == sum(d["credentialCount"] for d in inv.values())
    md = report.build_markdown(rows, list(inv.values()), "Contoso", "MZK9-GH0", "")
    assert "apim-contoso-prod-001" in md and "vulnerable" in md


def test_hunt_renders_without_workspace(tmp_path):
    res = hunt.run(None, tmp_path, "90d", "2026-11-19", ["abc"])
    assert len(res) == 6
    text = (tmp_path / "05-spn-signins.kql").read_text()
    assert '"abc"' in text and "{lookback}" not in text


def test_fixtures_in_sync():
    """Fixtures used by `apimtk demo` are regenerated from the fake tenant: python tests/make_fixtures.py"""
    rows, inv = _inventory()
    assert json.loads((FIX / "assess.json").read_text()) == json.loads(json.dumps(rows, default=str))
    assert json.loads((FIX / "inventory.json").read_text()) == \
        json.loads(json.dumps(list(inv.values()), default=str))


def test_arm_retries_timeouts_then_reports_error(monkeypatch):
    import requests

    from apimtk import arm as armmod
    monkeypatch.setattr(armmod.time, "sleep", lambda _: None)

    class Resp:
        status_code, text, headers = 200, '{"value": [1]}', {}

        def json(self):
            return {"value": [1]}

    calls = []

    class Session:
        def __init__(self, fail):
            self.fail = fail

        def request(self, *a, **k):
            calls.append(1)
            if len(calls) <= self.fail:
                raise requests.ReadTimeout("slow")
            return Resp()

    a = armmod.Arm(token="t", session=Session(fail=2))
    assert a.try_list("/x") == ([1], None)                               # recovers after 2 timeouts
    calls.clear()
    b = armmod.Arm(token="t", session=Session(fail=99))
    assert b.try_list("/x") == ([], "0")                                 # never crashes the inventory


def test_remediation_log_keeps_history(tmp_path, monkeypatch):
    from apimtk import cli
    monkeypatch.setattr(cli, "Arm", lambda dry_run=True: FakeArm(dry_run=dry_run))
    args = ["--out", str(tmp_path), "remediate", "--instance", APIM1, "--action", "disable-tenant-access"]
    cli.main(args)
    cli.main(args)
    log = json.loads((tmp_path / "remediation-log.json").read_text())
    assert len(log) == 4 and all(e["instance"] == APIM1 and e["time"] for e in log)  # 2 runs x 2 writes
