"""Offline stand-in for Arm: serves canned ARM responses for a fictional tenant."""
from __future__ import annotations

from apimtk.arm import Arm, ArmError, redact

SUB = "11111111-1111-1111-1111-111111111111"
SUB2 = "22222222-2222-2222-2222-222222222222"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ai-gw"
APIM1 = f"{RG}/providers/Microsoft.ApiManagement/service/apim-contoso-prod-001"
APIM2 = f"/subscriptions/{SUB2}/resourceGroups/rg-dev/providers/Microsoft.ApiManagement/service/apim-contoso-dev-001"
APIM3 = f"{RG}/providers/Microsoft.ApiManagement/service/apim-contoso-v2-001"
APIM4 = f"{RG}/providers/Microsoft.ApiManagement/service/apim-contoso-func-001"
ADVISORY = "Microsoft.ResourceHealth/events/MZK9-GH0"
SINCE = "2026-11-01"  # fixed date so fixtures don't depend on the clock


def _inst(id_, name, rg, sub, subname, sku, vnet, ident):
    return {"id": id_, "name": name, "resourceGroup": rg, "subscriptionId": sub, "subscriptionName": subname,
            "location": "uaenorth", "sku": sku, "capacity": 1, "vnetType": vnet, "identityType": ident,
            "gatewayUrl": f"https://{name}.azure-api.net"}


GRAPH = [
    _inst(APIM1, "apim-contoso-prod-001", "rg-ai-gw", SUB, "Sub-Prod", "Premium", "Internal", "SystemAssigned"),
    _inst(APIM2, "apim-contoso-dev-001", "rg-dev", SUB2, "Sub-Dev", "Developer", "None", ""),
    _inst(APIM3, "apim-contoso-v2-001", "rg-ai-gw", SUB, "Sub-Prod", "StandardV2", "None", "SystemAssigned"),
    _inst(APIM4, "apim-contoso-func-001", "rg-ai-gw", SUB, "Sub-Prod", "Consumption", "None", ""),
]

RUNTIME = {"https://apim-contoso-prod-001.azure-api.net": "0.53.32050.0",
           "https://apim-contoso-dev-001.azure-api.net": "0.52.31000.0"}

FAKE_KEY = "c4a3cdb1938a416e9f0d7b2a61e5c8f4"  # random-looking, not a real key
FAKE_KEY2 = "Zx8kQ2pL9vB4nM7cR1tY6wE3uI0oP5aS"


def nv(name, secret=False, value=None, kv=None):
    p = {"displayName": name, "secret": secret}
    if value is not None:
        p["value"] = value
    if kv:
        p["keyVault"] = {"secretIdentifier": kv, "lastStatus": {"code": "Success"}}
    return {"name": name, "properties": p}


def policy(xml):
    return {"raw": xml}  # real APIM returns format=rawxml as the raw response body


GLOBAL_POLICY = f"""<policies><inbound><set-header name="api-key" exists-action="override">
<value>{FAKE_KEY2}</value></set-header></inbound></policies>"""
API_POLICY = """<policies><inbound><base /><set-header name="api-key" exists-action="override">
<value>{{gpt-api-key}}</value></set-header><set-header name="x-env"><value>prod</value></set-header></inbound></policies>"""
OP_POLICY = """<policies><inbound><base /><authentication-basic username="svc" password="Sup3rS3cret!" /></inbound></policies>"""

API = f"{APIM1}/apis/orders"
OP = f"{API}/operations/create"
LIST_ADVISORY = "listSecurityAdvisoryImpactedResources"

RESP = {
    # advisory: tenant scope not readable; prod sub readable; dev sub listed but restricted
    f"/providers/{ADVISORY}/{LIST_ADVISORY}": ArmError(403, "x", "forbidden"),
    f"/subscriptions/{SUB}/providers/{ADVISORY}": {"name": "MZK9-GH0"},
    f"/subscriptions/{SUB}/providers/{ADVISORY}/{LIST_ADVISORY}": {"value": [{"properties": {"targetResourceId": APIM1}}]},
    f"/subscriptions/{SUB2}/providers/{ADVISORY}": {"name": "MZK9-GH0"},
    f"/subscriptions/{SUB2}/providers/{ADVISORY}/{LIST_ADVISORY}": ArmError(403, "x", "forbidden"),
    f"/subscriptions/{SUB2}/providers/{ADVISORY}/impactedResources": ArmError(403, "x", "forbidden"),

    f"{APIM1}/namedValues": {"value": [
        nv("embedding-api-key", value=FAKE_KEY),
        nv("tenant-id", value="00000000-0000-0000-0000-0000000000aa"),
        nv("api-audience", value="00000000-0000-0000-0000-0000000000bb"),
        nv("orders-backend-url", value="https://backend.contoso.example/api"),
        nv("gpt-api-key", secret=True),
        nv("5f1c0e2a9b7d4e3f8a6b1c2d", secret=True),
        nv("Logger-Credentials--eh01", secret=True),
        nv("Logger-Credentials--ai01", secret=True),
        nv("llm-api-key", secret=True, kv="https://kv-contoso.vault.azure.net/secrets/llm-api-key"),
    ]},
    f"{APIM1}/backends": {"value": [
        {"name": "aoai", "properties": {"url": "https://aoai.contoso.example/openai",
                                        "credentials": {"header": {"api-key": ["{{5f1c0e2a9b7d4e3f8a6b1c2d}}"]}}}},
        {"name": "func", "properties": {"url": "https://func.contoso.example/api/run?code=abcDEF123&x=1"}},
        {"name": "masked", "properties": {"url": "https://masked.contoso.example",  # how ARM returns literals
                                          "credentials": {"query": {"code": None}}}},
        {"name": "legacy", "properties": {"url": "https://legacy.contoso.example",
                                          "credentials": {"header": {"x-api-key": [FAKE_KEY]},
                                                          "certificateIds": [f"{APIM1}/certificates/legacy-client"]}}}]},
    f"{APIM1}/subscriptions": {"value": [
        {"name": "master", "properties": {"displayName": "Built-in all-access subscription", "scope": f"{APIM1}/apis",
                                          "state": "active", "createdDate": "2024-01-10T00:00:00Z"}},
        {"name": "app-a", "properties": {"displayName": "App A", "scope": f"{APIM1}/products/ai", "state": "active",
                                         "ownerId": f"{APIM1}/users/1", "createdDate": "2026-11-18T03:12:00Z"}},
        {"name": "app-b", "properties": {"displayName": "App B", "scope": f"{APIM1}/products/ai", "state": "suspended"}},
    ]},
    f"{APIM1}/products": {"value": [
        {"id": f"{APIM1}/products/ai", "name": "ai",
         "properties": {"subscriptionRequired": True, "approvalRequired": True, "state": "published"}},
        {"id": f"{APIM1}/products/starter", "name": "starter",
         "properties": {"subscriptionRequired": True, "approvalRequired": False, "state": "published"}}]},
    f"{APIM1}/apis": {"value": [{"id": API, "name": "orders",
                                 "properties": {"path": "orders", "serviceUrl": "https://backend.contoso.example/api",
                                                "subscriptionRequired": True}}]},
    f"{API}/operations": {"value": [{"id": OP, "name": "create"}]},
    f"{APIM1}/policies/policy": policy(GLOBAL_POLICY),
    f"{API}/policies/policy": policy(API_POLICY),
    f"{OP}/policies/policy": policy(OP_POLICY),
    f"{APIM1}/policyFragments": {"value": []},
    f"{APIM1}/loggers": {"value": [
        {"name": "eh-logger", "properties": {"loggerType": "azureEventHub",
                                             "credentials": {"name": "apim-logs",
                                                             "connectionString": "{{Logger-Credentials--eh01}}"}}},
        {"name": "appinsights", "properties": {"loggerType": "applicationInsights",
                                               "credentials": {"instrumentationKey": "{{Logger-Credentials--ai01}}"}}}]},
    f"{APIM1}/certificates": {"value": [
        {"name": "legacy-client", "properties": {"subject": "CN=legacy", "expirationDate": "2027-01-01T00:00:00Z"}}]},
    f"{APIM1}/users": {"value": [
        {"name": "1", "properties": {"email": "admin@contoso.example", "state": "active",
                                     "registrationDate": "2024-01-10T00:00:00Z", "identities": [{"provider": "Azure"}]}},
        {"name": "u-new", "properties": {"email": "new.user@example.net", "state": "active",
                                         "registrationDate": "2026-11-17T22:40:00.1055076Z", "identities": [{"provider": "Basic"}]}}]},
    f"/subscriptions/{SUB}/providers/Microsoft.Insights/eventtypes/management/values": {"value": [
        {"resourceId": f"{APIM1}/namedValues/gpt-api-key", "caller": "11111111-aaaa-bbbb-cccc-000000000001",
         "operationName": {"value": "Microsoft.ApiManagement/service/namedValues/listValue/action"},
         "eventTimestamp": "2026-11-17T23:01:00Z"},
        {"resourceId": f"{APIM1}/subscriptions/app-a", "caller": "admin@contoso.example",
         "operationName": {"value": "Microsoft.ApiManagement/service/subscriptions/write"},
         "status": {"value": "Started"}, "eventTimestamp": "2026-11-18T03:12:00Z"},
        {"resourceId": f"{APIM1}/subscriptions/app-a", "caller": "admin@contoso.example",
         "operationName": {"value": "Microsoft.ApiManagement/service/subscriptions/write"},
         "status": {"value": "Succeeded"}, "eventTimestamp": "2026-11-18T03:12:01Z"},
        {"resourceId": f"{APIM1}-eu/namedValues/x", "caller": "someone@contoso.example",
         "operationName": {"value": "Microsoft.ApiManagement/service/namedValues/listValue/action"},
         "eventTimestamp": "2026-11-18T05:00:00Z"},
        {"resourceId": f"{APIM1}/users/1", "caller": "",
         "operationName": {"value": "MICROSOFT.APIMANAGEMENT/SERVICE/USERS/READ"}, "eventTimestamp": "2026-11-12T00:00:00Z"},
        {"resourceId": APIM3, "caller": "admin@contoso.example",
         "operationName": {"value": "Microsoft.ApiManagement/service/write"}, "eventTimestamp": "2026-11-10T00:00:00Z"}]},
    f"{APIM1}/tenant/access": {"properties": {"enabled": False}},
    f"{APIM1}/tenant/gitAccess": {"properties": {"enabled": False}},
    f"{APIM1}/portalsettings/signup": {"properties": {"enabled": True}},
    f"{APIM1}/identityProviders": {"value": [{"name": "aad"}]},
    f"{APIM1}/authorizationServers": {"value": [{"name": "oauth-test-console"}]},
    f"{APIM1}/openidConnectProviders": {"value": [{"name": "entra-oidc"}]},
    f"{APIM1}/openidConnectProviders/entra-oidc": {"name": "entra-oidc"},
    f"{APIM1}/authorizationProviders": {"value": []},
    f"{APIM1}/namedValues/gpt-api-key": nv("gpt-api-key", secret=True),

    f"{APIM2}/namedValues": {"value": [nv("llm-api-key-dev", secret=True), nv("gpt-4o-api-key-LLM", secret=True)]},
    f"{APIM2}/backends": {"value": []},
    f"{APIM2}/subscriptions": {"value": [
        {"name": "master", "properties": {"displayName": "Built-in all-access subscription", "scope": f"{APIM2}/apis",
                                          "state": "active"}}]},
    f"{APIM2}/products": {"value": []},
    f"{APIM2}/apis": {"value": []},
    f"{APIM2}/policyFragments": {"value": []},
    f"{APIM2}/loggers": {"value": []},
    f"{APIM2}/certificates": {"value": []},
    f"{APIM2}/users": {"value": []},
    f"/subscriptions/{SUB2}/providers/Microsoft.Insights/eventtypes/management/values": {"value": []},
    f"{APIM2}/tenant/access": {"properties": {"enabled": True}},
    f"{APIM2}/tenant/gitAccess": ArmError(404, "x", "nf"),
    f"{APIM2}/portalsettings/signup": {"properties": {"enabled": False}},
    f"{APIM2}/identityProviders": {"value": []},
    f"{APIM2}/authorizationServers": {"value": []},
    f"{APIM2}/openidConnectProviders": {"value": []},
    f"{APIM2}/authorizationProviders": {"value": [{"name": "github", "properties": {"identityProvider": "github"}}]},
    f"{APIM2}/products/starter": ArmError(404, "x", "nf"),
    f"{APIM2}/products/unlimited": ArmError(404, "x", "nf"),
    APIM2: {"identity": {"type": "None"}},
}


class FakeArm(Arm):
    def __init__(self, dry_run=True, overrides: dict | None = None):
        super().__init__(token="fake", dry_run=dry_run)
        self.resp = {**RESP, **(overrides or {})}

    def request(self, method, path, api_version="x", body=None, headers=None, write=False):
        if write:
            self.log.append({"method": method, "url": path, "body": redact(body), "applied": not self.dry_run})
            return {"dryRun": True}
        if path == "/providers/Microsoft.ResourceGraph/resources":
            return {"data": [dict(g) for g in GRAPH]}
        key = path.replace("https://management.azure.com", "").split("?")[0]
        if key not in self.resp:
            raise ArmError(404, key, "not found")
        r = self.resp[key]
        if isinstance(r, Exception):
            raise r
        return r

    def gateway_runtime_version(self, gateway_url):
        v = RUNTIME.get(gateway_url)
        return (v, None) if v else (None, "ConnectionError")
