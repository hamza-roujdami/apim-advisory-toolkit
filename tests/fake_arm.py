"""Offline stand-in for Arm: serves canned ARM responses for a fictional tenant."""
from __future__ import annotations

from apimtk.arm import Arm, ArmError

SUB = "11111111-1111-1111-1111-111111111111"
SUB2 = "22222222-2222-2222-2222-222222222222"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ai-gw"
APIM1 = f"{RG}/providers/Microsoft.ApiManagement/service/apim-contoso-prod-001"
APIM2 = f"/subscriptions/{SUB2}/resourceGroups/rg-dev/providers/Microsoft.ApiManagement/service/apim-contoso-dev-001"
APIM3 = f"{RG}/providers/Microsoft.ApiManagement/service/apim-contoso-v2-001"

GRAPH = [
    {"id": APIM1, "name": "apim-contoso-prod-001", "resourceGroup": "rg-ai-gw", "subscriptionId": SUB,
     "subscriptionName": "Sub-Prod", "location": "uaenorth", "sku": "Premium", "capacity": 1,
     "vnetType": "Internal", "identityType": "SystemAssigned"},
    {"id": APIM2, "name": "apim-contoso-dev-001", "resourceGroup": "rg-dev", "subscriptionId": SUB2,
     "subscriptionName": "Sub-Dev", "location": "uaenorth", "sku": "Developer", "capacity": 1,
     "vnetType": "None", "identityType": ""},
    {"id": APIM3, "name": "apim-contoso-v2-001", "resourceGroup": "rg-ai-gw", "subscriptionId": SUB,
     "subscriptionName": "Sub-Prod", "location": "uaenorth", "sku": "StandardV2", "capacity": 1,
     "vnetType": "None", "identityType": "SystemAssigned"},
]

FAKE_KEY = "c4a3cdb1938a416e9f0d7b2a61e5c8f4"  # random-looking, not a real key


def nv(name, secret=False, value=None, kv=None):
    p = {"displayName": name, "secret": secret}
    if value is not None:
        p["value"] = value
    if kv:
        p["keyVault"] = {"secretIdentifier": kv, "lastStatus": {"code": "Success"}}
    return {"name": name, "properties": p}


RESP = {
    # advisory: prod sub listed with readable resources, dev sub listed but restricted
    f"/subscriptions/{SUB}/providers/Microsoft.ResourceHealth/events/MZK9-GH0": {"name": "MZK9-GH0"},
    f"/subscriptions/{SUB}/providers/Microsoft.ResourceHealth/events/MZK9-GH0/listSecurityAdvisoryImpactedResources":
        {"value": [{"properties": {"targetResourceId": APIM1}}]},
    f"/subscriptions/{SUB2}/providers/Microsoft.ResourceHealth/events/MZK9-GH0": {"name": "MZK9-GH0"},
    f"/subscriptions/{SUB2}/providers/Microsoft.ResourceHealth/events/MZK9-GH0/listSecurityAdvisoryImpactedResources": ArmError(403, "x", "forbidden"),
    f"/subscriptions/{SUB2}/providers/Microsoft.ResourceHealth/events/MZK9-GH0/impactedResources": ArmError(403, "x", "forbidden"),

    f"{APIM1}/namedValues": {"value": [
        nv("embedding-api-key", value=FAKE_KEY),
        nv("tenant-id", value="00000000-0000-0000-0000-0000000000aa"),
        nv("api-audience", value="00000000-0000-0000-0000-0000000000bb"),
        nv("orders-backend-url", value="https://backend.contoso.example/api"),
        nv("gpt-api-key", secret=True),
        nv("5f1c0e2a9b7d4e3f8a6b1c2d", secret=True),
        nv("llm-api-key", secret=True, kv="https://kv-contoso.vault.azure.net/secrets/llm-api-key"),
    ]},
    f"{APIM1}/backends": {"value": [
        {"name": "aoai", "properties": {"url": "https://aoai.contoso.example/openai",
                                        "credentials": {"header": {"api-key": ["{{5f1c0e2a9b7d4e3f8a6b1c2d}}"]}}}}]},
    f"{APIM1}/subscriptions": {"value": [
        {"name": "master", "properties": {"displayName": "Built-in all-access subscription", "scope": f"{APIM1}/apis", "state": "active"}},
        {"name": "app-a", "properties": {"displayName": "App A", "scope": f"{APIM1}/products/ai", "state": "active", "ownerId": f"{APIM1}/users/1"}},
        {"name": "app-b", "properties": {"displayName": "App B", "scope": f"{APIM1}/products/ai", "state": "suspended"}},
    ]},
    f"{APIM1}/products": {"value": [
        {"name": "ai", "properties": {"subscriptionRequired": True, "approvalRequired": True, "state": "published"}},
        {"name": "starter", "properties": {"subscriptionRequired": True, "approvalRequired": False, "state": "published"}}]},
    f"{APIM1}/tenant/access": {"properties": {"enabled": False}},
    f"{APIM1}/tenant/gitAccess": {"properties": {"enabled": False}},
    f"{APIM1}/portalsettings/signup": {"properties": {"enabled": True}},
    f"{APIM1}/identityProviders": {"value": [{"name": "aad"}]},
    f"{APIM1}/authorizationProviders": {"value": []},
    f"{APIM1}/namedValues/gpt-api-key": nv("gpt-api-key", secret=True),

    f"{APIM2}/namedValues": {"value": [nv("llm-api-key-dev", secret=True), nv("gpt-4o-api-key-LLM", secret=True)]},
    f"{APIM2}/backends": {"value": []},
    f"{APIM2}/subscriptions": {"value": [
        {"name": "master", "properties": {"displayName": "Built-in all-access subscription", "scope": f"{APIM2}/apis", "state": "active"}}]},
    f"{APIM2}/products": {"value": []},
    f"{APIM2}/tenant/access": {"properties": {"enabled": True}},
    f"{APIM2}/tenant/gitAccess": ArmError(404, "x", "nf"),
    f"{APIM2}/portalsettings/signup": {"properties": {"enabled": False}},
    f"{APIM2}/identityProviders": {"value": []},
    f"{APIM2}/authorizationProviders": {"value": [{"name": "github", "properties": {"identityProvider": "github"}}]},
    f"{APIM2}/products/starter": ArmError(404, "x", "nf"),
    f"{APIM2}/products/unlimited": ArmError(404, "x", "nf"),
    APIM2: {"identity": {"type": "None"}},
}


class FakeArm(Arm):
    def __init__(self, dry_run=True):
        super().__init__(token="fake", dry_run=dry_run)

    def request(self, method, path, api_version="x", body=None, headers=None, write=False):
        if write:
            self.log.append({"method": method, "url": path, "body": body, "applied": not self.dry_run})
            return {"dryRun": True}
        if path == "/providers/Microsoft.ResourceGraph/resources":
            return {"data": GRAPH}
        key = path.replace("https://management.azure.com", "").split("?")[0]
        if key not in RESP:
            raise ArmError(404, key, "not found")
        r = RESP[key]
        if isinstance(r, Exception):
            raise r
        return r
