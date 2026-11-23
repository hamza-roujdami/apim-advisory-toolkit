"""01 - Assess: which APIM instances exist, which are Classic, which are named in the advisory."""
from __future__ import annotations

from .arm import HEALTH_API, Arm, ArmError

CLASSIC_SKUS = {"Developer", "Basic", "Standard", "Premium", "Consumption"}

APIM_QUERY = """
resources
| where type =~ 'microsoft.apimanagement/service'
| project id, name, resourceGroup, subscriptionId, location,
          sku = tostring(sku.name), capacity = toint(sku.capacity),
          vnetType = tostring(properties.virtualNetworkType),
          publicNetworkAccess = tostring(properties.publicNetworkAccess),
          gatewayUrl = tostring(properties.gatewayUrl),
          developerPortalUrl = tostring(properties.developerPortalUrl),
          identityType = tostring(identity.type)
| join kind=leftouter (
    resourcecontainers
    | where type =~ 'microsoft.resources/subscriptions'
    | project subscriptionId, subscriptionName = name
  ) on subscriptionId
| project-away subscriptionId1
| order by subscriptionName asc, name asc
"""


def is_classic(sku: str) -> bool:
    return sku in CLASSIC_SKUS  # v2 SKUs are BasicV2 / StandardV2 / PremiumV2


SEC_ADVISORY_API = "2025-05-01"


def _post_list(arm: Arm, path: str, api_version: str) -> list[dict]:
    items, url = [], path
    while url:
        page = arm.request("POST", url, api_version) if url == path else arm.request("GET", url)
        items.extend(page.get("value", []))
        url = page.get("nextLink")
    return items


def advisory_impacted(arm: Arm, subscription_id: str, tracking_id: str) -> tuple[set[str] | None, str | None]:
    """Resource ids the Service Health security advisory lists as impacted in this subscription.

    Uses listSecurityAdvisoryImpactedResources (security advisories), falling back to the
    generic impactedResources endpoint. Needs Service Health Security Reader, Owner/Contributor,
    or Microsoft.ResourceHealth/events/listSecurityAdvisoryImpactedResources/action.
    """
    path = f"/subscriptions/{subscription_id}/providers/Microsoft.ResourceHealth/events/{tracking_id}"
    event, err = arm.try_get(path, HEALTH_API)
    if err == "404":
        return set(), None  # event not raised for this subscription
    if err:
        return None, f"event read failed ({err})"
    try:
        items = _post_list(arm, f"{path}/listSecurityAdvisoryImpactedResources", SEC_ADVISORY_API)
    except ArmError as e:
        items, err = arm.try_list(f"{path}/impactedResources", HEALTH_API)
        if err:
            # Event exists for the sub but resource-level detail is restricted: treat whole sub as impacted.
            return {"*"}, (f"impacted resources not readable ({e.status}/{err}); subscription is listed on "
                           "the event - grant Service Health Security Reader to see resource-level detail")
    ids = set()
    for it in items:
        props = it.get("properties") or {}
        target = props.get("targetResourceId") or props.get("resourceId") or it.get("id", "")
        ids.add(target.lower())
    return ids or {"*"}, None


def run(arm: Arm, subscriptions: list[str] | None, tracking_id: str | None) -> list[dict]:
    rows = arm.resource_graph(APIM_QUERY, subscriptions)
    cache: dict[str, tuple[set[str] | None, str | None]] = {}
    for r in rows:
        r["classic"] = is_classic(r.get("sku", ""))
        r["inAdvisory"] = "n/a"
        r["advisoryNote"] = ""
        if tracking_id:
            sid = r["subscriptionId"]
            if sid not in cache:
                cache[sid] = advisory_impacted(arm, sid, tracking_id)
            ids, note = cache[sid]
            if ids is None:
                r["inAdvisory"], r["advisoryNote"] = "Unknown", note or ""
            elif "*" in ids or r["id"].lower() in ids:
                r["inAdvisory"], r["advisoryNote"] = "Yes", note or ""
            else:
                r["inAdvisory"] = "No"
        r["priority"] = priority(r)
    return rows


def priority(r: dict) -> str:
    if r.get("inAdvisory") == "Yes":
        return "P1"
    if r.get("classic") and r.get("inAdvisory") in ("Unknown", "n/a"):
        return "P2"
    if r.get("classic"):
        return "P3"
    return "P4"
