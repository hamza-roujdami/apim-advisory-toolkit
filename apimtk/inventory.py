"""02 - Inventory: what secrets, keys and risky settings live inside each APIM instance.

Never prints or stores secret values. Plain (non-secret) named values are only
inspected in memory to detect values that *look* like keys; the report keeps
the name, length and a verdict - not the value.
"""
from __future__ import annotations

import math
import re
from collections import Counter

from .arm import Arm

SECRETY_NAME = re.compile(r"(key|secret|password|passwd|pwd|token|sas|conn(ection)?str|credential|apikey)", re.I)
NOT_SECRET_NAME = re.compile(r"(url|uri|endpoint|host|origin|audience|scope|tenant|client-?id|region|version|name)$", re.I)
REF = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def looks_like_secret(name: str, value: str | None) -> bool:
    """Heuristic for plain named values that hold a key in clear text."""
    v = (value or "").strip()
    if not v or v.startswith(("http://", "https://", "api://")):
        return False
    guid = re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", v)
    if guid and NOT_SECRET_NAME.search(name):
        return False  # tenant-id, client-id, audience ...
    if SECRETY_NAME.search(name) and len(v) >= 16:
        return True
    if re.search(r"(AccountKey=|SharedAccessSignature|sig=|Password=)", v, re.I):
        return True
    token_like = re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{24,}", v)
    return bool(token_like and entropy(v) >= 3.5 and not guid)


def classify_named_value(nv: dict) -> dict:
    p = nv.get("properties", {})
    name = nv.get("name", "")
    display = p.get("displayName", name)
    kv = (p.get("keyVault") or {})
    out = {"name": name, "displayName": display, "secret": bool(p.get("secret")),
           "keyVaultSecretId": kv.get("secretIdentifier") or "", "length": None}
    if kv.get("secretIdentifier"):
        status = ((kv.get("lastStatus") or {}).get("code") or "").lower()
        out["type"] = "KeyVault"
        out["risk"] = "OK" if status in ("", "success") else "KV fetch failing"
    elif p.get("secret"):
        out["type"], out["risk"] = "Secret (stored in APIM)", "Rotate + move to Key Vault"
    else:
        value = p.get("value")
        out["length"] = len(value) if value else 0
        if looks_like_secret(display, value):
            out["type"], out["risk"] = "Plain value (looks like a key)", "Rotate NOW + move to Key Vault"
        else:
            out["type"], out["risk"] = "Plain value", "OK (config)"
    return out


def _finding(findings: list, sev: str, area: str, item: str, detail: str, action: str):
    findings.append({"severity": sev, "area": area, "item": item, "detail": detail, "action": action})


def run_instance(arm: Arm, inst: dict, deep: bool = False) -> dict:
    sid = inst["id"]
    data: dict = {"instance": inst, "errors": {}, "findings": []}
    f = data["findings"]

    # Named values
    nvs, err = arm.try_list(f"{sid}/namedValues")
    if err:
        data["errors"]["namedValues"] = err
    data["namedValues"] = [classify_named_value(nv) for nv in nvs]

    # Where each named value is referenced (backends always; policies with --deep)
    usage: dict[str, set[str]] = {}

    def scan(text: str, where: str):
        for m in REF.findall(text or ""):
            usage.setdefault(m, set()).add(where)

    backends, err = arm.try_list(f"{sid}/backends")
    if err:
        data["errors"]["backends"] = err
    data["backends"] = []
    for b in backends:
        p = b.get("properties", {})
        creds = p.get("credentials") or {}
        scan(str(creds), f"backend:{b.get('name')}")
        data["backends"].append({"name": b.get("name"), "url": p.get("url", ""),
                                 "usesCredentials": bool(creds), "authorization": bool(creds.get("authorization"))})

    if deep:
        pol, _ = arm.try_get(f"{sid}/policies/policy?format=rawxml")
        scan(((pol or {}).get("properties") or {}).get("value", ""), "policy:global")
        apis, _ = arm.try_list(f"{sid}/apis")
        for a in apis:
            ap, _ = arm.try_get(f"{a['id']}/policies/policy?format=rawxml")
            scan(((ap or {}).get("properties") or {}).get("value", ""), f"api:{a.get('name')}")
        for fr in arm.try_list(f"{sid}/policyFragments")[0]:
            fp, _ = arm.try_get(f"{fr['id']}?format=rawxml")
            scan(((fp or {}).get("properties") or {}).get("value", ""), f"fragment:{fr.get('name')}")

    for nv in data["namedValues"]:
        nv["usedBy"] = ", ".join(sorted(usage.get(nv["name"], set()) | usage.get(nv["displayName"], set())))
        if nv["type"].startswith("Plain value (looks"):
            _finding(f, "Critical", "Named value", nv["displayName"], "Key-like value stored in clear text",
                     "Rotate at source now; store in Key Vault; recreate as Key Vault named value")
        elif nv["type"].startswith("Secret"):
            _finding(f, "High", "Named value", nv["displayName"], "Secret stored inside APIM (not Key Vault)",
                     "Rotate at source; store in Key Vault; link named value to Key Vault")
        elif nv["risk"] == "KV fetch failing":
            _finding(f, "Medium", "Named value", nv["displayName"], "Key Vault fetch failing",
                     "Check APIM managed identity access to Key Vault")

    # Subscriptions & products
    subs, err = arm.try_list(f"{sid}/subscriptions")
    if err:
        data["errors"]["subscriptions"] = err
    data["subscriptions"] = [{
        "name": s.get("name"), "displayName": (s.get("properties") or {}).get("displayName") or "",
        "scope": ((s.get("properties") or {}).get("scope") or "").split("/")[-2:],
        "state": (s.get("properties") or {}).get("state"),
        "owner": ((s.get("properties") or {}).get("ownerId") or "").split("/")[-1],
    } for s in subs]
    data["subscriptionCount"] = len(subs)
    all_access = [s for s in data["subscriptions"]
                  if s["name"] == "master" or s["scope"] == ["", "apis"] or s["scope"][-1] == "apis"
                  or "all-access" in s["displayName"].lower()]
    active_subs = [s for s in data["subscriptions"] if s["state"] == "active"]
    if active_subs:
        _finding(f, "High", "Subscription keys", f"{len(active_subs)} active subscriptions",
                 "Keys may have been read before the fix",
                 "Map client apps to subscriptions; regenerate secondary -> swap -> regenerate primary")
    for s in all_access:
        if s["state"] == "active":
            _finding(f, "High", "Subscription keys", "Built-in all-access subscription",
                     "Key grants access to every API", "Regenerate both keys; never use in apps")

    products, _ = arm.try_list(f"{sid}/products")
    data["products"] = [{"name": p.get("name"),
                         "subscriptionRequired": (p.get("properties") or {}).get("subscriptionRequired"),
                         "approvalRequired": (p.get("properties") or {}).get("approvalRequired"),
                         "state": (p.get("properties") or {}).get("state")} for p in products]
    for p in data["products"]:
        if p["name"] in ("starter", "unlimited"):
            _finding(f, "Low", "Products", p["name"], "Default sample product present",
                     "Delete if unused (remediate: delete-default-products)")
        elif p["state"] == "published" and p["subscriptionRequired"] and not p["approvalRequired"]:
            _finding(f, "Medium", "Products", p["name"], "Self-service subscription without approval",
                     "Set approvalRequired=true")

    # Direct management API (tenant access) + Git access
    for kind in ("access", "gitAccess"):
        ta, err = arm.try_get(f"{sid}/tenant/{kind}")
        enabled = ((ta or {}).get("properties") or {}).get("enabled")
        data[f"tenant_{kind}_enabled"] = enabled if not err else f"unknown ({err})"
        if err:
            _finding(f, "Info", "Management plane", f"tenant/{kind}", f"Could not read setting ({err})",
                     "Check manually in portal: Deployment + infrastructure > Management API")
        elif enabled:
            _finding(f, "High" if kind == "access" else "Medium", "Management plane", f"tenant/{kind}",
                     "Legacy direct management / Git access enabled",
                     "Disable and regenerate keys (remediate: disable-tenant-access, regen-tenant-keys)")
        else:
            _finding(f, "Info", "Management plane", f"tenant/{kind}",
                     "Disabled - still regenerate its keys after the advisory",
                     "remediate: regen-tenant-keys")

    # Developer portal
    signup, err = arm.try_get(f"{sid}/portalsettings/signup")
    signup_enabled = ((signup or {}).get("properties") or {}).get("enabled")
    data["portalSignupEnabled"] = signup_enabled if not err else f"unknown ({err})"
    idps, _ = arm.try_list(f"{sid}/identityProviders")
    data["identityProviders"] = [i.get("name") for i in idps]
    if signup_enabled:
        _finding(f, "Medium", "Developer portal", "Username/password sign-up",
                 "Self sign-up enabled (see CVE-2025-66390 behaviour)",
                 "Disable sign-up; prefer Entra ID identity provider only")

    # Credential manager
    aps, _ = arm.try_list(f"{sid}/authorizationProviders")
    data["credentialManager"] = [{"name": a.get("name"),
                                  "provider": (a.get("properties") or {}).get("identityProvider")} for a in aps]
    if aps:
        _finding(f, "High", "Credential manager", f"{len(aps)} providers",
                 "OAuth client secrets stored in APIM", "Rotate client secrets in each identity provider")

    # Instance-level posture
    if inst.get("classic"):
        _finding(f, "Info", "Tier", inst.get("sku", ""), "Classic tier (advisory scope)",
                 "Plan migration to v2 tier where available")
    if "systemassigned" not in (inst.get("identityType") or "").lower().replace(" ", "") and \
       "userassigned" not in (inst.get("identityType") or "").lower().replace(" ", ""):
        _finding(f, "Medium", "Identity", "Managed identity", "No managed identity on APIM",
                 "Enable system-assigned identity (needed for Key Vault refs and MI auth to Foundry)")

    f.sort(key=lambda x: SEV_ORDER[x["severity"]])
    counts = Counter(x["severity"] for x in f)
    data["summary"] = {k: counts.get(k, 0) for k in SEV_ORDER}
    data["secretsInApim"] = sum(1 for nv in data["namedValues"]
                                if nv["type"].startswith(("Secret", "Plain value (looks")))
    return data


def run(arm: Arm, instances: list[dict], deep: bool = False, only_classic: bool = True) -> list[dict]:
    out = []
    for inst in instances:
        if only_classic and not inst.get("classic"):
            continue
        out.append(run_instance(arm, inst, deep))
    return out
