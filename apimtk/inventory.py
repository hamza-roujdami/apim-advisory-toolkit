"""02 - Inventory: credentials, signs of tampering and risky settings in each APIM instance.

Covers the credential types in Microsoft's rotation guide: subscription keys, named values,
backend credentials (headers, query parameters, client certificates), OAuth 2.0 and OpenID
Connect client secrets, developer portal identity providers, logger connection strings,
credentials written into policies, and the direct management API keys.

Never prints or stores secret values. Plain named values, backend credentials and policy XML
are inspected in memory to spot clear-text keys; only names, locations and verdicts are kept.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .arm import ACTIVITY_API, Arm

SECRETY_NAME = re.compile(r"(key|secret|password|passwd|pwd|token|sas|conn(ection)?str|credential|apikey|authorization)", re.I)
NOT_SECRET_NAME = re.compile(r"(url|uri|endpoint|host|origin|audience|scope|tenant|client-?id|region|version|name)$", re.I)
REF = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")
SECRET_IN_TEXT = re.compile(r"(AccountKey=|SharedAccessKey=|SharedAccessSignature\s|(?:[?&]|&amp;)sig=|Password=(?![\"'])|-----BEGIN [A-Z ]*PRIVATE KEY)", re.I)

SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

# NSM thresholds for patched Classic runtimes: 0.52.x >= 31936, 0.53.x >= 31938
RUNTIME_THRESHOLDS = {(0, 52): 31936, (0, 53): 31938}


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def looks_like_secret(name: str, value: str | None) -> bool:
    """Heuristic for clear-text values that hold a key."""
    v = (value or "").strip()
    if v.lower().startswith(("bearer ", "basic ")):
        v = v.split(None, 1)[1].strip() if " " in v else ""
    if not v or v.startswith(("http://", "https://", "api://")):
        return False
    guid = re.fullmatch(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", v)
    if guid and NOT_SECRET_NAME.search(name):
        return False  # tenant-id, client-id, audience ...
    if SECRETY_NAME.search(name) and len(v) >= 16:
        return True
    if SECRET_IN_TEXT.search(v):
        return True
    token_like = re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{24,}", v)
    return bool(token_like and entropy(v) >= 3.5 and not guid)


def is_literal(value: str | None) -> bool:
    """True when a configured value is written out rather than a {{named value}} or a policy expression."""
    v = (value or "").strip()
    return bool(v) and "{{" not in v and not v.startswith("@")


def runtime_status(version: str | None, affected_tier: bool = True) -> str:
    """Classify a gateway RuntimeVersion with NSM's thresholds.

    NSM writes the pattern as 0.52.x / 0.53.x; in the four-part version the gateway reports
    (for example 0.53.32050.0) x is the third number. Consumption and v2 gateways report other
    build ranges (NSM's examples: 0.53.4608.0, 0.52.4150.0), so the threshold only applies to
    affected tiers.
    """
    if not version:
        return "unknown"
    try:
        parts = [int(p) for p in version.split(".")]
    except ValueError:
        return "unknown"
    if len(parts) < 3:
        return "unknown"
    if not affected_tier:
        return "not applicable"
    minor, build = tuple(parts[:2]), parts[2]
    if minor in RUNTIME_THRESHOLDS:
        return "patched" if build >= RUNTIME_THRESHOLDS[minor] else "vulnerable"
    return "patched" if minor > max(RUNTIME_THRESHOLDS) else "vulnerable"


def scan_policy_secrets(xml: str) -> list[str]:
    """Describe (never return) credentials written directly into policy XML."""
    hits: list[str] = []
    for tag in ("set-header", "set-query-parameter"):
        for m in re.finditer(rf'<{tag}\b([^>]*?)(?<!/)>(.*?)</{tag}>', xml or "", re.S | re.I):
            nm = re.search(r'\bname="([^"]+)"', m.group(1))
            if not nm:
                continue
            name = nm.group(1)
            for v in re.findall(r"<value>(.*?)</value>", m.group(2), re.S):
                if is_literal(v) and (looks_like_secret(name, v) or (SECRETY_NAME.search(name) and len(v.strip()) >= 8)):
                    hits.append(f'{tag} "{name}"')
    for m in re.finditer(r'<([\w-]+)\b[^>]*?\b(password|client-secret|secret|subscription-key|api-key|connection-string|sas-token|access-key)="([^"]*)"',
                         xml or "", re.I):
        if is_literal(m.group(3)):
            hits.append(f'{m.group(1)} {m.group(2)}=')
    for m in re.finditer(r'<authentication-certificate\b[^>]*\bbody="([^"]*)"', xml or "", re.I):
        if is_literal(m.group(1)):
            hits.append("authentication-certificate body= (embedded certificate)")
    stripped = REF.sub("", xml or "")
    for m in SECRET_IN_TEXT.finditer(stripped):
        hits.append(f"text containing {m.group(1).replace('&amp;', '&').strip()}")
    return sorted(set(hits))


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
        out["risk"] = "Rotate in Key Vault" if status in ("", "success") else "KV fetch failing"
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


def _props(x: dict | None) -> dict:
    return (x or {}).get("properties") or {}


def _date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", s.replace("Z", "+00:00")))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


ACTIVITY_LOG_DAYS = 89  # the Activity log API rejects start times more than 90 days back


def default_since() -> str:
    """Look back as far as the Activity log allows."""
    return (datetime.now(timezone.utc) - timedelta(days=ACTIVITY_LOG_DAYS)).date().isoformat()


def _policy_xml(resp: dict | None) -> str:
    """format=rawxml returns the XML as the response body; other formats wrap it in properties.value."""
    return _props(resp).get("value") or (resp or {}).get("raw") or ""


def _url_credential(c: "_Collector", where: str, params: list[str]):
    if params:
        c.both("Critical", "URL", "Credential in URL", f"{where}: ?{', '.join(params)}", where, "Written into the URL",
               "Key or signature written into the URL",
               "Rotate at source (Function key, SAS, ...); move it to a Key Vault named value")


class _Collector:
    def __init__(self, data: dict):
        self.data = data

    def finding(self, sev: str, area: str, item: str, detail: str, action: str):
        self.data["findings"].append({"severity": sev, "area": area, "item": item, "detail": detail, "action": action})

    def credential(self, kind: str, name: str, where: str, stored: str, action: str, sev: str):
        self.data["credentials"].append({"kind": kind, "name": name, "where": where, "stored": stored,
                                         "action": action, "severity": sev})

    def both(self, sev: str, area: str, kind: str, name: str, where: str, stored: str, detail: str, action: str):
        self.credential(kind, name, where, stored, action, sev)
        self.finding(sev, area, name, detail, action)


def _named_values(arm: Arm, sid: str, data: dict, c: _Collector):
    nvs, err = arm.try_list(f"{sid}/namedValues")
    if err:
        data["errors"]["namedValues"] = err
    data["namedValues"] = [classify_named_value(nv) for nv in nvs]


def _backends(arm: Arm, sid: str, data: dict, c: _Collector, scan):
    backends, err = arm.try_list(f"{sid}/backends")
    if err:
        data["errors"]["backends"] = err
    data["backends"] = []
    for b in backends:
        p, name = _props(b), b.get("name")
        creds = p.get("credentials") or {}
        scan(str(creds), f"backend:{name}")
        url, url_secrets = safe_url(p.get("url"))
        data["backends"].append({"name": name, "url": url, "usesCredentials": bool(creds)})
        _url_credential(c, f"backend:{name}", url_secrets)
        # ARM returns {{named value}} references as text but masks written-out values as null
        literal = []
        for part in ("header", "query"):
            for k, vals in (creds.get(part) or {}).items():
                if vals is None or any(v is None for v in vals):
                    literal.append((part, k, True))
                    continue
                for v in vals:
                    if is_literal(v):
                        literal.append((part, k, looks_like_secret(k, v) or bool(SECRETY_NAME.search(k))))
        auth = creds.get("authorization") or {}
        if auth and ("parameter" in auth) and (auth["parameter"] is None or is_literal(auth["parameter"])):
            literal.append(("authorization", auth.get("scheme") or "", True))
        for part, k, secret in literal:
            sev = "Critical" if secret else "Medium"
            c.both(sev, "Backend", "Backend credential", f"{name}: {part} {k}".strip(), f"backend:{name}",
                   "Written into the backend", "Credential written directly into the backend" if secret
                   else "Literal value in backend credentials - check whether it is a secret",
                   "Rotate at source; store in Key Vault; reference it as a Key Vault named value")
        if creds.get("certificateIds") or creds.get("certificate"):
            c.both("Medium", "Backend", "Client certificate", f"{name}: client certificate", f"backend:{name}",
                   "Certificate in APIM", "Backend authenticates with a client certificate",
                   "Reissue the certificate; store it in Key Vault")


URL_SECRET_PARAM = re.compile(r"^(code|sig|key|apikey|api-key|api_key|token|access_token|secret|password|sas)$", re.I)


def safe_url(url: str | None) -> tuple[str, list[str]]:
    """URL with query values masked, plus the names of query parameters that look like credentials."""
    url = url or ""
    base, _, query = url.partition("?")
    if not query:
        return url, []
    names = [kv.split("=", 1)[0] for kv in query.split("&") if kv]
    secret = [n for n in names if URL_SECRET_PARAM.match(n)]
    return f"{base}?{'&'.join(n + '=***' for n in names)}", secret


def _id(parent: str, kind: str, item: dict) -> str:
    return item.get("id") or f"{parent}/{kind}/{item.get('name')}"


def _policies(arm: Arm, sid: str, data: dict, c: _Collector, scan):
    """Scan global, product, API, operation and fragment policies."""
    def check(path: str, where: str):
        pol, _ = arm.try_get(f"{path}?format=rawxml")
        xml = _policy_xml(pol)
        if not xml:
            return
        data["policiesScanned"] += 1
        scan(xml, where)
        for hit in scan_policy_secrets(xml):
            c.both("Critical", "Policy", "Credential in policy", f"{where}: {hit}", where, "Written into the policy",
                   "Credential written directly into policy XML",
                   "Rotate at source; store in Key Vault; replace with {{named value}}")

    data["policiesScanned"] = 0
    check(f"{sid}/policies/policy", "policy:global")
    for prod in data["_products_raw"]:
        check(f"{_id(sid, 'products', prod)}/policies/policy", f"product:{prod.get('name')}")
    for a in data["_apis_raw"]:
        api_id = _id(sid, "apis", a)
        check(f"{api_id}/policies/policy", f"api:{a.get('name')}")
        for op in arm.try_list(f"{api_id}/operations")[0]:
            check(f"{_id(api_id, 'operations', op)}/policies/policy", f"operation:{a.get('name')}/{op.get('name')}")
    for fr in arm.try_list(f"{sid}/policyFragments")[0]:
        check(_id(sid, "policyFragments", fr), f"fragment:{fr.get('name')}")


def _identity_secrets(arm: Arm, sid: str, data: dict, c: _Collector):
    idps, _ = arm.try_list(f"{sid}/identityProviders")
    data["identityProviders"] = [i.get("name") for i in idps]
    for i in idps:
        c.both("High", "Developer portal", "Identity provider secret", f"identity provider: {i.get('name')}",
               "Developer portal > Identities", "Stored in APIM", "Client secret stored in APIM (listed in the advisory)",
               "Create a new client secret at the provider; update APIM; remove the old secret")

    servers, _ = arm.try_list(f"{sid}/authorizationServers")
    data["oauth2Servers"] = [s.get("name") for s in servers]
    for s in servers:
        c.both("High", "Developer portal", "OAuth 2.0 client secret", f"OAuth 2.0 server: {s.get('name')}",
               "Developer portal > OAuth 2.0 + OpenID Connect", "Stored in APIM",
               "OAuth 2.0 authorization server client secret stored in APIM",
               "Create a new client secret at the issuer; update APIM; remove the old secret")

    oidc, _ = arm.try_list(f"{sid}/openidConnectProviders")
    data["openidConnectProviders"] = [o.get("name") for o in oidc]
    for o in oidc:
        c.both("High", "Developer portal", "OpenID Connect client secret", f"OpenID Connect provider: {o.get('name')}",
               "Developer portal > OAuth 2.0 + OpenID Connect", "Stored in APIM",
               "OpenID Connect client secret stored in APIM (listed in the advisory)",
               "Create a new client secret at the issuer; update APIM; remove the old secret")

    aps, _ = arm.try_list(f"{sid}/authorizationProviders")
    data["credentialManager"] = [{"name": a.get("name"), "provider": _props(a).get("identityProvider")} for a in aps]
    for a in data["credentialManager"]:
        c.both("High", "Credential manager", "Credential Manager secret", f"credential provider: {a['name']}",
               f"Credential manager ({a['provider']})", "Stored in APIM", "OAuth client secret stored in APIM",
               "Rotate the client secret at the identity provider; update the provider in APIM")


def _loggers(arm: Arm, sid: str, data: dict, c: _Collector, scan):
    loggers, _ = arm.try_list(f"{sid}/loggers")
    data["loggers"] = []
    for lg in loggers:
        p, name = _props(lg), lg.get("name")
        creds = p.get("credentials") or {}
        scan(str(creds), f"logger:{name}")
        ltype = p.get("loggerType") or ""
        data["loggers"].append({"name": name, "type": ltype,
                                "managedIdentity": bool(creds.get("identityClientId"))})
        conn = creds.get("connectionString")
        if ltype == "azureEventHub" and conn:
            refs = REF.findall(conn)
            stored = f"named value {refs[0]}" if refs else "Written into the logger"
            c.finding("High", "Logger", f"logger: {name}", f"Event Hubs connection string stored in APIM ({stored})",
                      "Renew the Event Hubs key; better: switch the logger to managed identity")
            if not refs:  # a referenced named value already has its own credential row
                c.credential("Connection string", f"logger: {name}", f"logger:{name}", stored,
                             "Renew the Event Hubs key; better: switch the logger to managed identity", "High")
        elif ltype == "applicationInsights" and (creds.get("instrumentationKey") or creds.get("connectionString")):
            data["_aiLoggers"].add(f"logger:{name}")
            c.finding("Info", "Logger", f"logger: {name}", "Application Insights key stored in APIM",
                      "Ingestion-only key, not an access credential; prefer Entra authentication for ingestion")


def _certificates(arm: Arm, sid: str, data: dict, c: _Collector):
    certs, _ = arm.try_list(f"{sid}/certificates")
    data["certificates"] = []
    for ct in certs:
        p = _props(ct)
        kv = (p.get("keyVault") or {}).get("secretIdentifier")
        data["certificates"].append({"name": ct.get("name"), "subject": p.get("subject"),
                                     "expires": p.get("expirationDate"), "keyVault": bool(kv)})
        c.credential("Certificate", f"certificate: {ct.get('name')}", "Certificates",
                     "Key Vault" if kv else "Uploaded to APIM",
                     "Reissue at the CA; store in Key Vault" if not kv else "Reissue in Key Vault", "Medium")
        if not kv:
            c.finding("Medium", "Certificates", ct.get("name") or "", "Certificate with private key uploaded to APIM",
                      "Reissue the certificate; store it in Key Vault and reference it")


def _subscriptions(arm: Arm, sid: str, data: dict, c: _Collector, since: datetime):
    subs, err = arm.try_list(f"{sid}/subscriptions")
    if err:
        data["errors"]["subscriptions"] = err
    data["subscriptions"] = [{
        "name": s.get("name"), "displayName": _props(s).get("displayName") or "",
        "scope": (_props(s).get("scope") or "").split("/")[-2:],
        "state": _props(s).get("state"),
        "owner": (_props(s).get("ownerId") or "").split("/")[-1],
        "created": _props(s).get("createdDate"),
    } for s in subs]
    data["subscriptionCount"] = len(subs)
    for s in data["subscriptions"]:
        if s["state"] != "active":
            continue
        all_access = s["name"] == "master" or s["scope"][-1:] == ["apis"] or "all-access" in s["displayName"].lower()
        c.credential("Subscription key", f"subscription: {s['displayName'] or s['name']}",
                     "/".join(s["scope"]) or "-", "Stored in APIM",
                     "Regenerate both keys; never use in apps" if all_access
                     else "Move app to secondary key; regenerate primary; move app back; regenerate secondary", "High")
        if all_access:
            c.finding("High", "Subscription keys", "Built-in all-access subscription",
                      "Key grants access to every API", "Regenerate both keys; never use in apps")
        created = _date(s["created"])
        if created and created >= since:
            c.finding("Medium", "Review changes", f"subscription: {s['displayName'] or s['name']}",
                      f"Created {created.date()} - confirm you created it", "Suspend or delete if unknown")
    active = [s for s in data["subscriptions"] if s["state"] == "active"]
    if active:
        c.finding("High", "Subscription keys", f"{len(active)} active subscriptions",
                  "Subscription keys are listed in the advisory",
                  "Map apps to subscriptions; secondary -> regenerate primary -> primary -> regenerate secondary")


def _users(arm: Arm, sid: str, data: dict, c: _Collector, since: datetime):
    users, _ = arm.try_list(f"{sid}/users")
    data["users"] = []
    for u in users:
        p = _props(u)
        reg = _date(p.get("registrationDate"))
        data["users"].append({"name": u.get("name"), "email": p.get("email"), "state": p.get("state"),
                              "registered": p.get("registrationDate"),
                              "identities": [i.get("provider") for i in p.get("identities") or []]})
        if reg and reg >= since and p.get("state") == "active":
            c.finding("Medium", "Review changes", f"user: {p.get('email') or u.get('name')}",
                      f"Registered {reg.date()} - confirm you know this user", "Block or delete if unknown")


def _activity(arm: Arm, inst: dict, data: dict, c: _Collector, since: datetime):
    """Write and secret-read operations on the instance from the Azure Activity log (90-day retention)."""
    sub, rg, iid = inst.get("subscriptionId"), inst.get("resourceGroup"), inst["id"].lower()
    start = max(since, datetime.now(timezone.utc) - timedelta(days=ACTIVITY_LOG_DAYS))
    flt = quote(f"eventTimestamp ge '{start.strftime('%Y-%m-%dT%H:%M:%SZ')}' and resourceGroupName eq '{rg}'")
    events, err = arm.try_list(f"/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values"
                               f"?$filter={flt}&$select=eventTimestamp,operationName,caller,resourceId,status", ACTIVITY_API)
    if err:
        data["errors"]["activityLog"] = err
    groups: dict[tuple, dict] = {}
    for e in events:
        rid = (e.get("resourceId") or "").lower()
        if rid != iid and not rid.startswith(iid + "/"):
            continue
        if ((e.get("status") or {}).get("value") or "").lower() == "started":
            continue  # each operation also logs Succeeded/Failed; count it once
        op = (e.get("operationName") or {}).get("value") or ""
        if op.lower().endswith("/read"):
            continue  # reads are noise; secret reads are /action operations (listValue, listSecrets)
        caller = e.get("caller") or ""
        ts = e.get("eventTimestamp") or ""
        g = groups.setdefault((caller, op), {"caller": caller, "operation": op, "count": 0, "first": ts, "last": ts})
        g["count"] += 1
        g["first"], g["last"] = min(g["first"], ts), max(g["last"], ts)
    data["recentChanges"] = sorted(groups.values(), key=lambda g: g["last"], reverse=True)
    reads = [g for g in data["recentChanges"] if re.search(r"(listValue|listSecrets|listKeys)", g["operation"], re.I)]
    if reads:
        callers = sorted({g["caller"] for g in reads})
        c.finding("Medium", "Review changes", "Secret reads in Activity log",
                  f"{sum(g['count'] for g in reads)} secret reads by {', '.join(callers)[:200]}",
                  "Confirm each caller is expected")
    writes = [g for g in data["recentChanges"] if g not in reads]
    if writes:
        c.finding("Info", "Review changes", "Management operations in Activity log",
                  f"{sum(g['count'] for g in writes)} operations by {len({g['caller'] for g in writes})} callers since "
                  f"{since.date()}", "Review the Recent changes tab for anything you didn't do")


def run_instance(arm: Arm, inst: dict, since: str | None = None, runtime_check: bool = True) -> dict:
    sid = inst["id"]
    since_dt = _date(since or default_since()) or datetime.now(timezone.utc)
    data: dict = {"instance": inst, "errors": {}, "findings": [], "credentials": [], "since": since_dt.date().isoformat()}
    c = _Collector(data)
    usage: dict[str, set[str]] = {}

    def scan(text: str, where: str):
        for m in REF.findall(text or ""):
            usage.setdefault(m, set()).add(where)

    _named_values(arm, sid, data, c)
    _backends(arm, sid, data, c, scan)

    products, _ = arm.try_list(f"{sid}/products")
    apis, _ = arm.try_list(f"{sid}/apis")
    data["_products_raw"], data["_apis_raw"], data["_aiLoggers"] = products, apis, set()
    data["apis"] = []
    for a in apis:
        url, url_secrets = safe_url(_props(a).get("serviceUrl"))
        data["apis"].append({"name": a.get("name"), "path": _props(a).get("path"), "serviceUrl": url,
                             "subscriptionRequired": _props(a).get("subscriptionRequired")})
        _url_credential(c, f"api:{a.get('name')}", url_secrets)
    _policies(arm, sid, data, c, scan)
    _loggers(arm, sid, data, c, scan)
    ai_loggers = data.pop("_aiLoggers")
    del data["_products_raw"], data["_apis_raw"]

    # Named value findings, now that usage is known
    for nv in data["namedValues"]:
        used = usage.get(nv["name"], set()) | usage.get(nv["displayName"], set())
        nv["usedBy"] = ", ".join(sorted(used))
        where = nv["usedBy"] or "-"
        if used and used <= ai_loggers:
            nv["risk"] = "OK (Application Insights ingestion key)"
        elif nv["type"].startswith("Plain value (looks"):
            c.both("Critical", "Named value", "Named value", nv["displayName"], where, "Clear text in APIM",
                   "Key-like value stored in clear text",
                   "Rotate at source now; store in Key Vault; recreate as Key Vault named value")
        elif nv["type"].startswith("Secret"):
            c.both("High", "Named value", "Named value", nv["displayName"], where, "Secret in APIM",
                   "Secret stored inside APIM (not Key Vault)",
                   "Rotate at source; store in Key Vault; link named value to Key Vault")
        elif nv["type"] == "KeyVault":
            c.credential("Named value", nv["displayName"], where, "Key Vault reference",
                         "Rotate the secret at source; add a new version in Key Vault", "Medium")
            if nv["risk"] == "KV fetch failing":
                c.finding("Medium", "Named value", nv["displayName"], "Key Vault fetch failing",
                          "Check APIM managed identity access to Key Vault")
    kv_nvs = [nv for nv in data["namedValues"] if nv["type"] == "KeyVault"]
    if kv_nvs:
        c.finding("Medium", "Named value", f"{len(kv_nvs)} Key Vault references",
                  "Values can be read through policies or tracing by anyone who could manage APIM",
                  "Rotate the referenced secrets at source and add new versions in Key Vault")

    _subscriptions(arm, sid, data, c, since_dt)

    data["products"] = [{"name": p.get("name"), "subscriptionRequired": _props(p).get("subscriptionRequired"),
                         "approvalRequired": _props(p).get("approvalRequired"), "state": _props(p).get("state")}
                        for p in products]
    for p in data["products"]:
        if p["name"] in ("starter", "unlimited"):
            c.finding("Low", "Products", p["name"], "Default sample product present",
                      "Delete if unused (remediate: delete-default-products)")
        elif p["state"] == "published" and p["subscriptionRequired"] and not p["approvalRequired"]:
            c.finding("Medium", "Products", p["name"], "Self-service subscription without approval",
                      "Set approvalRequired=true")

    # Direct management API (tenant access) + Git access: their keys sign the management tokens in the advisory
    for kind in ("access", "gitAccess"):
        ta, err = arm.try_get(f"{sid}/tenant/{kind}")
        enabled = _props(ta).get("enabled")
        data[f"tenant_{kind}_enabled"] = enabled if not err else f"unknown ({err})"
        label = "Direct management API" if kind == "access" else "Git access"
        if err:
            c.finding("Info", "Management plane", f"tenant/{kind}", f"Could not read setting ({err})",
                      "Check manually in portal: Deployment + infrastructure > Management API")
            continue
        c.credential("Management API keys", f"{label} keys", f"tenant/{kind}", "Stored in APIM",
                     "Disable, then regenerate both keys (remediate: disable-tenant-access, regen-tenant-keys)",
                     "High" if enabled else "Medium")
        if enabled:
            c.finding("High" if kind == "access" else "Medium", "Management plane", f"tenant/{kind}",
                      f"{label} enabled", "Disable and regenerate keys (remediate: disable-tenant-access, regen-tenant-keys)")
        else:
            c.finding("Medium", "Management plane", f"tenant/{kind}",
                      "Disabled - regenerate its keys anyway (tokens are listed in the advisory)",
                      "remediate: regen-tenant-keys")

    _identity_secrets(arm, sid, data, c)
    _certificates(arm, sid, data, c)
    _users(arm, sid, data, c, since_dt)
    _activity(arm, inst, data, c, since_dt)

    signup, err = arm.try_get(f"{sid}/portalsettings/signup")
    signup_enabled = _props(signup).get("enabled")
    data["portalSignupEnabled"] = signup_enabled if not err else f"unknown ({err})"
    if signup_enabled:
        c.finding("Medium", "Developer portal", "Username/password sign-up", "Self sign-up enabled",
                  "Disable sign-up; prefer Entra ID identity provider only")

    if inst.get("affectedTier"):
        c.finding("Info", "Tier", inst.get("sku", ""), "Classic tier named in the advisory",
                  "Plan migration to a v2 tier where available")
    ident = (inst.get("identityType") or "").lower().replace(" ", "")
    if "systemassigned" not in ident and "userassigned" not in ident:
        c.finding("Medium", "Identity", "Managed identity", "No managed identity on APIM",
                  "Enable system-assigned identity (needed for Key Vault refs and MI auth to backends)")

    data["runtimeVersion"], data["runtimeStatus"] = None, "not checked"
    if runtime_check and inst.get("gatewayUrl"):
        version, err = arm.gateway_runtime_version(inst["gatewayUrl"])
        data["runtimeVersion"], data["runtimeStatus"] = version, runtime_status(version, bool(inst.get("affectedTier")))
        if data["runtimeStatus"] == "vulnerable":
            c.finding("Critical", "Runtime", version or "", "Gateway runtime is below NSM's patched thresholds",
                      "Contact Microsoft support")
        elif data["runtimeStatus"] == "unknown":
            c.finding("Info", "Runtime", "RuntimeVersion", f"Could not read the gateway status page ({err or version})",
                      "Check manually: https://<gateway>/internal-status-0123456789abcdef (see README)")

    data["findings"].sort(key=lambda x: SEV_ORDER[x["severity"]])
    data["credentials"].sort(key=lambda x: (SEV_ORDER[x["severity"]], x["kind"], x["name"]))
    counts = Counter(x["severity"] for x in data["findings"])
    data["summary"] = {k: counts.get(k, 0) for k in SEV_ORDER}
    data["credentialCount"] = len(data["credentials"])
    data["secretsInApim"] = sum(1 for nv in data["namedValues"] if nv["type"].startswith(("Secret", "Plain value (looks"))
                                and not nv["risk"].startswith("OK"))
    return data


def run(arm: Arm, instances: list[dict], since: str | None = None, include_unaffected: bool = False,
        runtime_check: bool = True) -> list[dict]:
    return [run_instance(arm, inst, since, runtime_check) for inst in instances
            if include_unaffected or inst.get("affectedTier")]
