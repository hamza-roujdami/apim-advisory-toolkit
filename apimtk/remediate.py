"""04 - Remediate: guided changes on one APIM instance.

Safety model
  * Dry run by default: every write is printed and logged, nothing is sent.
  * --apply sends the writes; each action still asks for confirmation unless --yes.
  * The toolkit never reads or writes secret values. Backend keys (third-party LLM providers,
    Foundry/AOAI, app registrations) are rotated at their source by the owner,
    stored in Key Vault, then linked here with `link-keyvault`.
"""
from __future__ import annotations

from typing import Callable

from .arm import Arm

IFMATCH = {"If-Match": "*"}


def _confirm(msg: str, yes: bool) -> bool:
    if yes:
        return True
    return input(f"{msg} [y/N] ").strip().lower() == "y"


def disable_tenant_access(arm: Arm, sid: str, **_):
    for kind in ("access", "gitAccess"):
        arm.request("PATCH", f"{sid}/tenant/{kind}", body={"properties": {"enabled": False}},
                    headers=IFMATCH, write=True)


def regen_tenant_keys(arm: Arm, sid: str, **_):
    for kind in ("access", "gitAccess"):
        for k in ("Primary", "Secondary"):
            arm.request("POST", f"{sid}/tenant/{kind}/regenerate{k}Key", write=True)


def regen_sub_keys(arm: Arm, sid: str, which: str = "secondary", subs: list[str] | None = None,
                   include_all_access: bool = True, **_):
    """Regenerate ONE key of each subscription. Run 'secondary' first, let apps
    switch to it, then run 'primary'."""
    if which not in ("primary", "secondary"):
        raise ValueError("which must be primary or secondary")
    targets = subs or [s["name"] for s in arm.list(f"{sid}/subscriptions")
                       if (s.get("properties") or {}).get("state") == "active"]
    if not include_all_access:
        targets = [t for t in targets if t != "master"]
    for name in targets:
        arm.request("POST", f"{sid}/subscriptions/{name}/regenerate{which.capitalize()}Key", write=True)
    return targets


def link_keyvault(arm: Arm, sid: str, named_value: str, secret_uri: str,
                  identity_client_id: str | None = None, **_):
    """Point an existing named value at a Key Vault secret (use a versionless URI
    so rotations in Key Vault flow to APIM automatically)."""
    cur = arm.get(f"{sid}/namedValues/{named_value}")
    p = cur.get("properties", {})
    kv = {"secretIdentifier": secret_uri}
    if identity_client_id:
        kv["identityClientId"] = identity_client_id
    body = {"properties": {"displayName": p.get("displayName", named_value), "secret": True,
                           "keyVault": kv, "tags": p.get("tags") or []}}
    arm.request("PUT", f"{sid}/namedValues/{named_value}", body=body, headers=IFMATCH, write=True)


def delete_default_products(arm: Arm, sid: str, **_):
    for prod in ("starter", "unlimited"):
        res, err = arm.try_get(f"{sid}/products/{prod}")
        if res and not err:
            arm.request("DELETE", f"{sid}/products/{prod}?deleteSubscriptions=true", headers=IFMATCH, write=True)


def disable_portal_signup(arm: Arm, sid: str, **_):
    arm.request("PUT", f"{sid}/portalsettings/signup",
                body={"properties": {"enabled": False, "termsOfService": {"enabled": False, "consentRequired": False}}},
                headers=IFMATCH, write=True)


def enable_managed_identity(arm: Arm, sid: str, **_):
    svc = arm.get(sid)
    ident = svc.get("identity") or {}
    t = (ident.get("type") or "None").replace(" ", "")
    if "SystemAssigned" in t:
        return
    body: dict = {"identity": {"type": "SystemAssigned"}}
    if "UserAssigned" in t:
        body["identity"] = {"type": "SystemAssigned, UserAssigned",
                            "userAssignedIdentities": {k: {} for k in (ident.get("userAssignedIdentities") or {})}}
    arm.request("PATCH", sid, body=body, write=True)


ACTIONS: dict[str, tuple[Callable, str]] = {
    "disable-tenant-access": (disable_tenant_access, "Disable legacy direct management API + Git access"),
    "regen-tenant-keys": (regen_tenant_keys, "Regenerate direct-management and Git access keys"),
    "regen-sub-keys": (regen_sub_keys, "Regenerate one key (primary|secondary) of each active subscription - BREAKS apps still using it"),
    "link-keyvault": (link_keyvault, "Convert a named value to a Key Vault reference"),
    "delete-default-products": (delete_default_products, "Delete Starter/Unlimited products and their subscriptions"),
    "disable-portal-signup": (disable_portal_signup, "Disable developer portal self sign-up"),
    "enable-managed-identity": (enable_managed_identity, "Enable system-assigned managed identity"),
}

CONTAINMENT = ["disable-tenant-access", "regen-tenant-keys", "enable-managed-identity"]


def run(arm: Arm, sid: str, actions: list[str], yes: bool, **kw) -> list[dict]:
    mode = "APPLY" if not arm.dry_run else "DRY RUN"
    for a in actions:
        fn, desc = ACTIONS[a]
        print(f"\n[{mode}] {a}: {desc}\n  target: {sid}")
        if not arm.dry_run and not _confirm("  Proceed?", yes):
            print("  skipped")
            continue
        start = len(arm.log)
        fn(arm, sid, **kw)
        for entry in arm.log[start:]:
            print(f"  {'SENT' if entry['applied'] else 'would send'}: {entry['method']} {entry['url']}")
    return arm.log
