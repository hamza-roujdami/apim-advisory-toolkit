"""Minimal Azure Resource Manager client.

Auth order:
  1. azure-identity DefaultAzureCredential (if the package is installed)
  2. Azure CLI: `az account get-access-token`

Read operations are the default everywhere. Write operations only run from
the remediate module, and only with --apply.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

import requests

ARM = "https://management.azure.com"
APIM_API = "2024-05-01"
GRAPH_API = "2021-03-01"
HEALTH_API = "2022-10-01"
ACTIVITY_API = "2015-04-01"
# NSM: open https://<gateway-hostname>/internal-status-0123456789abcdef and read RuntimeVersion
RUNTIME_STATUS_PATH = "/internal-status-0123456789abcdef"
SECRET_FIELDS = {"clientsecret", "value", "connectionstring", "password", "instrumentationkey"}


def redact(obj: Any) -> Any:
    """Copy of a request body with secret-bearing fields masked, for logs."""
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SECRET_FIELDS and isinstance(v, str) else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


class ArmError(RuntimeError):
    def __init__(self, status: int, url: str, body: str):
        super().__init__(f"HTTP {status} on {url}: {body[:400]}")
        self.status = status
        self.url = url
        self.body = body


def _token_from_cli(scope: str) -> str:
    az = shutil.which("az")
    if not az:
        raise RuntimeError(
            "No credentials: install azure-identity (pip install azure-identity) "
            "or the Azure CLI and run `az login`."
        )
    resource = scope.replace("/.default", "")
    out = subprocess.run(
        [az, "account", "get-access-token", "--resource", resource, "-o", "json"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)["accessToken"]


def get_token(scope: str = "https://management.azure.com/.default") -> str:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore

        return DefaultAzureCredential(exclude_interactive_browser_credential=False).get_token(scope).token
    except ImportError:
        return _token_from_cli(scope)


@dataclass
class Arm:
    token: str | None = None
    dry_run: bool = True
    session: requests.Session = field(default_factory=requests.Session)
    log: list[dict] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def _headers(self, extra: dict | None = None) -> dict:
        if not self.token:
            self.token = get_token()
        h = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        if extra:
            h.update(extra)
        return h

    def _url(self, path: str, api_version: str) -> str:
        if path.startswith("http"):
            return path
        sep = "&" if "?" in path else "?"
        return f"{ARM}{path}{sep}api-version={api_version}"

    def request(self, method: str, path: str, api_version: str = APIM_API,
                body: Any = None, headers: dict | None = None, write: bool = False) -> Any:
        url = self._url(path, api_version)
        if write:
            self.log.append({"method": method, "url": url, "body": redact(body), "applied": not self.dry_run})
            if self.dry_run:
                return {"dryRun": True}
        for attempt in range(5):
            try:
                r = self.session.request(method, url, headers=self._headers(headers),
                                         data=json.dumps(body) if body is not None else None, timeout=60)
            except (requests.Timeout, requests.ConnectionError) as e:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise ArmError(0, url, f"{type(e).__name__} after retries") from e
            if r.status_code in (429, 500, 502, 503, 504) and attempt < 4:
                time.sleep(int(r.headers.get("Retry-After", 2 ** attempt)))
                continue
            if r.status_code >= 400:
                raise ArmError(r.status_code, url, r.text)
            if not r.text:
                return {}
            try:
                return r.json()
            except ValueError:
                return {"raw": r.text}
        raise ArmError(0, url, "retries exhausted")

    def get(self, path: str, api_version: str = APIM_API) -> Any:
        return self.request("GET", path, api_version)

    def list(self, path: str, api_version: str = APIM_API) -> Iterator[dict]:
        url: str | None = self._url(path, api_version)
        while url:
            page = self.request("GET", url)
            yield from page.get("value", [])
            url = page.get("nextLink")

    def try_get(self, path: str, api_version: str = APIM_API) -> tuple[Any, str | None]:
        """Return (result, error). Never raises on 4xx — inventory keeps going."""
        try:
            return self.get(path, api_version), None
        except ArmError as e:
            return None, f"{e.status}"

    def try_list(self, path: str, api_version: str = APIM_API) -> tuple[list, str | None]:
        try:
            return list(self.list(path, api_version)), None
        except ArmError as e:
            return [], f"{e.status}"

    def gateway_runtime_version(self, gateway_url: str) -> tuple[str | None, str | None]:
        """Read RuntimeVersion from the gateway status page (NSM check). Returns (version, error)."""
        try:
            r = self.session.get(gateway_url.rstrip("/") + RUNTIME_STATUS_PATH, timeout=10)
        except requests.RequestException as e:
            return None, type(e).__name__
        m = re.search(r"RuntimeVersion\W+(\d+(?:\.\d+)+)", r.text or "", re.I)
        if m:
            return m.group(1), None
        return None, f"HTTP {r.status_code}, no RuntimeVersion"

    def resource_graph(self, query: str, subscriptions: list[str] | None = None) -> list[dict]:
        rows: list[dict] = []
        body: dict[str, Any] = {"query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
        if subscriptions:
            body["subscriptions"] = subscriptions
        while True:
            res = self.request("POST", "/providers/Microsoft.ResourceGraph/resources", GRAPH_API, body)
            rows.extend(res.get("data", []))
            token = res.get("$skipToken")
            if not token:
                return rows
            body["options"]["$skipToken"] = token
