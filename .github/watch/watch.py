"""Daily watch for changes that may require updating this repo.

Checks:
  - the pages the README relies on (sources.json "pages"): text between start/end markers, compared with state.json
  - new news articles about Azure API Management security (Google News RSS)
  - new MSRC CVEs whose title mentions API Management

Writes report.md (source or CVE changes: may need a repo update) and news.md (new articles), and updates state.json.
Exits 0 always; sets changed=true / news=true in $GITHUB_OUTPUT.
Standard library only.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

HERE = Path(__file__).parent
STATE = HERE / "state.json"
REPORT = HERE / "report.md"
NEWS = HERE / "news.md"
UA = {"User-Agent": "Mozilla/5.0 (apim-advisory-toolkit source watch)"}
BLOCK = {"p", "div", "li", "h1", "h2", "h3", "h4", "tr", "br", "section", "article", "pre", "table", "ul", "ol"}
SKIP = {"script", "style", "noscript", "svg", "head", "template"}


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in SKIP:
            self.skip += 1
        elif tag in BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in SKIP and self.skip:
            self.skip -= 1
        elif tag in BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def fetch(url: str) -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def page_text(html: str, start: str, end: str) -> str | None:
    parser = _Text()
    parser.feed(html)
    lines = [re.sub(r"\s+", " ", line).strip() for line in "".join(parser.parts).splitlines()]
    text = "\n".join(line for line in lines if line)
    i = text.find(start)
    if i < 0:
        return None
    j = text.find(end, i + len(start))
    return text[i : j if j > 0 else None].strip()


def check_pages(cfg: dict, state: dict) -> list[str]:
    out = []
    pages = state.setdefault("pages", {})
    for src in cfg["pages"]:
        old = pages.get(src["url"], {})
        try:
            text = page_text(fetch(src["url"]), src["start"], src["end"])
        except Exception as e:  # network or HTTP error: report, keep the old state
            out.append(f"### Couldn't read: [{src['name']}]({src['url']})\n\n`{type(e).__name__}: {e}`\n")
            continue
        if text is None:
            out.append(f"### Page layout changed: [{src['name']}]({src['url']})\n\nStart marker not found. "
                       f"Check the page and update `.github/watch/sources.json`.\n")
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        if old and old.get("sha256") != digest:
            diff = "\n".join(list(difflib.unified_diff(old.get("text", "").splitlines(), text.splitlines(),
                                                       "before", "after", lineterm="", n=1))[:40])
            out.append(f"### Changed: [{src['name']}]({src['url']})\n\n```diff\n{diff}\n```\n")
        pages[src["url"]] = {"sha256": digest, "text": text, "checked": _now()}
    return out


def check_news(cfg: dict, state: dict) -> list[str]:
    q = urllib.parse.quote(cfg["news_query"] + " when:3d")
    url = f"https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en"
    seen = set(state.setdefault("news_seen", []))
    first_run = not seen
    try:
        items = ET.fromstring(fetch(url)).findall("./channel/item")
    except Exception as e:
        return [f"### Couldn't read the news feed\n\n`{type(e).__name__}: {e}`\n"]
    new = []
    for item in items:
        title, link = item.findtext("title") or "", item.findtext("link") or ""
        key = hashlib.sha256(title.encode()).hexdigest()[:16]
        if key not in seen:
            seen.add(key)
            new.append(f"- [{title}]({link}) ({(item.findtext('pubDate') or '')[:16]})")
    state["news_seen"] = sorted(seen)[-500:]
    if first_run or not new:
        return []
    return ["### New articles\n\n" + "\n".join(new) + "\n"]


def check_msrc(cfg: dict, state: dict) -> list[str]:
    flt = urllib.parse.quote(f"contains(cveTitle,'{cfg['msrc_title_filter']}')")
    url = f"https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?$filter={flt}&$orderby=releaseDate%20desc"
    try:
        cves = json.loads(fetch(url)).get("value", [])
    except Exception as e:
        return [f"### Couldn't read the MSRC Security Update Guide\n\n`{type(e).__name__}: {e}`\n"]
    known = set(state.setdefault("msrc_cves", []))
    first_run = not known
    new = [c for c in cves if c.get("cveNumber") not in known]
    state["msrc_cves"] = sorted(known | {c["cveNumber"] for c in cves if c.get("cveNumber")})
    if first_run or not new:
        return []
    lines = [f"- [{c['cveNumber']}](https://msrc.microsoft.com/update-guide/vulnerability/{c['cveNumber']}): "
             f"{c.get('cveTitle', '')} ({(c.get('releaseDate') or '')[:10]})" for c in new]
    return ["### New MSRC CVEs mentioning API Management\n\n" + "\n".join(lines) + "\n"]


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def main() -> int:
    cfg = json.loads((HERE / "sources.json").read_text())
    state = json.loads(STATE.read_text()) if STATE.exists() else {}
    findings = check_pages(cfg, state) + check_msrc(cfg, state)
    news = check_news(cfg, state)
    state["last_run"] = _now()
    STATE.write_text(json.dumps(state, indent=1, ensure_ascii=False) + "\n")
    if findings:
        REPORT.write_text(
            "A source the README relies on changed, or there's a new CVE. Review it and update the README, "
            "docs/RUNBOOK.md or the toolkit if needed, then close this issue.\n\n" + "\n".join(findings))
    if news:
        NEWS.write_text(f"**{_now()[:10]}**\n\n" + "\n".join(news))
    print("\n".join(findings + news) or "No changes.")
    if gh := os.environ.get("GITHUB_OUTPUT"):
        with open(gh, "a") as f:
            f.write(f"changed={'true' if findings else 'false'}\nnews={'true' if news else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
