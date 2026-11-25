# Copilot instructions: apim-advisory-toolkit

A public, community (not official Microsoft) CLI, `apimtk`, for customers affected by the November 2026 Azure API
Management Classic-tiers security advisory (Service Health tracking ID MZK9-GH0). Customers run it read-only against
their own tenant: it finds affected instances, lists every credential to rotate without reading secret values, flags
recent changes, and builds an Excel tracker.

## Hard rules
- **Public repo.** Never add customer names, tenant or subscription IDs, emails, internal role names, or anything
  specific to the maintainer's employer or job.
- **Every factual claim about the advisory must cite a public source.** Sources: Microsoft Learn, Microsoft Tech
  Community, NSM, or reputable news, linked in README "Sources". Never cite the non-public advisory text directly.
- **Keep it safe.**
  - Read-only by default; only `apimtk remediate --apply` writes to Azure.
  - Never call `listValue` or `listSecrets`, and never store or print secret values.
- **Keep the README short and customer-first.** Lead with "Run it on your Azure environment"; the lab is optional.

## Layout
- `apimtk/`: `arm.py` (REST client), `assess.py`, `inventory.py`, `report.py`, `hunt.py`, `remediate.py`, `cli.py`
- `tests/`: offline tests against a fake tenant (`fake_arm.py`)
- `kql/`: hunting queries
- `harden/`: example Policy, Bicep and policy XML (not deployment-tested)
- `lab/`: optional real-Azure test lab (`seed.bicep`, `run-lab.sh`, `verify.py`)
- `docs/`: runbook, diagrams, sanitized lab results
- `.github/watch/`: the daily source watch (see below)

## Commands
```bash
pip install -e ".[dev]" && pytest -q
python tests/make_fixtures.py   # after changing assess/inventory output or tests/fake_arm.py; test_fixtures_in_sync enforces it
apimtk --out out/demo demo --customer Contoso
```

## Things learned on real Azure (keep them)
- `?format=rawxml` policy GETs return a raw XML body (`Arm.request` yields `{"raw": text}`).
- The Activity log API rejects start times more than 90 days back, so the tool uses 89.
- ARM masks written-out backend credential values as `null`.
- Git access keys regenerate at `tenant/access/git/regenerate*Key`.
- NSM's runtime "x" is the third number of `RuntimeVersion` (e.g. `0.53.32050.0`).

## Handling "Source watch" issues
`.github/workflows/watch-sources.yml` opens a "review needed" issue when a watched source page changes or a new MSRC
CVE mentions API Management. When assigned one:
1. Read the diff in the issue and open the source link.
2. Decide what's affected: README "The advisory in brief" or "What it checks", `docs/RUNBOOK.md`, the NSM runtime
   thresholds in `apimtk/inventory.py` (`RUNTIME_THRESHOLDS`), or the credential coverage.
3. Make the smallest change that keeps the repo accurate, with the source linked.
4. Update tests and fixtures if code changed.
5. If nothing needs to change, say so in the PR description and change nothing.
6. If a watched page was only restructured ("Page layout changed"), update its markers in `.github/watch/sources.json`.

News-only updates go to the "Source watch: news coverage" issue and normally need no change.
