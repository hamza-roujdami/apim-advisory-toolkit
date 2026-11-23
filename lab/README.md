# Lab: test apimtk on real Classic APIM instances

Deploys **two Developer-tier (Classic) APIM instances** plus a Key Vault, seeded with every risk apimtk looks for.
Use a lab or sandbox subscription. **Never** a customer one.

| Instance | Seeded on purpose | apimtk should report |
|---|---|---|
| `apimtk-lab-a-*` | `embedding-api-key` stored as a plain value with a key-like string | **Critical**: clear-text key |
| | `gpt-api-key` secret stored in APIM, used by backend `aoai` | **High**, Used by = `backend:aoai` |
| | `llm-api-key` as a Key Vault reference | OK |
| | `tenant-id`, `backend-url` plain config | OK (must **not** be flagged) |
| | Direct management API **on** | **High** |
| | Portal sign-up **on** | Medium |
| | `ai-lab` product with no approval, subscription `app-a` | Medium, plus subscription keys High |
| `apimtk-lab-b-*` | No managed identity, 2 secrets in APIM (secrets-only pattern) | Medium (identity), 2 × High |

All "keys" are random strings generated when you deploy. They aren't real credentials.

## Run it
```bash
pip install -e ".[identity]" && az login && az account set -s <lab-sub>
./lab/run-lab.sh deploy you@contoso.com    # ~30-45 min
./lab/run-lab.sh before                    # expect: ALL PASSED (before)
./lab/run-lab.sh fix                       # shows the dry run, asks, then applies
./lab/run-lab.sh after                     # expect: ALL PASSED (after)
./lab/run-lab.sh teardown
```

**Cost:** Developer tier is billed per hour, about $50 a month per instance at list price. Tear down the same day.

**Not testable in the lab:** whether an instance is listed in the advisory. Your lab subscription isn't in MZK9-GH0, so `In advisory?` will show **No**, which is the correct result.

**If `deploy` fails on `llm-api-key`:** the Key Vault role assignment hadn't finished propagating. Run `deploy` again; it's idempotent.
