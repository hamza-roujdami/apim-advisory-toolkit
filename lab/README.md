# Lab: test apimtk on real Classic APIM instances

Deploys **two Developer-tier (Classic) APIM instances**, one **Consumption** instance, a Key Vault and a Basic Event
Hubs namespace, seeded with every credential type apimtk looks for. `deploy` needs `openssl` (for the test certificate).
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
| | Key written into the global policy; password in the `orders/create` operation policy | **Critical** × 2 |
| | Backend `legacy` with a key written into its headers | **Critical** |
| | Entra identity provider, OAuth 2.0 server, OpenID Connect provider with client secrets | **High** × 3 |
| | Event Hubs logger using a connection string | **High** |
| | Developer portal user registered at deploy time | Medium (review changes) |
| | API `orders` with a backend URL | Listed in the APIs & backends tab |
| | Key written into the `ai-lab` product policy; password in the `legacy-auth` policy fragment | **Critical** × 2 |
| | Backend `func` with a Function key in its query credentials; API `export` with a SAS `sig=` in its service URL | **Critical** × 2, URL stored masked |
| | Credential Manager provider `github` with a client secret | **High** |
| | Self-signed certificate uploaded to APIM, used by backend `mtls` | Medium × 2 |
| `apimtk-lab-b-*` | No managed identity, 2 secrets in APIM (secrets-only pattern) | Medium (identity), 2 × High |
| `apimtk-lab-c-*` | Consumption tier | Assessed as **not affected**, not inventoried |

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

**Cost:** about $0.15 an hour in total at list price (Developer tier $0.0658/hour per instance, Event Hubs Basic
$0.0198/hour). Tear down the same day.

The Consumption instance is billed per call (the first million calls a month are free).

**Not testable in the lab:** whether an instance is listed in the advisory. Your lab subscription isn't in MZK9-GH0, so `In advisory?` will show **No**, which is the correct result.

**If `deploy` fails on `eh-logger` with `LocalAuthDisabled`:** an Azure Policy in your subscription forces local
auth off on Event Hubs. Run `EH_LOGGER=false ./lab/run-lab.sh deploy ...` (and the same variable for `before`/`after`)
to skip that scenario; the offline tests still cover it.

**If `deploy` fails on `llm-api-key`:** the Key Vault role assignment hadn't finished propagating. Run `deploy` again; it's idempotent.
