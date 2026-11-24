# Lab results: end-to-end run on real Classic instances

Evidence from one run of the [test lab](../../lab/README.md) in a sandbox subscription on 24 Nov 2026. The lab deployed
two Developer-tier instances (A and B) and one Consumption instance (C), seeded with every credential type apimtk
looks for. All seeded "keys" were random fake values, and the lab has since been deleted.

Identifiers are sanitized: the subscription ID, the admin account, an Entra object ID and the resource-name suffix
were replaced with placeholders, and an unrelated APIM instance in the same subscription was removed. Nothing else
was changed.

| File | What it is |
|---|---|
| [APIM-advisory_lab_tracker.xlsx](APIM-advisory_lab_tracker.xlsx) | The Excel tracker apimtk produced |
| [lab_report.md](lab_report.md) | The Markdown summary |
| [assess.json](assess.json), [inventory.json](inventory.json) | Raw results (no secret values) |

## What was run

1. `./lab/run-lab.sh deploy`: deploy the seeded instances.
2. `./lab/run-lab.sh before`: `apimtk run`, then `lab/verify.py --phase before` checks each seeded risk was found. **All passed.**
3. `./lab/run-lab.sh fix`: dry run, then `remediate --apply`. It disabled the direct management API and
   regenerated its keys, enabled managed identity, turned off portal sign-up, linked `gpt-api-key` to Key Vault,
   and regenerated subscription keys.
4. `./lab/run-lab.sh after`: re-run and check that the fixed findings cleared. **All passed** (output below).

These files are from the `after` run. Credentials that must be rotated at their source (policy and backend keys,
client secrets, certificates) are still listed, as expected: the toolkit doesn't rotate those for you.

Not covered live: the Event Hubs logger scenario. A policy in the sandbox subscription forces SAS authentication off
on Event Hubs, so it was skipped (`EH_LOGGER=false`); the offline tests cover it.

## Checks (`lab/verify.py --phase after`)

```
  PASS  assess: both lab instances are on an affected tier
  PASS  A: embedding-api-key flagged as clear-text key
  PASS  A: tenant-id NOT flagged
  PASS  A: backend-url NOT flagged
  PASS  A: llm-api-key is a Key Vault reference
  PASS  A: all-access subscription flagged
  PASS  B: both secrets stored in APIM
  PASS  A: literal key in global policy
  PASS  A: password in operation policy
  PASS  A: literal key in backend legacy
  PASS  A: portal identity provider secret
  PASS  A: OAuth 2.0 server secret
  PASS  A: OpenID Connect provider secret
  PASS  A: recently registered user flagged
  PASS  A: API orders mapped to its backend URL
  PASS  A: literal key in product policy
  PASS  A: password in policy fragment
  PASS  A: Function key in backend query credentials
  PASS  A: signature in API service URL (?sig)
  PASS  A: URL secrets stored masked
  PASS  A: Credential Manager provider secret
  PASS  A: uploaded certificate
  PASS  A: backend client certificate
  PASS  C: Consumption instance assessed as not affected
  PASS  C: Consumption instance not inventoried
  PASS  A: gateway runtime version read
  PASS  A: gateway runtime patched (NSM thresholds)
  PASS  no secret values stored in inventory.json
  PASS  A: gpt-api-key now a Key Vault reference
  PASS  A: direct management API disabled
  PASS  A: portal sign-up disabled
  PASS  B: managed identity enabled

  runtime: A=0.53.32050.0 (patched), B=0.53.32050.0 (patched)

ALL PASSED (after)
```
