# Runbook: APIM Classic-tiers advisory (MZK9-GH0)

One pass per organisation. Split the work: the **platform/security team** leads phases 1 and 3, the **application/AI team** owns the backend keys (Foundry, third-party LLM APIs) in phases 2 and 4, and one person owns the Microsoft support case and communications. If a Microsoft account team is helping you, agree these roles with them.

## Phase 0: Triage (day 0)
- [ ] Portal → Service Health → Security advisories → **MZK9-GH0**. Note the impacted subscriptions.
- [ ] Open a support case from the advisory if you need confirmation for a specific instance.
- [ ] `apimtk run --customer <name>` and share the tracker and Markdown summary with the owners.
- [ ] Check the **Runtime** column (NSM's runtime-version check). Any `vulnerable` instance: open a support case.
- [ ] Review the **Recent changes** tab and the `Review changes` findings: subscriptions, users and operations nobody recognises.
- [ ] Agree owners and dates for every row of the Credentials tab.

## Phase 1: Contain (day 0-1)
- [ ] `apimtk remediate --instance <id> --containment` (dry run), then `--apply`
  - direct management API and Git access disabled
  - tenant access keys regenerated
  - system-assigned managed identity enabled
- [ ] Review who has Owner/Contributor/APIM Contributor on each instance. Anyone who can edit policies can get the instance's managed identity token.

## Phase 2: Rotate (day 1-5)
Work down the **Credentials** tab: Critical → High → Medium. For every credential, Microsoft's order applies: create
the replacement at the issuer, update APIM, test, then revoke the old one. Updating APIM alone doesn't revoke anything.

| What | Where to rotate | Then |
|---|---|---|
| Key written into a policy or backend (Critical) | At the source, **now** | Key Vault → named value → replace the literal with `{{name}}` |
| Plain value that looks like a key (Critical) | At the source, **now** | Key Vault → `link-keyvault` |
| Secret named values | LLM provider / Foundry (key 2 → switch → key 1) / Entra app secret | Key Vault → `link-keyvault` |
| GUID-named secrets | See the **Used by** column (usually backend credentials from an API import) | same |
| Key Vault references | Rotate at the source, add a new version in Key Vault | versionless URIs refresh automatically |
| OAuth 2.0 / OpenID Connect / portal identity providers | The issuer (usually an Entra app registration) | `update-client-secret`, then delete the old secret at the issuer |
| Credential Manager providers | The OAuth provider (Entra, GitHub, ...) | update the provider in APIM |
| Event Hubs logger connection string | Event Hubs: renew the key | `link-keyvault` on its `Logger-Credentials--*` named value, or switch the logger to managed identity |
| Certificates | Reissue at the CA | store in Key Vault and reference it |
| Subscription keys | Apps → secondary; `regen-sub-keys --which primary`; apps → primary; `--which secondary` | each app keeps its key in Key Vault |
| Built-in all-access key | APIM, both keys | don't use it in apps |
| Direct management API / Git access keys | `regen-tenant-keys` | keep the API disabled |

## Phase 3: Hunt (in parallel)
- [ ] `apimtk hunt --workspace-id <ws> --lookback 90d --app-id <ids of app regs whose secrets were in APIM>`
- [ ] Without access to the workspace: run with no `--workspace-id` and paste `out/hunt/*.kql` into Sentinel.
- [ ] Ask any third-party LLM provider for per-key usage on its keys. Their logs aren't in Azure.
- [ ] Use the **APIs & backends** tab to list the data and systems behind each instance, and check their logs too.
- [ ] If anything looks suspicious: open a Microsoft support case and follow your incident response process. In Norway, NSM also asks to be contacted ([NSM](https://nsm.no/aktuelt/nsm-deler-tiltak-mot-sarbarhet-i-azure-api-management)).

## Phase 4: Harden (week 2-4)
- [ ] `harden/bicep/secure-ai-gateway.bicep`: Key Vault named values, MI → Foundry, tenant access off
- [ ] Turn off key auth on Foundry/AOAI once APIM uses MI
- [ ] `harden/apim-policies/ai-gateway-api-policy.xml`: Entra token validation plus subscription key, token limits
- [ ] Assign `harden/policy/*` in Audit mode, then switch to Deny once migrated
- [ ] Developer portal: Entra ID only, sign-up off, or turn the portal off
- [ ] Plan the move to a v2 tier where it's available

## Done when
- No `Critical`/`High` findings on a re-run of `apimtk run`
- Every named value is either config or a Key Vault reference, and no policy or backend holds a written-out key
- Every row of the Credentials tab has a rotated date and a revoked date
- Each tracker row is `Done`, with the dates the keys were rotated at the source
