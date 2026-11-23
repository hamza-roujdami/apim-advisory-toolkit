# Runbook: APIM Classic-tiers advisory (MZK9-GH0)

One pass per customer. Split the work: the **Infra/Security CSA** leads phases 1 and 3, the **AI CSA** leads the backend keys (Foundry, third-party LLM APIs) in phase 2 and phase 4, and the **CSAM** owns the support case and comms.

## Phase 0: Triage (day 0)
- [ ] Portal → Service Health → Security advisories → **MZK9-GH0**. Note the impacted subscriptions.
- [ ] Open a support case from the advisory if the customer needs confirmation for a specific instance.
- [ ] `apimtk run --customer <name>` and send the tracker and Markdown summary to the customer.
- [ ] Agree owners and dates. Use one Microsoft voice towards the customer.

## Phase 1: Contain (day 0-1)
- [ ] `apimtk remediate --instance <id> --containment` (dry run), then `--apply`
  - direct management API and Git access disabled
  - tenant access keys regenerated
  - system-assigned managed identity enabled
- [ ] Review who has Owner/Contributor/APIM Contributor on each instance. Anyone who can edit policies can get the instance's managed identity token.

## Phase 2: Rotate (day 1-5)
Order: **Critical** named values → **High** named values → Credential Manager → subscription keys.

| What | Where to rotate | Then |
|---|---|---|
| Plain value that looks like a key (Critical) | At the source, **now** | Key Vault → `link-keyvault` |
| Secret named values | LLM provider / Foundry (key 2 → switch → key 1) / Entra app secret | Key Vault → `link-keyvault` |
| GUID-named secrets | See the **Used by** column (usually backend credentials from an API import) | same |
| Credential Manager providers | The OAuth provider (Entra, GitHub, ...) | update the provider in APIM |
| Subscription keys | APIM: `regen-sub-keys --which secondary` → apps switch → `--which primary` | each app keeps its key in Key Vault |
| Built-in all-access key | APIM, both keys | don't use it in apps |

## Phase 3: Hunt (in parallel)
- [ ] `apimtk hunt --workspace-id <ws> --lookback 90d --app-id <ids of app regs whose secrets were in APIM>`
- [ ] Without access to the workspace: run with no `--workspace-id` and paste `out/hunt/*.kql` into Sentinel.
- [ ] Ask any third-party LLM provider for per-key usage on its keys. Their logs aren't in Azure.
- [ ] If anything looks suspicious: escalate through the CSAM to Microsoft Incident Response.

## Phase 4: Harden (week 2-4)
- [ ] `harden/bicep/secure-ai-gateway.bicep`: Key Vault named values, MI → Foundry, tenant access off
- [ ] Turn off key auth on Foundry/AOAI once APIM uses MI
- [ ] `harden/apim-policies/ai-gateway-api-policy.xml`: Entra token validation plus subscription key, token limits
- [ ] Assign `harden/policy/*` in Audit mode, then switch to Deny once migrated
- [ ] Developer portal: Entra ID only, sign-up off, or turn the portal off
- [ ] Plan the move to a v2 tier where it's available

## Done when
- No `Critical`/`High` findings on a re-run of `apimtk run`
- Every named value is either config or a Key Vault reference
- Each tracker row is `Done`, with the dates the keys were rotated at the source
