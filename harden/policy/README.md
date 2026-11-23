# Azure Policy

| File | Effect | Purpose |
|---|---|---|
| `apim-namedvalues-keyvault.json` | Audit (or Deny) | No secret named value without a Key Vault reference |
| `apim-classic-tier-audit.json` | Audit | Inventory Classic-tier instances continuously |

Before assigning, also check the **built-in** API Management policies in your tenant
(Portal → Policy → Definitions → Category "API Management") and prefer a built-in where one
covers the same control. Validate aliases first:

```bash
az provider show -n Microsoft.ApiManagement --expand "resourceTypes/aliases" \
  --query "resourceTypes[?resourceType=='service/namedValues'].aliases[].name"
```

Deploy:

```bash
az policy definition create -n apim-nv-keyvault --rules <(jq .properties.policyRule apim-namedvalues-keyvault.json) \
  --params <(jq .properties.parameters apim-namedvalues-keyvault.json) --mode All \
  --display-name "APIM secret named values must reference Key Vault"
az policy assignment create -n apim-nv-keyvault --policy apim-nv-keyvault --scope /subscriptions/<sub-id> \
  --params '{"effect":{"value":"Audit"}}'
```

Start with **Audit**; switch to **Deny** once existing named values are migrated.
