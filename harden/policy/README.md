# Azure Policy

| File | Effect | Purpose |
|---|---|---|
| `apim-namedvalues-keyvault.json` | Audit (or Deny) | No secret named value without a Key Vault reference |
| `apim-classic-tier-audit.json` | Audit | Inventory Classic-tier instances continuously |

**Prefer the built-in policy** *API Management secret named values should be stored in Azure Key Vault*
(definition id `f1cc7827-022c-473e-836e-5a51cae0b249`, Audit/Deny). It covers the same control as
`apim-namedvalues-keyvault.json`. See [Built-in policy definitions for API Management](https://learn.microsoft.com/azure/api-management/policy-reference).

```bash
az policy assignment create -n apim-nv-in-kv --scope /subscriptions/<sub-id> \
  --policy f1cc7827-022c-473e-836e-5a51cae0b249 --params '{"effect":{"value":"Audit"}}'
```

Before assigning anything else, also check the **built-in** API Management policies in your tenant
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
