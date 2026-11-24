# APIM advisory report - lab

- Tracking ID: **MZK9-GH0**
- Generated: 2026-11-24
- Instances found: 3 | On an affected tier: 2 | In advisory: 0

| Priority | Instance | Tier | In advisory | Runtime | Credentials to rotate | Critical | High |
|---|---|---|---|---|---|---|---|
| P3 | apimtk-lab-a-xxxxxx | Developer | No | patched | 23 | 8 | 6 |
| P3 | apimtk-lab-b-xxxxxx | Developer | No | patched | 7 | 0 | 4 |
| P4 | apimtk-lab-c-xxxxxx | Consumption | No | - | - | - | - |

## apimtk-lab-a-xxxxxx

- **Critical** - func: query code: Credential written directly into the backend -> _Rotate at source; store in Key Vault; reference it as a Key Vault named value_
- **Critical** - legacy: header x-api-key: Credential written directly into the backend -> _Rotate at source; store in Key Vault; reference it as a Key Vault named value_
- **Critical** - api:export: ?sv, sp, sig: Key or signature written into a backend URL -> _Rotate at source (Function key, SAS, ...); move it to a Key Vault named value_
- **Critical** - policy:global: set-header "api-key": Credential written directly into policy XML -> _Rotate at source; store in Key Vault; replace with {{named value}}_
- **Critical** - product:ai-lab: set-header "x-partner-key": Credential written directly into policy XML -> _Rotate at source; store in Key Vault; replace with {{named value}}_
- **Critical** - operation:orders/create: authentication-basic password=: Credential written directly into policy XML -> _Rotate at source; store in Key Vault; replace with {{named value}}_
- **Critical** - fragment:legacy-auth: authentication-basic password=: Credential written directly into policy XML -> _Rotate at source; store in Key Vault; replace with {{named value}}_
- **Critical** - embedding-api-key: Key-like value stored in clear text -> _Rotate at source now; store in Key Vault; recreate as Key Vault named value_
- **High** - Built-in all-access subscription: Key grants access to every API -> _Regenerate both keys; never use in apps_
- **High** - 5 active subscriptions: Subscription keys are listed in the advisory -> _Map apps to subscriptions; secondary -> regenerate primary -> primary -> regenerate secondary_
- **High** - identity provider: aad: Client secret stored in APIM (listed in the advisory) -> _Create a new client secret at the provider; update APIM; remove the old secret_
- **High** - OAuth 2.0 server: oauth-test-console: OAuth 2.0 authorization server client secret stored in APIM -> _Create a new client secret at the issuer; update APIM; remove the old secret_
- **High** - OpenID Connect provider: entra-oidc: OpenID Connect client secret stored in APIM (listed in the advisory) -> _Create a new client secret at the issuer; update APIM; remove the old secret_
- **High** - credential provider: github: OAuth client secret stored in APIM -> _Rotate the client secret at the identity provider; update the provider in APIM_

## apimtk-lab-b-xxxxxx

- **High** - gpt-4o-api-key-LLM: Secret stored inside APIM (not Key Vault) -> _Rotate at source; store in Key Vault; link named value to Key Vault_
- **High** - llm-api-key-dev: Secret stored inside APIM (not Key Vault) -> _Rotate at source; store in Key Vault; link named value to Key Vault_
- **High** - Built-in all-access subscription: Key grants access to every API -> _Regenerate both keys; never use in apps_
- **High** - 3 active subscriptions: Subscription keys are listed in the advisory -> _Map apps to subscriptions; secondary -> regenerate primary -> primary -> regenerate secondary_
