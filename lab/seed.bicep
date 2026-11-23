// LAB ONLY - deploys two Classic (Developer tier) APIM instances seeded with the
// risky settings apimtk is meant to find, plus a Key Vault for the fix path.
// All "keys" are random GUID-derived strings generated at deploy time - not real credentials.
//
//   az group create -n rg-apimtk-lab -l uaenorth
//   az deployment group create -g rg-apimtk-lab -f lab/seed.bicep -p publisherEmail=<you@contoso.com>
//
// Provisioning takes ~30-45 min per instance (they deploy in parallel). Delete the RG when done.

targetScope = 'resourceGroup'

@description('Publisher email required by APIM')
param publisherEmail string

param location string = resourceGroup().location
param prefix string = 'apimtk'

@description('Fake key material - generated per deployment, never a real credential')
@secure()
param fakeKey1 string = replace(newGuid(), '-', '')
@secure()
param fakeKey2 string = replace(newGuid(), '-', '')
@secure()
param fakeKey3 string = replace(newGuid(), '-', '')

var suffix = uniqueString(resourceGroup().id)
var keyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'

// ---------------------------------------------------------------- Key Vault
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-${prefix}-${take(suffix, 8)}'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
  }
}

resource kvLlm 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'llm-api-key'
  properties: { value: fakeKey3 }
}

// target secret used later by: apimtk remediate --action link-keyvault --named-value gpt-api-key
resource kvGpt 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: kv
  name: 'gpt-api-key'
  properties: { value: 'rotated-${fakeKey2}' }
}

// ---------------------------------------------------------------- Instance A
// Has managed identity, a mix of named value types, legacy mgmt API ON, sign-up ON,
// self-service product without approval, an app subscription.
resource apimA 'Microsoft.ApiManagement/service@2022-08-01' = {
  name: '${prefix}-lab-a-${take(suffix, 6)}'
  location: location
  sku: { name: 'Developer', capacity: 1 }
  identity: { type: 'SystemAssigned' }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'apimtk lab'
  }
}

resource kvRoleA 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(kv.id, apimA.id, keyVaultSecretsUser)
  scope: kv
  properties: {
    principalId: apimA.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUser)
  }
}

// CRITICAL: key-like value stored as plain text
resource nvPlainKey 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimA
  name: 'embedding-api-key'
  properties: { displayName: 'embedding-api-key', secret: false, value: fakeKey1 }
}

// HIGH: secret stored inside APIM, referenced by a backend
resource nvSecret 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimA
  name: 'gpt-api-key'
  properties: { displayName: 'gpt-api-key', secret: true, value: fakeKey2 }
}

// OK: Key Vault reference (versionless)
resource nvKv 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimA
  name: 'llm-api-key'
  properties: {
    displayName: 'llm-api-key'
    secret: true
    keyVault: { secretIdentifier: '${kv.properties.vaultUri}secrets/llm-api-key' }
  }
  dependsOn: [ kvRoleA, kvLlm ]
}

// OK: config values that must NOT be flagged
resource nvTenant 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimA
  name: 'tenant-id'
  properties: { displayName: 'tenant-id', secret: false, value: subscription().tenantId }
}

resource nvUrl 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimA
  name: 'backend-url'
  properties: { displayName: 'backend-url', secret: false, value: 'https://backend.contoso.example/api' }
}

resource backendAoai 'Microsoft.ApiManagement/service/backends@2022-08-01' = {
  parent: apimA
  name: 'aoai'
  properties: {
    protocol: 'http'
    url: 'https://aoai.contoso.example/openai'
    credentials: { header: { 'api-key': [ '{{gpt-api-key}}' ] } }
  }
  dependsOn: [ nvSecret ]
}

// HIGH: legacy direct management API enabled
resource tenantAccessA 'Microsoft.ApiManagement/service/tenant@2022-08-01' = {
  parent: apimA
  name: 'access'
  properties: { enabled: true }
}

// MEDIUM: developer portal self sign-up enabled
resource signupA 'Microsoft.ApiManagement/service/portalsettings@2022-08-01' = {
  parent: apimA
  name: 'signup'
  properties: {
    enabled: true
    termsOfService: { enabled: false, consentRequired: false }
  }
}

// MEDIUM: published product, subscription required, no approval
resource productA 'Microsoft.ApiManagement/service/products@2022-08-01' = {
  parent: apimA
  name: 'ai-lab'
  properties: {
    displayName: 'AI lab'
    subscriptionRequired: true
    approvalRequired: false
    state: 'published'
  }
}

resource subA 'Microsoft.ApiManagement/service/subscriptions@2022-08-01' = {
  parent: apimA
  name: 'app-a'
  properties: {
    displayName: 'App A'
    scope: productA.id
    state: 'active'
  }
}

// ---------------------------------------------------------------- Instance B
// No managed identity, only secrets stored in APIM (secrets-only pattern).
resource apimB 'Microsoft.ApiManagement/service@2022-08-01' = {
  name: '${prefix}-lab-b-${take(suffix, 6)}'
  location: location
  sku: { name: 'Developer', capacity: 1 }
  properties: {
    publisherEmail: publisherEmail
    publisherName: 'apimtk lab'
  }
}

resource nvB1 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimB
  name: 'llm-api-key-dev'
  properties: { displayName: 'llm-api-key-dev', secret: true, value: fakeKey1 }
}

resource nvB2 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = {
  parent: apimB
  name: 'gpt-4o-api-key-LLM'
  properties: { displayName: 'gpt-4o-api-key-LLM', secret: true, value: fakeKey3 }
}

output apimAId string = apimA.id
output apimBId string = apimB.id
output keyVaultUri string = kv.properties.vaultUri
output gptSecretUri string = '${kv.properties.vaultUri}secrets/gpt-api-key'
