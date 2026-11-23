// Hardening for an EXISTING APIM AI gateway (Classic or v2).
// - Key Vault-referenced named values (APIM managed identity, versionless URIs)
// - Managed identity access to Foundry / Azure OpenAI (no API key)
// - Legacy direct management API disabled
// Prereq: APIM has a system-assigned identity (apimtk remediate --action enable-managed-identity).
// Key Vault must use the Azure RBAC permission model.

targetScope = 'resourceGroup'

@description('Existing API Management service name')
param apimName string

@description('Existing Key Vault (RBAC model) holding the rotated backend secrets')
param keyVaultName string

@description('Resource group of the Key Vault (defaults to this one)')
param keyVaultResourceGroup string = resourceGroup().name

@description('Named values to create/convert: [{ name: "llm-api-key", secretName: "llm-api-key" }]')
param keyVaultNamedValues array = []

@description('Foundry / Azure OpenAI account name for managed identity access (empty to skip)')
param foundryAccountName string = ''

@description('Resource group of the Foundry account')
param foundryResourceGroup string = resourceGroup().name

@description('Disable the legacy direct management API')
param disableDirectManagementApi bool = true

var keyVaultSecretsUser = '4633458b-17de-408a-b874-0445c86b69e6'
var cognitiveServicesOpenAIUser = '5e0bd9bd-7b93-4f28-af87-19fc36ad61bd'

resource apim 'Microsoft.ApiManagement/service@2022-08-01' existing = {
  name: apimName
}

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
  scope: resourceGroup(keyVaultResourceGroup)
}

module kvRole 'modules/kv-role.bicep' = {
  name: 'apim-kv-secrets-user'
  scope: resourceGroup(keyVaultResourceGroup)
  params: {
    keyVaultName: keyVaultName
    principalId: apim.identity.principalId
    roleDefinitionId: keyVaultSecretsUser
  }
}

resource namedValues 'Microsoft.ApiManagement/service/namedValues@2022-08-01' = [for nv in keyVaultNamedValues: {
  parent: apim
  name: nv.name
  properties: {
    displayName: nv.name
    secret: true
    keyVault: {
      // versionless: a new version in Key Vault is picked up by APIM automatically
      secretIdentifier: '${kv.properties.vaultUri}secrets/${nv.secretName}'
    }
  }
  dependsOn: [ kvRole ]
}]

module foundryRole 'modules/foundry-role.bicep' = if (!empty(foundryAccountName)) {
  name: 'apim-foundry-openai-user'
  scope: resourceGroup(foundryResourceGroup)
  params: {
    accountName: foundryAccountName
    principalId: apim.identity.principalId
    roleDefinitionId: cognitiveServicesOpenAIUser
  }
}

resource tenantAccess 'Microsoft.ApiManagement/service/tenant@2022-08-01' = if (disableDirectManagementApi) {
  parent: apim
  name: 'access'
  properties: {
    enabled: false
  }
}

output apimPrincipalId string = apim.identity.principalId
