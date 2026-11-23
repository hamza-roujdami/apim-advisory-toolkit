using 'secure-ai-gateway.bicep'

param apimName = 'apim-contoso-ai-001'
param keyVaultName = 'kv-contoso-apim-001'
param keyVaultNamedValues = [
  { name: 'llm-api-key', secretName: 'llm-api-key' }
  { name: 'embedding-api-key', secretName: 'embedding-api-key' }
]
param foundryAccountName = 'aif-contoso-uaen-001'
param disableDirectManagementApi = true
