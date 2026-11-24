#!/usr/bin/env bash
# End-to-end lab test for apimtk on two real Classic (Developer) APIM instances.
#   ./lab/run-lab.sh deploy  <publisher-email>   # ~45 min (needs openssl)
#   ./lab/run-lab.sh before                       # inventory + verify seeded findings
#   ./lab/run-lab.sh fix                          # dry run, then apply remediation (asks per action)
#   ./lab/run-lab.sh after                        # re-inventory + verify findings cleared
#   ./lab/run-lab.sh teardown                     # delete everything
set -euo pipefail
RG=${RG:-rg-apimtk-lab}
LOC=${LOC:-uaenorth}
OUT=${OUT:-out/lab}
EH_LOGGER=${EH_LOGGER:-true}   # false where Azure Policy forces disableLocalAuth on Event Hubs
SUB=$(az account show --query id -o tsv)
outputs() { az deployment group show -g "$RG" -n seed --query "properties.outputs.$1.value" -o tsv; }

case "${1:-}" in
  deploy)
    az group create -n "$RG" -l "$LOC" -o none
    # Self-signed client certificate for the "certificate uploaded to APIM" scenario (lab only, 30 days)
    TMP=$(mktemp -d); PW=$(openssl rand -hex 16)
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=apimtk-lab-client" \
      -keyout "$TMP/k.pem" -out "$TMP/c.pem" 2>/dev/null
    openssl pkcs12 -export -inkey "$TMP/k.pem" -in "$TMP/c.pem" -passout "pass:$PW" -out "$TMP/c.pfx"
    PARAMS=$(mktemp); python3 - "$TMP/c.pfx" "$PW" "${2:?publisher email}" "$EH_LOGGER" > "$PARAMS" <<'PY'
import base64, json, sys
pfx, pw, email, eh = sys.argv[1:5]
print(json.dumps({"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
                  "contentVersion": "1.0.0.0", "parameters": {
                      "publisherEmail": {"value": email},
                      "clientCertPfx": {"value": base64.b64encode(open(pfx, "rb").read()).decode()},
                      "clientCertPassword": {"value": pw},
                      "deployEventHubLogger": {"value": eh == "true"}}}))
PY
    rm -rf "$TMP"
    az deployment group create -g "$RG" -n seed -f lab/seed.bicep -p "@$PARAMS" -o none
    rm -f "$PARAMS"
    echo "Deployed: $(outputs apimAId)"; echo "          $(outputs apimBId)" ;;
  before)
    apimtk --out "$OUT" run --customer apimtk-lab --subscription "$SUB"
    python lab/verify.py --phase before --out "$OUT" $([[ "$EH_LOGGER" == true ]] || echo --no-eventhub) ;;
  fix)
    A=$(outputs apimAId); B=$(outputs apimBId); URI=$(outputs gptSecretUri)
    echo "== DRY RUN =="
    apimtk --out "$OUT" remediate --instance "$A" --containment --action disable-portal-signup
    apimtk --out "$OUT" remediate --instance "$A" --action link-keyvault --named-value gpt-api-key --secret-uri "$URI"
    apimtk --out "$OUT" remediate --instance "$B" --containment
    apimtk --out "$OUT" remediate --instance "$A" --action update-client-secret --provider oidc:entra-oidc
    read -rp "Apply these changes? [y/N] " yn; [[ "$yn" == "y" ]] || exit 0
    apimtk --out "$OUT" remediate --instance "$A" --containment --action disable-portal-signup --apply
    apimtk --out "$OUT" remediate --instance "$A" --action link-keyvault --named-value gpt-api-key --secret-uri "$URI" --apply
    apimtk --out "$OUT" remediate --instance "$B" --containment --apply
    # Microsoft's order: apps on secondary -> regenerate primary -> apps on primary -> regenerate secondary
    apimtk --out "$OUT" remediate --instance "$A" --action regen-sub-keys --which primary --apply
    echo "Wait ~5 min for Resource Graph to pick up the new managed identity, then run: $0 after" ;;
  after)
    apimtk --out "$OUT" run --customer apimtk-lab --subscription "$SUB"
    python lab/verify.py --phase after --out "$OUT" $([[ "$EH_LOGGER" == true ]] || echo --no-eventhub) ;;
  teardown)
    az group delete -n "$RG" --yes --no-wait
    echo "Deleting $RG. Key Vault stays soft-deleted for 7 days (purge: az keyvault purge -n <name>)." ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
