#!/usr/bin/env bash
# End-to-end lab test for apimtk on two real Classic (Developer) APIM instances.
#   ./lab/run-lab.sh deploy  <publisher-email>   # ~45 min
#   ./lab/run-lab.sh before                       # inventory + verify seeded findings
#   ./lab/run-lab.sh fix                          # dry run, then apply remediation (asks per action)
#   ./lab/run-lab.sh after                        # re-inventory + verify findings cleared
#   ./lab/run-lab.sh teardown                     # delete everything
set -euo pipefail
RG=${RG:-rg-apimtk-lab}
LOC=${LOC:-uaenorth}
OUT=${OUT:-out/lab}
SUB=$(az account show --query id -o tsv)
outputs() { az deployment group show -g "$RG" -n seed --query "properties.outputs.$1.value" -o tsv; }

case "${1:-}" in
  deploy)
    az group create -n "$RG" -l "$LOC" -o none
    az deployment group create -g "$RG" -n seed -f lab/seed.bicep -p publisherEmail="${2:?publisher email}" -o none
    echo "Deployed: $(outputs apimAId)"; echo "          $(outputs apimBId)" ;;
  before)
    apimtk --out "$OUT" run --customer apimtk-lab --subscription "$SUB" --deep
    python lab/verify.py --phase before --out "$OUT" ;;
  fix)
    A=$(outputs apimAId); B=$(outputs apimBId); URI=$(outputs gptSecretUri)
    echo "== DRY RUN =="
    apimtk --out "$OUT" remediate --instance "$A" --containment --action disable-portal-signup
    apimtk --out "$OUT" remediate --instance "$A" --action link-keyvault --named-value gpt-api-key --secret-uri "$URI"
    apimtk --out "$OUT" remediate --instance "$B" --containment
    read -rp "Apply these changes? [y/N] " yn; [[ "$yn" == "y" ]] || exit 0
    apimtk --out "$OUT" remediate --instance "$A" --containment --action disable-portal-signup --apply
    apimtk --out "$OUT" remediate --instance "$A" --action link-keyvault --named-value gpt-api-key --secret-uri "$URI" --apply
    apimtk --out "$OUT" remediate --instance "$B" --containment --apply
    apimtk --out "$OUT" remediate --instance "$A" --action regen-sub-keys --which secondary --apply
    echo "Wait ~5 min for Resource Graph to pick up the new managed identity, then run: $0 after" ;;
  after)
    apimtk --out "$OUT" run --customer apimtk-lab --subscription "$SUB" --deep
    python lab/verify.py --phase after --out "$OUT" ;;
  teardown)
    az group delete -n "$RG" --yes --no-wait
    echo "Deleting $RG. Key Vault stays soft-deleted for 7 days (purge: az keyvault purge -n <name>)." ;;
  *) sed -n '2,8p' "$0"; exit 1 ;;
esac
