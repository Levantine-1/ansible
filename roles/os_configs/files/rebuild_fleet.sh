#!/bin/bash
# The "one button": terraform destroy + apply the Proxmox fleet, then
# ansible-playbook the whole thing back to a working state.
#
# `service` is deliberately never targeted for destroy -- it's the host
# running this script, so it can't orchestrate its own destruction. If a
# full rebuild including `service` is ever needed, that has to be kicked
# off from somewhere else (see terraform/proxmox/service.tf's header
# comment). The target list below is built dynamically from
# `terraform state list` each run, so it stays in sync automatically as
# VMs are added/removed from proxmox/vms.tf without editing this script.
#
# OPNsense, pi-hole, and vault are NOT terraform-managed at all (hand-built,
# predate this module) so they're untouched by construction, not because of
# anything special in this script.
#
# DATA-LOSS WARNING: pxdbc1-3 (Percona) and the kube-* nodes have no
# persistent-disk separation or backup/restore step yet (tracked as
# unresolved investigation in the IaC reconciliation plan) -- destroying
# and recreating them WIPES their data. There is currently no automated
# recovery for that beyond OS/app reinstall from scratch. Don't run this
# expecting Percona/Kubernetes state to survive.
set -euo pipefail

TERRAFORM_DIR=/home/automation/terraform
ANSIBLE_DIR=/home/automation/ansible
TFVARS=vars/production.tfvars
INVENTORY=inventories/production/production.ini
SSH_KEY=/home/automation/.ssh/automation.pem
SSH_OPTS=(-i "$SSH_KEY" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o BatchMode=yes)

log() { echo "[rebuild-fleet] $(date -u +%FT%TZ) $*"; }

source /etc/vault-approle.env
get_vault_token() {
  curl -s -X POST \
    -d "{\"role_id\":\"${VAULT_ROLE_ID}\",\"secret_id\":\"${VAULT_SECRET_ID}\"}" \
    "${VAULT_ADDR}/v1/auth/approle/login" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['auth']['client_token'])"
}

log "starting fleet rebuild"
cd "$TERRAFORM_DIR"
git pull
TOKEN=$(get_vault_token)

log "discovering VM resources to destroy (everything under module.proxmox_resources except service)"
TARGETS=$(sudo terraform state list \
  | grep '^module\.proxmox_resources\.proxmox_virtual_environment_vm\.' \
  | grep -v '\.service$')
if [ -z "$TARGETS" ]; then
  log "no proxmox VM resources found in state, aborting"
  exit 1
fi
log "targets:"
echo "$TARGETS" | sed 's/^/  /'

TARGET_ARGS=()
while IFS= read -r addr; do
  TARGET_ARGS+=("-target=$addr")
done <<< "$TARGETS"

log "destroying fleet"
sudo terraform destroy -auto-approve \
  -var-file="$TFVARS" -var "vault_token=${TOKEN}" \
  "${TARGET_ARGS[@]}"

log "rebuilding fleet"
sudo terraform apply -auto-approve \
  -var-file="$TFVARS" -var "vault_token=${TOKEN}"

log "waiting for SSH on rebuilt hosts"
HOSTS=$(echo "$TARGETS" \
  | sed 's/^module\.proxmox_resources\.proxmox_virtual_environment_vm\.//' \
  | sed -E 's/vms\["([^"]+)"\]/\1/' \
  | sed 's/$/.internal.levantine.io/')
for host in $HOSTS; do
  log "waiting for $host..."
  up=0
  for _ in $(seq 1 60); do
    if ssh "${SSH_OPTS[@]}" automation@"$host" true 2>/dev/null; then
      up=1
      break
    fi
    sleep 5
  done
  if [ "$up" -eq 0 ]; then
    log "WARNING: $host never came up after 5 minutes, continuing anyway"
  else
    log "$host is up"
  fi
done

log "running full OS bootstrap (all.yml), limited to the hosts just rebuilt -- covers jenkins (JCasC/plugins/jobs) and theia install too"
cd "$ANSIBLE_DIR"
git pull
# --limit to exactly the rebuilt hosts, not the whole inventory: running
# unrestricted here hit a real dpkg-lock race (the inventory has a
# `[localhost]` group alongside `[service]`, both resolving to this same
# machine, so an unscoped `hosts: all` run apt-upgrades it twice at once)
# and dragged in pre-existing, unrelated breakage on the AWS bastion.
# Neither `service` nor the AWS side were touched by this rebuild, so they
# have no business being reconfigured by it either.
LIMIT=$(echo "$HOSTS" | paste -sd, -)
ansible-playbook -i "$INVENTORY" roles/os_configs/all.yml \
  --limit "$LIMIT" \
  --user automation --private-key "$SSH_KEY" \
  --extra-vars "hashicorp_vault_token=${TOKEN}"

log "starting theia app processes (pm2)"
ansible-playbook -i "$INVENTORY" roles/applications/theia/start.yml \
  --limit theia.internal.levantine.io \
  --user automation --private-key "$SSH_KEY"

log "fleet rebuild complete"
