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
# OPNsense, pi-hole, and vault ARE terraform-managed now (brought in to
# close a real IaC gap), but they're still explicitly excluded below --
# they're the fleet's critical tier (router/DNS for the whole internal
# network, secrets, ad-blocking DNS) and none of them has a clean
# unattended rebuild path even where they're now declared in terraform
# (OPNsense in particular needs a manual ISO install; Vault's data isn't
# something you'd want blown away and reinitialized on a whim). Unlike
# `service`, this exclusion is NOT automatic from `terraform state list`
# alone -- it's an explicit grep pattern below, so it needs updating if
# any of these three are ever renamed.
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
  | grep -v -E '\.service$|\.opnsense$|vms\["vault"\]|vms\["pi-hole"\]')
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
sudo terraform destroy -auto-approve -parallelism=3 \
  -var-file="$TFVARS" -var "vault_token=${TOKEN}" \
  "${TARGET_ARGS[@]}"

log "rebuilding fleet"
# -parallelism=3 (default 10): 8 VMs landing on FX8200's local-lvm at once
# blew past Proxmox's own LVM lock handling -- "trying to acquire lock...
# got timeout" on the thin pool, with cascading "hotplug problem" errors on
# the VMs queued behind the timed-out one. Found running this for real
# against both hosts; the original host's SSD1TB storage handled the
# lower VM count on it fine even at default parallelism, but there's no
# reason to risk the same failure mode there as the fleet grows.
#
# Reuses the SAME $TARGET_ARGS as the destroy above -- this used to be a
# plain unscoped `terraform apply`, which is a real bug found the hard way:
# an unscoped apply also picks up ANY other pending drift in the whole
# config, including on `service`/`opnsense`/`vault`/`pi-hole` if any of
# them happen to differ from their live state at the time (e.g. a cpu-type
# change committed but not yet live-applied) -- exactly the critical tier
# this script exists to never touch. Re-targeting with the pre-destroy
# list (not a fresh post-destroy discovery -- destroyed resources are
# removed from state, so they wouldn't be discoverable there anymore)
# keeps this apply scoped to exactly what was just destroyed.
#
# Trade-off: a VM added to vms.tf but never applied even once won't be in
# pre-destroy state either, so it's silently skipped by both the destroy
# and this apply -- run a normal unscoped `terraform apply` by hand once
# for a genuinely new VM before using this script, or just run this script
# a second time afterward.
sudo terraform apply -auto-approve -parallelism=3 \
  -var-file="$TFVARS" -var "vault_token=${TOKEN}" \
  "${TARGET_ARGS[@]}"

# Re-discover from state *after* apply, not the pre-destroy TARGETS list --
# a resource that's brand-new to state this run (e.g. a whole new resource
# block just added to vms.tf) wouldn't be in the pre-apply capture, so
# reusing it here would silently skip SSH-waiting/provisioning newly
# created VMs even though terraform just created them. This keeps the
# script correct for that case without needing a throwaway first apply.
log "discovering current VM resources (post-apply, includes anything new this run)"
CURRENT_TARGETS=$(sudo terraform state list \
  | grep '^module\.proxmox_resources\.proxmox_virtual_environment_vm\.' \
  | grep -v -E '\.service$|\.opnsense$|vms\["vault"\]|vms\["pi-hole"\]')

log "waiting for SSH on rebuilt hosts"
HOSTS=$(echo "$CURRENT_TARGETS" \
  | sed 's/^module\.proxmox_resources\.proxmox_virtual_environment_vm\.//' \
  | sed -E 's/.*\["([^"]+)"\]$/\1/' \
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

log "running full OS bootstrap (all.yml), limited to the hosts just rebuilt -- covers theia install too"
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
