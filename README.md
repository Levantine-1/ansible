# Ansible Playbooks Repository

This repository contains a collection of Ansible playbooks for managing and configuring servers. The playbooks are organized into different categories based on their purpose and functionality.

## Playbook Categories

### OS Configurations (`os_configs`)

Playbooks in this category are responsible for configuring the operating system on the hosts. This includes tasks such as installing and updating basic packages, setting up specific software like Firefox, and deploying SSL certificates. These playbooks ensure that the hosts are set up with the necessary software and configurations to run the services they are intended for.

Run the app.yml to cover all the playbooks in this category.

### Applications (`applications`)

The `applications` category contains playbooks for setting up and configuring specific applications on the hosts. This could include tasks such as installing and configuring web servers, databases, and other application-specific software. These playbooks are used to set up the specific services that the hosts are intended to run.

# Note:
### SSL Certificates:
The SSL certificates are stored in hashicorp vault so the playbook will need access to retrieve the certificates from vault and deploy them to the hosts.

## The `service` host (control plane)

`service.internal.levantine.io` is the permanent control plane: it holds this repo and the `terraform` repo (cloned under `/home/automation/`), runs `terraform` and `ansible-playbook` directly, and is where recurring automation jobs live. Credentials on `service`:

- `/root/.aws/credentials` — `[default]` (`terraform_admin`) and `[delegate]` (subdomain-delegation account for the `levantine.io` Route53 zone), fetched from Vault, never stored anywhere else.
- `/etc/vault-approle.env` — a scoped Vault AppRole (policy `service-host`: read on `kv/data/aws/iam_access_keys/*`, `kv/data/splunk/*`, `kv/data/proxmox/*`, `kv/data/ssh/*`, `kv/data/theia/*`, `kv/data/opnsense/*`, `kv/data/github/*`, `kv/data/semaphore/*`, `kv/data/monitoring/*`, `kv/data/zammad/*`, read/write on `kv/data/ssl_certs/*` and `kv/data/k8clusters/*`) for `service`'s own ongoing use. The Vault *root* token is not stored long-term on `service` — it's only used interactively to bootstrap things like this. (`k8clusters` needs write too, not just read: a fresh control-plane node generates and stores its own join token/cert hash there during `kubeadm init` -- found via the first real rebuild-fleet.sh run failing to store it.)
- `/etc/proxmox-token.env` — a dedicated Proxmox API token (`terraform@pve`, `PVEAdmin` role) for terraform's Proxmox provider.
- `/etc/ansible-vault-password.txt` (owned by `automation`, 0600) — the ansible-vault password, referenced by `ansible.cfg`'s `vault_password_file` (that file is gitignored — it's machine-specific). This means playbooks that `vars_files: vault.yml` run **unmodified** from `service`; no need for the extra-var workarounds used earlier in this repo's history.
- `service` has its own WireGuard client identity (see `inventories/production/group_vars/Wireguard`) so it's reachable over the tunnel from anywhere, not just the home network.

### Job scheduler convention

Recurring jobs on `service` are plain **systemd timers**, not a separate scheduling system. Each job is a pair:

- `/etc/systemd/system/<name>.service` — `Type=oneshot`, `ExecStart=/usr/local/bin/<name>.sh`, secrets via `EnvironmentFile=/etc/<name>.env` (root-only, 0600, never committed anywhere).
- `/etc/systemd/system/<name>.timer` — an `OnCalendar=` schedule with `RandomizedDelaySec=` to avoid thundering-herd, `Persistent=true` so a missed run (e.g. host was down) fires on next boot.

Logs go to journald (`journalctl -u <name>.service`) — no separate log aggregation for job output. `levantine-ssl-renew.service`/`.timer` (`/usr/local/bin/renew_levantine_ssl.sh`) is the reference example: renews the `levantine.io` cert via `certbot-dns-route53`, pushes it to Vault, deploys it to the `Nginx` group via `roles/os_configs/deploySSLCerts.yml`.

`opnsense-config-backup.service`/`.timer` (`/usr/local/bin/backup_opnsense_config.py`, deployed by `roles/applications/opnsense/backup.yml`) is the other example: weekly pull of OPNsense's `config.xml` via its session-based API, committed and pushed to `roles/applications/opnsense/backups/config.xml` using a GitHub PAT fetched from Vault (`kv/data/github/ansible_repo_pat`) through a git credential helper, rather than a token stored on disk.

`vault-secrets-backup.service`/`.timer` (`/usr/local/bin/backup_vault_secrets.py`, deployed by `roles/applications/vault_backup/backup.yml`) is the same pattern applied to Vault itself: weekly walk of every `kv/` path, piped straight into `ansible-vault encrypt` via stdin (the plaintext dump never touches disk) and committed to `roles/applications/vault_backup/backups/secrets.json.vault`.

This is deliberately the same pattern a future automation/incident-response agent on `service` would plug into — same SSH access, same credentials, same job convention.

### The "one button" fleet rebuild

`rebuild-fleet.service` (`/usr/local/bin/rebuild_fleet.sh`, deployed by `roles/os_configs/deploy_fleet_rebuild_job.yml`) is the one exception to "every job gets a timer" — it's **on-demand only**, triggered manually with `systemctl start rebuild-fleet.service` and watched with `journalctl -u rebuild-fleet.service -f`. It `terraform destroy`s every Proxmox VM in the non-critical tier (target list built dynamically from `terraform state list`, so it stays in sync as VMs are added/removed from `proxmox/vms.tf` — except the critical tier below, which is excluded by an explicit name match, not just by omission), `terraform apply`s to rebuild them, waits for SSH, then runs `roles/os_configs/all.yml` fleet-wide (which now covers Theia's install too, not just base OS bootstrap).

`service` can't destroy itself while orchestrating its own destruction — a full rebuild including `service` has to be kicked off from somewhere else. **`pxdbc1-3` (Percona) and the `kube-*` nodes have no persistent-disk separation or backup/restore step** — this script wipes their data on every run. Don't use it expecting that state to survive; that's tracked as unresolved follow-up work, not something this script handles.

### The critical tier: OPNsense, Vault, pi-hole, `service`

`opnsense`, `vault`, and `pi-hole` are all terraform-managed now (previously hand-built, imported later to close a real IaC gap), but — along with `service` — they're deliberately never touched by `rebuild-fleet.service`. OPNsense is the router/DHCP/DNS for the whole internal network; Vault holds every other credential in the fleet with no data backup on the VM itself; pi-hole is lower stakes but still excluded on principle; `service` runs the rebuild and can't destroy itself. None of the first three has a clean unattended rebuild path even now that they're declared in terraform — OPNsense in particular still needs a manual ISO install (no cloud-init support, no unattended-install mechanism exists for it).

Vault's secrets and OPNsense's config each have automated weekly backups (`vault-secrets-backup.service`/`.timer` and `opnsense-config-backup.service`/`.timer`, same job-scheduler convention as above, committing encrypted/plain artifacts respectively into this repo) with matching restore scripts for actually using them. See **`docs/disaster-recovery.md`** for the full runbooks — both a partial rebuild (non-critical tier only) and a from-scratch rebuild after total physical host loss.