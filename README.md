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
- `/etc/vault-approle.env` — a scoped Vault AppRole (policy `service-host`: read on `kv/data/aws/iam_access_keys/*`, `kv/data/splunk/*`, `kv/data/k8clusters/*`, `kv/data/proxmox/*`, `kv/data/jenkins/*`, `kv/data/ssh/*`, `kv/data/theia/*`, `kv/data/opnsense/*`, `kv/data/github/*`, read/write on `kv/data/ssl_certs/*`) for `service`'s own ongoing use. The Vault *root* token is not stored long-term on `service` — it's only used interactively to bootstrap things like this.
- `/etc/proxmox-token.env` — a dedicated Proxmox API token (`terraform@pve`, `PVEAdmin` role) for terraform's Proxmox provider.
- `/etc/ansible-vault-password.txt` (owned by `automation`, 0600) — the ansible-vault password, referenced by `ansible.cfg`'s `vault_password_file` (that file is gitignored — it's machine-specific). This means playbooks that `vars_files: vault.yml` run **unmodified** from `service`; no need for the extra-var workarounds used earlier in this repo's history.
- `service` has its own WireGuard client identity (see `inventories/production/group_vars/Wireguard`) so it's reachable over the tunnel from anywhere, not just the home network.

### Job scheduler convention

Recurring jobs on `service` are plain **systemd timers**, not a separate scheduling system. Each job is a pair:

- `/etc/systemd/system/<name>.service` — `Type=oneshot`, `ExecStart=/usr/local/bin/<name>.sh`, secrets via `EnvironmentFile=/etc/<name>.env` (root-only, 0600, never committed anywhere).
- `/etc/systemd/system/<name>.timer` — an `OnCalendar=` schedule with `RandomizedDelaySec=` to avoid thundering-herd, `Persistent=true` so a missed run (e.g. host was down) fires on next boot.

Logs go to journald (`journalctl -u <name>.service`) — no separate log aggregation for job output. `levantine-ssl-renew.service`/`.timer` (`/usr/local/bin/renew_levantine_ssl.sh`) is the reference example: renews the `levantine.io` cert via `certbot-dns-route53`, pushes it to Vault, deploys it to the `Nginx` group via `roles/os_configs/deploySSLCerts.yml`.

`opnsense-config-backup.service`/`.timer` (`/usr/local/bin/backup_opnsense_config.py`, deployed by `roles/applications/opnsense/backup.yml`) is the other example: weekly pull of OPNsense's `config.xml` via its session-based API, committed and pushed to `roles/applications/opnsense/backups/config.xml` using a GitHub PAT fetched from Vault (`kv/data/github/ansible_repo_pat`) through a git credential helper, rather than a token stored on disk.

This is deliberately the same pattern a future automation/incident-response agent on `service` would plug into — same SSH access, same credentials, same job convention.

### The "one button" fleet rebuild

`rebuild-fleet.service` (`/usr/local/bin/rebuild_fleet.sh`, deployed by `roles/os_configs/deploy_fleet_rebuild_job.yml`) is the one exception to "every job gets a timer" — it's **on-demand only**, triggered manually with `systemctl start rebuild-fleet.service` and watched with `journalctl -u rebuild-fleet.service -f`. It `terraform destroy`s every Proxmox VM except `service` itself (target list built dynamically from `terraform state list`, so it stays in sync as VMs are added/removed from `proxmox/vms.tf`), `terraform apply`s to rebuild them, waits for SSH, then runs `roles/os_configs/all.yml` fleet-wide (which now covers Jenkins's full JCasC/plugin/job install and Theia's install, not just base OS bootstrap).

`service` can't destroy itself while orchestrating its own destruction — a full rebuild including `service` has to be kicked off from somewhere else. **`pxdbc1-3` (Percona), `splunk`, and the `kube-*` nodes have no persistent-disk separation or backup/restore step** — this script wipes their data on every run. Don't use it expecting that state to survive; that's tracked as unresolved follow-up work, not something this script handles.

### OPNsense: backup only, not part of destroy/rebuild

OPNsense (the firewall/router VM) is **explicitly excluded** from the terraform destroy/rebuild cycle — it's a hand-configured appliance, not a disposable cloud-init VM, and there's no automation to rebuild it from scratch. Its only safety net is the weekly `config.xml` backup above: if it's ever lost, the router has to be reinstalled by hand and its config restored from the latest commit under `roles/applications/opnsense/backups/config.xml`.