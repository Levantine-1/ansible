# Disaster Recovery

Two scenarios, covering different amounts of loss. Both assume the reader
starts from this repo and `terraform` (the sibling infra repo) checked out,
and is comfortable running `ansible-playbook`/`terraform` by hand.

Before either scenario is usable for real, three things must already be
true, set up **before** any disaster, not during one:

- **Vault's unseal keys and root token** (from the original `vault operator
  init`) are retained by a human, outside the homelab entirely (password
  manager, printed copy, whatever). Nothing below works without them —
  Vault will not unseal itself, by design.
- **The ansible-vault password** (normally at `/etc/ansible-vault-password.txt`
  on `service`) is likewise retained outside the homelab. It decrypts the
  Vault secrets backup (see below) and anything else `ansible-vault`
  encrypted in this repo.
- Both of the above are periodically verified to still work, not just
  written down once and forgotten.

## Scenario A: soft DR — partial rebuild, critical tier untouched

**When to use:** something in the non-critical tier is broken badly enough
that rebuilding from scratch is faster than debugging (or you're
deliberately testing that the IaC still works).

**Critical tier — never touched by this scenario:**

| Host | Why it's protected |
|---|---|
| `opnsense` | Router/DHCP/DNS for all of `192.168.1.0/24`. Losing it cuts off access to everything else, including the ability to fix anything else. |
| `vault` | Every other host's secrets come from here. No unattended-rebuild path — see Scenario B for why. |
| `pi-hole` | Lower stakes than the other two, but still deliberately excluded — no reason to churn it in a "just rebuild the broken stuff" pass. |
| `service` | Runs this rebuild — can't destroy itself mid-orchestration. Also hosts Semaphore, monitoring, and the local Docker registry. |

**Non-critical tier — fair game:** `dockerhost1`, `pxdbc1`, `pxdbc2`,
`pxdbc3`, `proxysql`, `kube-c-00`, `theia`, `vmwarebastion`.

### Steps

1. **Run the fleet rebuild.** On `service`, as `automation`:
   ```
   systemctl start rebuild-fleet.service
   journalctl -u rebuild-fleet.service -f
   ```
   This `terraform destroy`s then `terraform apply`s every VM in the
   non-critical tier (target list is dynamic, built from `terraform state
   list` at run time — critical-tier hosts are explicitly excluded by name
   in `roles/os_configs/files/rebuild_fleet.sh`, not just by omission), waits
   for SSH, then runs `roles/os_configs/all.yml --limit <rebuilt hosts>`.
   Expect it to take a while. **Data loss is expected and accepted** for
   `pxdbc1-3` and `kube-c-00` — there's no backup/restore step for either yet.

2. **Bootstrap the Percona/Galera cluster by hand.** Deliberately not
   automated (split-brain safety — see `configure_percona_wrapper.yml`'s own
   debug output). On `pxdbc1` (declared `bootstrap=yes` in
   `inventories/production/production.ini`):
   ```
   sudo systemctl start mysql@bootstrap.service
   ```
   Then on `pxdbc2` and `pxdbc3`, plain:
   ```
   sudo systemctl start mysql
   ```
   Verify on all three:
   ```
   mysql -uroot -p<root_password> -e "SHOW STATUS LIKE 'wsrep_cluster_size'; SHOW STATUS LIKE 'wsrep_local_state_comment'; SHOW STATUS LIKE 'wsrep_ready';"
   ```
   Expect `wsrep_cluster_size=3`, `Synced`, `wsrep_ready=ON` on every node.
   Root password is at Vault path `kv/data/percona_cluster/pxc-cluster`.

3. **Re-run ProxySQL config**, now that the cluster it depends on is
   actually up (the copy that ran inside step 1's `all.yml` will have timed
   out waiting ~10 minutes for a cluster that wasn't bootstrapped yet):
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/perconaXtraDbCluster/configure_proxysql.yml \
     --extra-vars "hashicorp_vault_token=<token>"
   ```
   Verify backends are `ONLINE` (not `SHUNNED`) via the ProxySQL admin
   interface (`mysql -h127.0.0.1 -P6032 -uadmin -p<admin_password> -e
   "SELECT hostgroup,srv_host,status FROM stats_mysql_connection_pool;"`).
   Admin password is at Vault path `kv/data/percona_cluster/proxy_sql`
   (key `admin_password`).

4. **Re-deploy DataGateway** onto the fresh k8s cluster:
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/dataGateway/dataGatewayK8Configs.yml \
     --extra-vars "hashicorp_vault_token=<token>"
   ```
   This also exercises the `createDatabaseIfNotExist`/`ddl-auto=update`
   self-healing schema creation — the `datagateway` database won't exist on
   a freshly-bootstrapped cluster, and shouldn't need a manual `CREATE
   DATABASE` this time.

5. **Re-register the GitHub self-hosted runners** on the fresh `dockerhost1`:
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/github_runner/install.yml \
     --extra-vars "hashicorp_vault_token=<token>"
   ```

6. **Redeploy all 9 app containers.** Fastest path is triggering Semaphore's
   `Deploy Container` template directly (project `Homelab Ops`) for each of
   `portfolio`, `thisper`, `processMining`, `pet-care`, `dental-care`,
   `education-platform`, `real_estate`, `booking-movie-ticket`, plus `Deploy
   DataGateway` once — same API call each app's own CI workflow makes
   (`POST /api/project/{id}/tasks` with `template_id` resolved by name, see
   any app repo's `.github/workflows/deploy.yml` `deploy_container` job for
   the exact call). Doesn't require the runners from step 5 to be re-registered
   first, though step 5 still needs to happen for *future* CI-triggered
   deploys to work.

### Verification

- Percona: `wsrep_cluster_size=3`, all `Synced`.
- ProxySQL: all 3 backends `ONLINE`.
- `kubectl get pods`: DataGateway pods `Running`/`Ready`.
- GitHub: all 9 runners `online` (Actions API, or the repo's Settings →
  Actions → Runners page).
- `docker ps` on `dockerhost1`: all 9 app containers `Up`.
- Prometheus `probe_success` (`http://service.internal.levantine.io/prometheus`):
  all blackbox HTTP targets green.
- `POST /generateToken` against DataGateway's NodePort returns `200`.
- `https://thisper.levantine.io/analytics` still works end-to-end.

## Scenario B: hard DR — total physical host loss

**When to use:** the physical machine hosting the fleet is gone —
hardware failure, theft, fire, whatever. Starting point: a new laptop with
this repo and `terraform` cloned, and new (or repaired) hardware to install
Proxmox on.

This is a bootstrap-ordering problem before it's anything else: normal
operation reads *every* credential (Proxmox API token, AWS keys, DB
passwords) from Vault, but Vault doesn't exist yet in this scenario — it's
one of the things being rebuilt. The stages below exist specifically to get
from "nothing" to "Vault is back with its real secrets," after which
everything reverts to the normal, fully-automated path.

### Stage 0 — manual

Install Proxmox on the new hardware. Note root/API access — this is used
directly, once, in Stage 1; it doesn't need to go anywhere durable.

### Stage 1 — break-glass terraform apply

Vault, OPNsense, and pi-hole are the only three hosts with no dependency on
Vault already being up (everything else's terraform reads Vault-sourced
credentials for AWS/Proxmox both). Apply just those three, supplying
credentials directly instead of through Vault:

```
cd terraform
terraform init
terraform apply \
  -var-file=vars/production.tfvars \
  -var "proxmox_bootstrap_mode=true" \
  -var "proxmox_api_token_override=<token_id>=<token_secret>" \
  -var "proxmox_ssh_username_override=<user>" \
  -var "proxmox_ssh_password_override=<password>" \
  -target='module.proxmox_resources.proxmox_virtual_environment_vm.vms["vault"]' \
  -target='module.proxmox_resources.proxmox_virtual_environment_vm.opnsense' \
  -target='module.proxmox_resources.proxmox_download_file.opnsense_iso' \
  -target='module.proxmox_resources.proxmox_virtual_environment_vm.vms["pi-hole"]'
```

`proxmox_bootstrap_mode` (default `false`, zero effect on normal operation
— see `proxmox/main.tf`) skips the Vault-sourced credential data sources
entirely and uses the four override vars instead. The credentials here come
from the fresh Proxmox install itself (Stage 0) — generate an API token via
Proxmox's own UI/CLI, or use root directly for this one-time bootstrap.

Note this only reaches the primary Proxmox host (`10.69.69.139` in the
current config) — that's where Vault/OPNsense/pi-hole live. If the second
host is *also* gone, its VMs (`pxdbc1-3`, `proxysql`, `kube-c-00`, `theia`)
come back in Stage 3 along with everything else, once Vault-sourced
credentials work normally again.

### Stage 2 — manual + ansible

1. **OPNsense**: connect via Proxmox's console and complete the installer
   interactively (no unattended-install mechanism exists — see
   `proxmox/opnsense.tf`'s header comment for why). Once it has at least LAN
   connectivity and a temporary admin password:
   ```
   VAULT_ADDR=http://vault.internal.levantine.io:8200 \
   VAULT_ROLE_ID=<role_id> VAULT_SECRET_ID=<secret_id> \
   roles/applications/opnsense/files/restore_opnsense_config.py
   ```
   This restores the fleet's actual firewall/interface/DHCP/Unbound-DNS
   config from the latest commit under
   `roles/applications/opnsense/backups/config.xml` — the internal DNS
   overrides for every other hostname come back as part of this, since
   they're part of OPNsense's own config, not a separate step.

2. **Vault**: install via ansible, then init/unseal by hand with the
   operator's retained keys (this repo never automates that step, on
   purpose):
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/hashicorp_vault/configure_hvault_server.yml
   vault operator init    # only if this is genuinely a fresh Vault
   vault operator unseal  # x3, with the retained keys
   ```

3. **Restore Vault's secrets** from the latest committed encrypted backup:
   ```
   VAULT_ADDR=http://vault.internal.levantine.io:8200 \
   VAULT_TOKEN=<root token from step 2> \
   ANSIBLE_VAULT_PASSWORD_FILE=<path to the retained ansible-vault password> \
   roles/applications/vault_backup/files/restore_vault_secrets.py
   ```
   Uses the root token directly, not AppRole — AppRole auth itself is one of
   the things being restored, so it isn't available yet at this point.

### Stage 3 — fully automated again

Vault now has its real secrets back, so every other credential lookup
(Proxmox, AWS, DB passwords, GitHub PATs) resolves normally. From here it's
the same mechanism as Scenario A, just covering the whole fleet instead of
the non-critical tier:

```
cd terraform
terraform apply -var-file=vars/production.tfvars
```
then
```
cd ansible
ansible-playbook -i inventories/production/production.ini roles/os_configs/all.yml \
  --extra-vars "hashicorp_vault_token=<token>"
```
then Scenario A's steps 2–6 (Percona bootstrap, ProxySQL, DataGateway,
GitHub runner, app container redeploys) in the same order.

### Verification

Same checklist as Scenario A, plus:
- OPNsense's Unbound Host Overrides resolve every internal hostname
  correctly (spot-check a few via `nslookup <host>.internal.levantine.io
  192.168.1.1` from any host).
- `vault status` shows unsealed, and a spot-check of a few known secret
  paths (e.g. `kv/data/percona_cluster/pxc-cluster`) returns the same
  values they had before the disaster.

## Known gaps (not solved by either scenario)

- **Percona and Kubernetes have no data backup/restore at all.** Both
  scenarios above wipe and recreate them from empty. If the actual data in
  either ever needs to survive a rebuild, that's separate, unstarted work.
- **`restore_opnsense_config.py`'s exact API contract is unverified**
  against a live install — written by mirroring the proven backup script's
  auth flow, but the restore endpoint/payload shape hasn't been exercised
  for real (would require actually destroying/reinstalling OPNsense to
  test, which is out of scope until this DR plan is deliberately being
  rehearsed).
- **Neither scenario has been run for real end-to-end.** Scenario A's
  individual steps have each been exercised live at some point (Percona
  bootstrap, ProxySQL recovery, the Vault secrets backup script), but not
  strung together as one continuous rehearsal. Scenario B is entirely
  unrehearsed. Treat this document as a strong starting point, not a
  guarantee — the next time either is actually needed for real, expect to
  find and fix something.
