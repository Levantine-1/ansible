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
| `service` | Runs this rebuild — can't destroy itself mid-orchestration. Also hosts Semaphore, monitoring, the local Docker registry, and (as of 2026-08-22) the fleet's apt/Docker-Hub package cache (`roles/applications/apt_cache_mirror/`) — living here means the cache survives every soft-DR rebuild automatically, no separate exclusion-list entry needed. |

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
   This now creates the `datagateway` database explicitly (an `mysql_db`
   task — the JDBC `createDatabaseIfNotExist=true` flag doesn't actually
   work through ProxySQL, confirmed by testing), then checks whether
   thisper's *existing* Vault-stored token still validates against the
   fresh DataGateway and only mints + stores a new one if it doesn't.
   That check-first step matters: `auth_token.token_hash` has no unique
   DB constraint, so unconditionally calling `/generateToken` on every
   deploy (the first version of this fix) silently inserted a duplicate
   row each run, which broke every protected endpoint (`/analytics`
   included) with a `NonUniqueResultException` 500 — found live on a
   second DR pass. Safe to run repeatedly either way now.

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

   `thisper` specifically must be redeployed *after* step 4, not before:
   step 4 writes a freshly-generated token to Vault (needed whenever
   Percona's `auth_token` table was wiped), but thisper's container only
   reads that value from its environment at container start — a redeploy
   is what picks up a changed value. If `thisper`'s deploy already ran
   earlier in this pass, trigger it again.

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

Vault, OPNsense, pi-hole, and `service` are the four hosts with no
dependency on Vault already being up (everything else's terraform reads
Vault-sourced credentials for AWS/Proxmox both) — `service` belongs in this
set too, even though it's not "critical tier" in the OPNsense/Vault sense:
it's still just a plain VM shell created by the same Vault-dependent
config, so it needs the identical treatment.

**A first attempt at this (a `proxmox_bootstrap_mode` variable gating the
Proxmox provider's Vault-sourced data sources behind `count`, with direct
override vars used instead) was built, then reverted the same day it was
added.** Found live, via a real dry-run `terraform plan -destroy -target=...`
before ever running an actual destroy: gating those data sources behind
`count` changes their resource address (bare → indexed), which Terraform
treats as a "moved" resource. Any `-target` operation is then required to
include them — and since they feed the *shared* default provider block that
every host1 resource uses (including `service`), doing so pulled every
host1 resource into scope, silently defeating `rebuild_fleet.sh`'s core
safety property (confirmed: targeting just `vmwarebastion` alone was enough
to show `service` staged for destruction). Reverted rather than ship
something that could destroy `service` the first time anyone actually used
it. See the commit that reverted it in `terraform/proxmox/main.tf`'s
history for the full writeup.

**The actual fix: `terraform/proxmox-bootstrap/`, a genuinely separate
terraform configuration** — own directory, own provider block, own local
state, zero references to Vault or AWS anywhere in it. It creates exactly
the four VM shells (`vault`, `opnsense`, `pi-hole`, `service`), taking
Proxmox credentials as plain input variables supplied by hand from the
fresh Proxmox install's own UI/CLI. See that directory's `README.md` for
the apply command and, critically, the state-reconciliation step
afterward (`terraform import` these four into the real `terraform/proxmox`
state once Vault is back up, so future operations go through the normal
path again — this bootstrap config is meant to be used once per incident,
not kept as an ongoing parallel state).

Not yet exercised against a real fresh Proxmox install — the terraform
syntax validates, and the resource shapes are copied from the live
`proxmox/vms.tf`/`service.tf`/`opnsense.tf`, but a real `terraform apply`
against actual new hardware would be the first real test of this path,
same as Scenario A needed two live passes before its bugs surfaced.

### Stage 2 — manual + ansible

1. **`service`**: SSH in as `automation`, clone both repos, install
   ansible + the `community.hashi_vault`/`kubernetes.core` collections
   (see the ansible repo's own README for the exact package list). Every
   command in this stage runs from here.

2. **pi-hole**: fully unattended, nothing bootstrap-specific —
   `ansible-playbook -i inventories/production/production.ini
   roles/applications/pi-hole/configure_pi-hole.yml`.

3. **Vault**: install via ansible, then init/unseal by hand with the
   operator's retained keys (this repo never automates that step, on
   purpose):
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/hashicorp_vault/configure_hvault_server.yml
   vault operator init    # only if this is genuinely a fresh Vault
   vault operator unseal  # x3, with the retained keys
   ```

4. **Restore Vault's secrets** from the latest committed encrypted backup:
   ```
   VAULT_ADDR=http://vault.internal.levantine.io:8200 \
   VAULT_TOKEN=<root token from step 3> \
   ANSIBLE_VAULT_PASSWORD_FILE=<path to the retained ansible-vault password> \
   roles/applications/vault_backup/files/restore_vault_secrets.py
   ```
   Uses the root token directly, not AppRole — AppRole auth itself is one of
   the things being restored, so it isn't available yet at this point. This
   restores secret *values* only — it does not touch the `approle` auth
   method, the `service-host` policy, or the AppRole role binding itself,
   none of which live under `kv/`. Step 5 below covers that.

5. **Configure Vault's own auth config** (the piece step 4 doesn't cover —
   enables `approle`, writes the `service-host` policy, creates the role,
   and mints `/etc/vault-approle.env` since it won't exist yet on a fresh
   `service`):
   ```
   ansible-playbook -i inventories/production/production.ini \
     roles/applications/hashicorp_vault/configure_vault_auth.yml \
     --extra-vars "vault_root_token=<root token from step 3>"
   ```
   Idempotent — safe to re-run any time `service-host`'s policy needs to
   change, not just during a DR recovery. Only mints a fresh role_id/
   secret_id when `/etc/vault-approle.env` is actually missing.

6. **OPNsense**: connect via Proxmox's console and complete the installer
   interactively (no unattended-install mechanism exists — see
   `proxmox/opnsense.tf`'s header comment for why). Once it has at least LAN
   connectivity and a temporary admin password:
   ```
   source /etc/vault-approle.env  # from step 5
   roles/applications/opnsense/files/restore_opnsense_config.py
   ```
   This restores the fleet's actual firewall/interface/DHCP/Unbound-DNS
   config from the latest commit under
   `roles/applications/opnsense/backups/config.xml` — the internal DNS
   overrides for every other hostname come back as part of this, since
   they're part of OPNsense's own config, not a separate step.

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
- **`configure_vault_auth.yml` has only been tested as a no-op re-run**
  against a live, already-configured Vault (confirmed it correctly skips
  re-minting `/etc/vault-approle.env`, and that the policy/role rewrite
  didn't disrupt anything live). It has never been exercised against a
  genuinely fresh Vault with `approle` not yet enabled and no existing
  credential file — the actual Stage 2 bootstrap path it's meant for.
- **Scenario B is entirely unrehearsed end-to-end.** Stage 1's terraform
  config (`terraform/proxmox-bootstrap/`) is syntax-validated but has never
  run against real hardware; Stage 2 has never been run start to finish.
  Scenario A, by contrast, has now been run for real twice (see below) —
  Scenario B needs the same treatment before it should be trusted. Treat
  this document as a strong starting point, not a
  guarantee — the next time either is actually needed for real, expect to
  find and fix something.
