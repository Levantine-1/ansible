# Disaster Recovery

Three scenarios, covering different amounts of loss: **A** (rebuild the
non-critical tier), **B** (physical host gone), and **C** (power outage —
nothing lost, just everything restarted at once; most common, and the one to
reach for first if the hardware is fine). Both assume the reader
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
`pxdbc3`, `proxysql`, `kube-c-00`, `theia`, `vmwarebastion`,
`incident-agent`.

`incident-agent` is deliberately in this tier rather than protected: it
responds to incidents but nothing else depends on it, so losing it degrades
the fleet to "tickets wait for a human" — which is exactly how things worked
before it existed. It rebuilds unattended (`roles/applications/incident-agent/`
is imported by `all.yml`, so step 1 restores it with no extra step), though
expect the rebuild to spend a few minutes pulling the local model.

**What is lost when it is rebuilt:** everything under
`/var/lib/incident-agent/` — the incident history database (`incidents.db`)
and `learned_notes.md`, the file successive escalations append fleet knowledge
to. This is accepted rather than backed up, for the same reason Frigate's
footage is: the half that matters is already elsewhere. Every RCA is posted to
Zammad, which runs on `service` and is untouched by soft DR, so the account of
each individual incident survives.

What genuinely does not survive is the accumulated `learned_notes.md` and the
incident statistics. **This is a real gap, not a solved problem** — anything in
those notes worth keeping permanently has to be promoted by hand into
`roles/applications/incident-agent/files/AGENT_CONTEXT.md`, which is in git and
therefore rebuilt with the host. Worth skimming
`/var/lib/incident-agent/learned_notes.md` occasionally and moving the durable
lines across, since nothing does it automatically.

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

   The same applies to `frigate`: it is *not* in the exclusion list, so a
   soft DR destroys and rebuilds it, **and all recorded camera footage goes
   with it** (the 2TB disk is part of the VM). This is a deliberate choice,
   not an oversight — the footage is disposable and the alternative is
   carving the recording disk out of the VM's lifecycle for little benefit.
   Ansible rebuilds Frigate and its bundled go2rtc from scratch, so live
   view and recording resume automatically once the rebuild finishes; only
   the history is lost. The host-level `nvr-hdd` Proxmox storage pool
   survives, since it was created outside terraform.

   Note this takes **live view** down too, not just recordings: Frigate
   ships the only go2rtc in the fleet and livecam streams from it, so
   livecam's tiles stay blank until the rebuild finishes.

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

   **But the fix only stops *new* duplicates — it doesn't remove ones already
   there.** The four duplicate rows from 2026-08-22's passes were still in
   `datagateway.auth_token` on 2026-11-09, so `/analytics` had likely been
   500ing ever since. If protected endpoints throw `NonUniqueResultException`,
   check `SELECT token_hash, COUNT(*) FROM auth_token GROUP BY token_hash
   HAVING COUNT(*)>1` and delete all but the lowest `id` per hash.

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

`incident-agent` is deliberately **not** part of this stage. It is not needed
to bootstrap anything — nothing else depends on it, and an incident responder
is of no use when the whole fleet is being rebuilt by hand anyway. It returns
normally in Stage 3's full `terraform apply` + `all.yml`, with no
bootstrap-specific handling. Do not add it to `terraform/proxmox-bootstrap/`:
that config's value is being minimal and Vault-free, and every VM added to it
is another thing that must work during the worst possible moment.

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

## Scenario C: power outage / cold start — hardware and disks intact

**When to use:** both Proxmox hosts lost power (or were hard-reset) at
roughly the same time, and came back with their disks intact. Nothing needs
rebuilding — **do not run Scenario A or B here**; both destroy data that is
still perfectly good. This is a "bring it back up in the right order" job.

First run for real 2026-11-09. Timeline from that incident, for reference:
FX8200 came back ~02:56 UTC, 3800XT not until ~04:27 UTC, so for 1.5h the
database tier was up with no router, DNS or Vault.

Every VM has `on_boot=1`, so they all start by themselves; there is **no
startup ordering** between them, and the two hosts are independent, so
expect everything to race. What does and does not survive that:

| Comes back by itself | Needs a human |
|---|---|
| OPNsense, pi-hole, dockerhost1 + all app containers, incident-agent, vmwarebastion, theia, frigate, proxysql, k8s control plane, `service`'s Docker stack (Semaphore, Prometheus, Grafana, Zammad, registry…) | **Vault** (sealed, by design) · **Percona/Galera** (all 3 nodes refuse to start) · DataGateway (crash-loops until Percona is up) · `service`'s home-LAN IP (see step 5) |

### Steps

All of this runs from `service` unless stated. Get there from a home-LAN
machine by jumping through 3800XT, which has a leg on `vmbr1`
(`192.168.1.253`): `ssh -J root@10.69.69.40 -i automation.pem automation@192.168.1.50`.

0. **Confirm both hypervisors are up and every VM is `running`**
   (`qm list` on each). If a host hasn't come back, power it on — nothing
   below works without 3800XT (OPNsense, Vault, `service` all live there).

1. **Unseal Vault.** `curl -s http://vault.internal.levantine.io:8200/v1/sys/seal-status`
   should show `"initialized":true,"sealed":true`. Unseal with 3 of the 5
   retained keys (`vault operator unseal` ×3, or `PUT /v1/sys/unseal` with
   `{"key": "..."}` — pipe the body over stdin, don't put keys on a command
   line). The Vault UI via the ops dashboard may be unreachable at this point
   — see steps 2 and 5 — so don't depend on it.

2. **Check nginx on `service`.** Before the 2026-11-09 fix, `nginx` lost a
   boot race against OPNsense: `livecam-lan.conf` proxies to
   `dockerhost1.internal.levantine.io`, nginx resolves that once at startup,
   DNS wasn't answering yet, config test failed, and systemd never retried —
   which takes the **ops dashboard and Vault UI down with it**. Now fixed by a
   systemd drop-in (`roles/applications/livecam/lan_proxy.yml`: waits up to
   5 min for internal DNS, then `Restart=on-failure`). If it's somehow failed
   anyway: `sudo systemctl restart nginx`.

3. **Recover Percona/Galera — find the most advanced node first.** After a
   simultaneous hard stop, every node's `/var/lib/mysql/grastate.dat` shows
   `seqno: -1` and `safe_to_bootstrap: 0`, and `mysql.service` is `failed` on
   all three. **Do not blindly bootstrap `pxdbc1`** the way Scenario A does —
   that's only safe there because the nodes are empty. Here they hold real
   data, and bootstrapping from a node that's behind silently discards
   whatever the others committed after it.

   On each of `pxdbc1-3`:
   ```
   sudo mysqld --wsrep-recover --user=mysql --log-error=/tmp/wsrep_recover.log
   sudo grep 'Recovered position' /tmp/wsrep_recover.log
   ```
   Pick the node with the **highest seqno** (same cluster UUID on all
   three). On ties, any of them — prefer `pxdbc1`, since inventory already
   marks it `bootstrap=yes`. On that node only:
   ```
   sudo sed -i 's/^safe_to_bootstrap: 0/safe_to_bootstrap: 1/' /var/lib/mysql/grastate.dat
   sudo systemctl start mysql@bootstrap.service
   ```
   Then plain `sudo systemctl start mysql` on the other two, one at a time.
   Confirm `Synchronized with group` in each node's `/var/log/mysql/error.log`.

   **Then move the bootstrap node back to the normal unit** — otherwise it's
   still running as `mysql@bootstrap` and the *next* reboot repeats this:
   ```
   sudo systemctl stop mysql@bootstrap.service && sudo systemctl start mysql
   ```
   (Safe once the other two are `Synced`: they hold quorum while it rejoins.)

   2026-11-09: all three recovered to `b3bd4c7c…:28`, bootstrapped from
   `pxdbc1`, no data lost.

4. **Nudge DataGateway.** ProxySQL un-shuns its backends on its own once
   Galera is back — no re-run of `configure_proxysql.yml` needed (unlike
   Scenario A, its config survived). But the DataGateway pods will be deep in
   `CrashLoopBackOff` (up to 5 min between attempts); skip the wait with
   `sudo kubectl delete pod -l app=datagateway` on `kube-c-00`.

5. **Check home-LAN addresses held.** The home LAN (`10.69.69.0/24`) is
   served by the **DD-WRT router at `10.69.69.1`** (not OPNsense — that
   subnet is OPNsense's WAN side). Its dynamic pool is `.100`–`.149`;
   everything the fleet depends on sits below it:

   | Address | What | How it's pinned |
   |---|---|---|
   | `10.69.69.40` | 3800XT (`vmbr0`) | static in `/etc/network/interfaces` (+ DD-WRT lease, documentation only) |
   | `10.69.69.41` | FX8200 (`vmbr0`) | static in `/etc/network/interfaces` (+ DD-WRT lease, documentation only) |
   | `10.69.69.50` | `service` `eth0` | DD-WRT static lease, MAC `bc:24:11:52:91:25` |
   | `10.69.69.60` | camera `the-boiz` | DD-WRT static lease, MAC `a0:60:32:09:23:01` |
   | `10.69.69.61` | camera `the-gurlz` | DD-WRT static lease, MAC `a0:60:32:09:2c:2e` |
   | `10.69.69.62` | camera `baby-ptz` (PTZ) | DD-WRT static lease, MAC `34:46:63:20:8c:d2` |

   This is new as of 2026-11-09. Before that, `service`'s `eth0` was a
   floating lease, and the outage moved it `.133` → `.134`, which silently
   broke every LAN entrance (ops dashboard, Vault UI, livecam-lan) while
   nginx itself was fine. The hypervisors were static but *inside* the pool
   (`.139`/`.116`), so the router could have handed either address to
   something else. Check with `ip -br -4 a show eth0` on `service`. If it
   drifted anyway, `sudo networkctl reconfigure eth0` re-requests the lease.

   Things that must agree with `.50`: Route53 `service.levantine.io`
   (`terraform/route53/hosted_zones/levantine.io.tf`) and
   `livecam-lan.levantine.io` (`livecam/terraform/route53_records.tf`),
   OPNsense's Unbound override for `service.levantine.io`, and
   `livecam_lan_listen_address` in `roles/applications/livecam/lan_proxy.yml`.
   Things that must agree with `.40`/`.41`: `[ProxmoxHosts]` in the
   inventory, `monitored_hosts` in `group_vars/all`, the incident-agent's
   `fleet.yml`, `hardware_monitoring.yml`'s sensor map, both
   `proxmox_endpoint*` defaults in `terraform/proxmox/main.tf`, and the
   `3800xt`/`fx8200` Unbound overrides
   (`roles/applications/opnsense/files/add_dns_host_override.py`).

   DD-WRT's static leases live in nvram (`static_leases`, space-separated
   `mac=hostname=ip=time`, plus `static_leasenum`); edit them through the web
   UI (Services → DHCP Server). The `.10`/`.20`/`.30`/`.31`/`.2` entries are
   ESXi-era VMware MACs and are left as they were.

   **Editing them from a script** (the web UI's Administration → Commands
   console, or `apply.cgi`): the console strips double quotes and expands
   `$` before running anything, so `nvram set static_leases="$(nvram get
   static_leases) ..."` word-splits and silently truncates the list to its
   first entry (this happened on 2026-11-09). Write a script with `printf`
   using `\042` for `"` and `\044` for `$`, `cat` it to check, then
   `nvram get static_leases > /tmp/static_leases.bak; sh` it, `nvram
   commit`, and `stopservice dnsmasq; startservice dnsmasq`. Confirm with
   `grep dhcp-host /tmp/dnsmasq.conf`.

   Cameras got static leases on 2026-11-10 (they were floating at
   `.107`/`.143`/`.144`, inside the pool). Their IPs are used in
   `group_vars/Frigate` (which also feeds the timelapse captures and
   monitoring's `blackbox_cameras` probes) and, for `baby-ptz`'s PTZ/talk,
   `roles/applications/livecam/files/cameras.yml`. After an outage, a camera
   that's down is almost always physical: `baby-ptz` dropped out on
   2026-11-09 because the power strip it shares with the AC tripped, and
   again on 2026-11-10 for ~17h before anyone noticed (`CameraOffline` now
   alerts on it). Power-cycle it; the lease brings it back on its address.

### Verification

Use Scenario A's checklist — in particular Percona 3/3 `Synced`, ProxySQL 3
`ONLINE`, DataGateway pods `Ready`, and Prometheus clean:
`probe_success==0` and `up==0` both empty, `ALERTS{alertstate="firing"}`
explained. Also `POST https://thisper.levantine.io/analytics` with
`{"request":"/dr-check","userAgent":"dr-check"}` — not an empty body, which
500s regardless.

## Known gaps (not solved by either scenario)

- **No VM startup ordering.** All VMs are `on_boot` with no `startup`
  order/delay, and the two hosts are independent, so after an outage
  everything races OPNsense/DNS and Vault. The nginx case is now handled
  defensively, but anything else that resolves an internal name only once
  at startup has the same failure mode. A Proxmox `startup` order
  (opnsense → pi-hole → vault → service → everything else) in
  `terraform/proxmox/` would narrow it, though it can't help across hosts.
- **Galera never auto-recovers from a full-cluster crash**, by design
  (`pc.recovery` aside, Galera won't elect a primary when every node died
  uncleanly). Scenario C step 3 is the manual procedure; there's no
  automation and there shouldn't casually be one.

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
