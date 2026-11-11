#!/usr/bin/env python3
"""Tests for fleet_recover.py against a fake fleet.

Run on `service` (same as the incident-agent tests):
  python3 roles/applications/fleet_recovery/tests/test_fleet_recover.py
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("fleet_recover", os.path.join(HERE, "..", "files", "fleet_recover.py"))
fr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fr)

UUID = "b3bd4c7c-9da2-11f1-af8c-82b6d7a62ed3"
OTHER = "aaaaaaaa-9da2-11f1-af8c-82b6d7a62ed3"

CFG = {
    "ssh_user": "automation", "ssh_key": "/k",
    "dns_probe_name": "pxdbc1.internal.levantine.io",
    "lan_iface": "eth0", "lan_ip": "10.69.69.50",
    "hypervisors": [
        {"name": "3800xt", "address": "10.69.69.40", "mac": "a8:a1:59:37:7d:62"},
        {"name": "fx8200", "address": "10.69.69.41", "mac": "1c:fd:08:7c:3b:f4"},
    ],
    "wol_broadcast": "10.69.69.255",
    "vm_start_window": [600, 3600],
    "galera_nodes": [
        {"name": "pxdbc1", "address": "pxdbc1", "bootstrap": True},
        {"name": "pxdbc2", "address": "pxdbc2", "bootstrap": False},
        {"name": "pxdbc3", "address": "pxdbc3", "bootstrap": False},
    ],
    "galera_wait_for_all_seconds": 900,
    "kube_host": "kube-c-00", "datagateway_selector": "app=datagateway",
    "datagateway_probe_url": "http://kube-c-00:30080/mousey",
    "proxysql_host": "proxysql",
    "vault_url": "http://vault:8200",
    "vault_dependent_units": ["vault-secrets-backup.service"],
    "prometheus_url": "http://localhost:9090/prometheus",
    "alertmanager_url": "http://localhost:9093/alertmanager",
    "zammad_env_file": None,  # set per test
    "settle_seconds": 120, "silence_minutes": 45,
}


class FakeFleet:
    """A tiny model of the fleet that reacts to the commands it's sent."""

    def __init__(self):
        self.t = 1_000_000.0
        self.hv = {"10.69.69.40": {"up": True, "uptime": 99999, "stopped": []},
                   "10.69.69.41": {"up": True, "uptime": 99999, "stopped": []}}
        self.db = {n: {"reachable": True, "mysql": "active", "bootstrap": "inactive", "mysqld": "yes",
                       "pos": (UUID, 28), "port_open": True}
                   for n in ("pxdbc1", "pxdbc2", "pxdbc3")}
        self.sealed = False
        self.dg_ok = True
        self.dg_fixed_by = None  # "pods" | "proxysql" | None
        self.nginx = "active"
        self.dns = True
        self.lan_ip = "10.69.69.50"
        self.failed_units = set()
        self.commands = []
        self.tickets = {}
        self.articles = []
        self.silences = {}
        self.wol = []
        self.on_sleep = None
        self.sleeps = 0

    # -- Ops interface --------------------------------------------------
    def ssh(self, address, command, timeout=30):
        self.commands.append((address, command))
        if address in self.hv:
            h = self.hv[address]
            if not h["up"]:
                return False, "timeout"
            if command.startswith("sudo qm start"):
                vmid = command.split()[-1]
                h["stopped"] = [s for s in h["stopped"] if s[0] != vmid]
                return True, ""
            out = [str(h["uptime"])] + [f"STOPPED {i} onboot={o} template=" for i, o in h["stopped"]]
            return True, "\n".join(out)
        if address in self.db:
            n = self.db[address]
            if not n["reachable"]:
                return False, "timeout"
            if "pgrep" in command:
                return True, f"mysql={n['mysql']} bootstrap={n['bootstrap']} mysqld={n['mysqld']}"
            if "--wsrep-recover" in command:
                if n["pos"] is None:
                    return True, f"uuid:    {UUID}\nseqno:   -1"
                u, s = n["pos"]
                return True, f"... WSREP: Recovered position: {u}:{s}\nuuid:    {u}\nseqno:   -1"
            if "grastate.dat" in command and "sed" not in command:
                return True, f"uuid:    {UUID}\nseqno:   -1"
            if "mysql@bootstrap" in command and "sed" in command:
                n["bootstrap"], n["mysqld"] = "active", "yes"
                return True, ""
            if "stop mysql@bootstrap && sudo systemctl start mysql" in command:
                n["bootstrap"], n["mysql"] = "inactive", "active"
                return True, ""
            if command == "sudo systemctl start mysql":
                if any("active" in (m["mysql"], m["bootstrap"]) for m in self.db.values()):
                    n["mysql"], n["mysqld"] = "active", "yes"
                    return True, ""
                return False, "no primary to join"
            if "systemctl stop" in command:
                n["mysql"] = n["bootstrap"] = "inactive"
                n["mysqld"] = "no"
                return True, ""
        if address == "kube-c-00" and "kubectl delete pod" in command:
            if self.dg_fixed_by == "pods":
                self.dg_ok = True
            return True, ""
        if address == "proxysql" and "restart proxysql" in command:
            if self.dg_fixed_by == "proxysql":
                self.dg_ok = True
            return True, ""
        return False, f"unhandled {address}: {command}"

    def local(self, argv, timeout=60):
        self.commands.append(("local", " ".join(argv)))
        if argv[:2] == ["systemctl", "is-active"]:
            return self.nginx == "active", self.nginx
        if argv[:2] == ["systemctl", "restart"]:
            self.nginx = "active"
            return True, ""
        if argv[:2] == ["systemctl", "is-failed"]:
            return argv[2] in self.failed_units, "failed" if argv[2] in self.failed_units else "active"
        if argv[0] == "ip":
            return True, f"2: eth0    inet {self.lan_ip}/24 brd 10.69.69.255 scope global"
        if argv[0] == "sh" and "reset-failed" in argv[2]:
            self.failed_units.discard(argv[2].split()[2])
            return True, ""
        return True, ""

    def http(self, method, url, data=None, headers=None, timeout=10):
        if "/v1/sys/seal-status" in url:
            return 200, {"sealed": self.sealed, "initialized": True}
        if "mousey" in url:
            return (200, "ok") if self.dg_ok else (0, "refused")
        if "/api/v1/query" in url:
            return 200, {"data": {"result": []}}
        if url.endswith("/api/v2/silences"):
            sid = f"s{len(self.silences) + 1}"
            self.silences[sid] = data
            return 200, {"silenceID": sid}
        if "/api/v2/silence/" in url and method == "DELETE":
            self.silences.pop(url.rsplit("/", 1)[1], None)
            return 200, None
        if url.endswith("/api/v1/tickets") and method == "POST":
            tid = len(self.tickets) + 1
            self.tickets[tid] = {"state": "open", "title": data["title"]}
            self.articles.append(data["article"]["subject"])
            return 201, {"id": tid, "number": f"9{tid}"}
        m = re.search(r"/api/v1/tickets/(\d+)$", url)
        if m and method == "PUT":
            t = self.tickets[int(m.group(1))]
            if "article" in data:
                self.articles.append(data["article"]["subject"])
            if data.get("state"):
                t["state"] = data["state"]
            return 200, {}
        return 404, None

    def tcp_open(self, host, port, timeout=3):
        return self.db.get(host, {}).get("port_open", False)

    def resolves(self, name):
        return self.dns

    def send_wol(self, mac, broadcast):
        self.wol.append(mac)

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s
        self.sleeps += 1
        if self.sleeps > 2000:
            raise RuntimeError("recovery never finished")
        if self.on_sleep:
            self.on_sleep(self)

    # helpers
    def actions(self):
        return [c for a, c in self.commands if any(k in c for k in
                ("qm start", "systemctl start", "systemctl restart", "kubectl delete", "sed -i", "reset-failed"))]


def make(fleet, **kw):
    d = tempfile.mkdtemp()
    env = os.path.join(d, "zammad.env")
    with open(env, "w") as f:
        f.write("ZAMMAD_URL=http://localhost:8080\nZAMMAD_API_TOKEN=t\n")
    cfg = dict(CFG, zammad_env_file=env)
    fr.DISABLED_FLAG = os.path.join(d, "disabled")
    return fr.Recovery(cfg, fleet, os.path.join(d, "state.json"), log=lambda m: None, **kw), d


def all_down(fleet):
    for n in fleet.db.values():
        n.update(mysql="failed", bootstrap="inactive", mysqld="no", port_open=False)


class PureLogic(unittest.TestCase):
    def test_parse_position(self):
        self.assertEqual(fr.parse_position(f"WSREP: Recovered position: {UUID}:28\nuuid: {UUID}\nseqno: -1"), (UUID, 28))
        self.assertEqual(fr.parse_position(f"uuid:    {UUID}\nseqno:   41"), (UUID, 41))  # clean shutdown
        self.assertIsNone(fr.parse_position(f"uuid:    {UUID}\nseqno:   -1"))
        self.assertIsNone(fr.parse_position(""))

    def test_choose_highest(self):
        node, _ = fr.choose_bootstrap({"pxdbc1": (UUID, 28), "pxdbc2": (UUID, 31), "pxdbc3": (UUID, 30)}, "pxdbc1")
        self.assertEqual(node, "pxdbc2")

    def test_choose_tie_prefers_bootstrap_node(self):
        node, _ = fr.choose_bootstrap({"pxdbc1": (UUID, 28), "pxdbc2": (UUID, 28), "pxdbc3": (UUID, 28)}, "pxdbc1")
        self.assertEqual(node, "pxdbc1")
        node, _ = fr.choose_bootstrap({"pxdbc1": (UUID, 20), "pxdbc2": (UUID, 28), "pxdbc3": (UUID, 28)}, "pxdbc1")
        self.assertEqual(node, "pxdbc2")

    def test_choose_majority_uuid_beats_higher_seqno(self):
        node, _ = fr.choose_bootstrap({"pxdbc1": (UUID, 28), "pxdbc2": (UUID, 27), "pxdbc3": (OTHER, 999)}, "pxdbc1")
        self.assertEqual(node, "pxdbc1")

    def test_choose_with_missing_and_none(self):
        self.assertEqual(fr.choose_bootstrap({"pxdbc1": None, "pxdbc2": (UUID, 5)}, "pxdbc1")[0], "pxdbc2")
        self.assertIsNone(fr.choose_bootstrap({"pxdbc1": None, "pxdbc2": None}, "pxdbc1")[0])

    def test_assess(self):
        up = {"reachable": True, "mysql": "active", "bootstrap": "inactive"}
        down = {"reachable": True, "mysql": "failed", "bootstrap": "inactive"}
        joining = {"reachable": True, "mysql": "activating", "bootstrap": "inactive"}
        gone = {"reachable": False, "mysql": "", "bootstrap": ""}
        self.assertEqual(fr.galera_assess({"a": up, "b": down}), "primary")
        self.assertEqual(fr.galera_assess({"a": down, "b": down, "c": gone}), "down")
        self.assertEqual(fr.galera_assess({"a": up, "b": joining}), "starting")


class Runs(unittest.TestCase):
    def test_healthy_fleet_exits_quietly(self):
        f = FakeFleet()
        rec, d = make(f)
        self.assertEqual(rec.run(), 0)
        self.assertEqual(f.actions(), [])
        self.assertEqual(f.tickets, {})
        self.assertEqual(f.silences, {})
        self.assertFalse(os.path.exists(os.path.join(d, "state.json")))

    def test_dry_run_on_healthy_fleet_plans_nothing(self):
        f = FakeFleet()
        rec, _ = make(f, dry_run=True)
        rec.run()
        self.assertEqual(rec.planned, [])

    def test_disabled_flag(self):
        f = FakeFleet()
        f.sealed = True
        rec, d = make(f)
        open(fr.DISABLED_FLAG, "w").close()
        self.assertEqual(rec.run(), 0)
        self.assertEqual(f.tickets, {})

    def test_vault_sealed_waits_then_finishes(self):
        f = FakeFleet()
        f.sealed = True
        f.failed_units.add("vault-secrets-backup.service")

        def unseal_later(fl):
            if fl.sleeps == 40:  # 20 minutes of waiting
                fl.sealed = False
        f.on_sleep = unseal_later
        rec, _ = make(f)
        self.assertEqual(rec.run(), 0)
        self.assertIn("Waiting for you: unseal Vault", f.articles)
        self.assertEqual(f.articles.count("Waiting for you: unseal Vault"), 1)  # not every 30s
        self.assertEqual(f.tickets[1]["state"], "closed")
        self.assertEqual(f.silences, {})  # lifted while still waiting on Vault
        self.assertNotIn("vault-secrets-backup.service", f.failed_units)  # re-run after unseal

    def test_galera_full_crash_bootstraps_most_advanced(self):
        f = FakeFleet()
        all_down(f)
        f.db["pxdbc1"]["pos"] = (UUID, 28)
        f.db["pxdbc2"]["pos"] = (UUID, 31)
        f.db["pxdbc3"]["pos"] = (UUID, 30)
        rec, _ = make(f)
        self.assertEqual(rec.run(), 0)
        acts = f.actions()
        boot = [i for i, c in enumerate(acts) if "mysql@bootstrap" in c and "sed" in c]
        self.assertEqual(len(boot), 1)
        boot_node = [a for a, c in f.commands if "sed -i" in c][0]
        self.assertEqual(boot_node, "pxdbc2")
        for n in f.db.values():
            self.assertEqual((n["mysql"], n["bootstrap"]), ("active", "inactive"))  # moved off bootstrap unit
        self.assertEqual(f.tickets[1]["state"], "closed")

    def test_galera_waits_for_missing_node_then_bootstraps_without_it(self):
        f = FakeFleet()
        all_down(f)
        f.db["pxdbc3"]["reachable"] = False
        f.db["pxdbc1"]["pos"] = (UUID, 40)
        rec, _ = make(f)
        rec.state = {"run_started_at": f.t}
        rec.pass_once()
        self.assertFalse(any("sed -i" in c for _, c in f.commands))  # waits first
        f.t += 901
        rec.pass_once()
        self.assertEqual([a for a, c in f.commands if "sed -i" in c], ["pxdbc1"])

    def test_galera_split_brain_guard(self):
        f = FakeFleet()
        all_down(f)
        f.db["pxdbc2"]["reachable"] = False
        f.db["pxdbc2"]["port_open"] = True  # SSH gone, but still serving Galera
        rec, _ = make(f)
        rec.state = {"run_started_at": f.t}
        rec.pass_once()
        f.t += 3600
        res = rec.pass_once()
        self.assertEqual(res["galera"], fr.PROBLEM)
        self.assertFalse(any("sed -i" in c for _, c in f.commands))

    def test_galera_one_node_crashed_rejoins_without_bootstrap(self):
        f = FakeFleet()
        f.db["pxdbc3"].update(mysql="failed", mysqld="no")
        rec, _ = make(f)
        self.assertEqual(rec.run(), 0)
        self.assertFalse(any("sed -i" in c or "wsrep-recover" in c for _, c in f.commands))
        self.assertEqual(f.db["pxdbc3"]["mysql"], "active")

    def test_vm_start_only_in_post_boot_window(self):
        for uptime, expect_start in ((300, False), (1200, True), (7200, False)):
            f = FakeFleet()
            f.hv["10.69.69.41"].update(uptime=uptime, stopped=[("202", "1")])
            rec, _ = make(f)
            rec.state = {"run_started_at": f.t}
            rec.pass_once()
            started = any(c == "sudo qm start 202" for _, c in f.commands)
            self.assertEqual(started, expect_start, f"uptime={uptime}")

    def test_unreachable_hypervisor_gets_wol_after_two_minutes(self):
        f = FakeFleet()
        f.hv["10.69.69.41"]["up"] = False
        rec, _ = make(f)
        rec.state = {"run_started_at": f.t}
        rec.pass_once()
        self.assertEqual(f.wol, [])
        f.t += 130
        rec.pass_once()
        self.assertEqual(f.wol, ["1c:fd:08:7c:3b:f4"])
        f.t += 60
        rec.pass_once()
        self.assertEqual(len(f.wol), 1)  # not every pass

    def test_datagateway_escalates_pods_then_proxysql(self):
        f = FakeFleet()
        f.dg_ok = False
        f.dg_fixed_by = "proxysql"
        rec, _ = make(f)
        self.assertEqual(rec.run(), 0)
        acts = f.actions()
        self.assertTrue(any("kubectl delete pod -l app=datagateway" in c for c in acts))
        self.assertTrue(any("restart proxysql" in c for c in acts))
        self.assertLess(next(i for i, c in enumerate(acts) if "kubectl" in c),
                        next(i for i, c in enumerate(acts) if "proxysql" in c))

    def test_zammad_down_queues_updates(self):
        f = FakeFleet()
        f.nginx = "failed"
        real_http = f.http
        calls = {"n": 0}

        def flaky(method, url, data=None, headers=None, timeout=10):
            if "/api/v1/tickets" in url:
                calls["n"] += 1
                if calls["n"] <= 3:
                    return 0, "connection refused"
            return real_http(method, url, data, headers, timeout)
        f.http = flaky
        rec, _ = make(f)
        self.assertEqual(rec.run(), 0)
        self.assertEqual(len(f.tickets), 1)
        self.assertIn("Recovery started", f.articles)


if __name__ == "__main__":
    unittest.main(verbosity=2)
