"""SSH and Proxmox VM control.

This is the only module in the agent that can change anything, so the
criticality check is enforced *here* rather than only at the call sites. A new
caller (including a future tool exposed to an LLM) therefore cannot bypass the
policy by forgetting to check first -- it has to go through a function that
refuses.

Plain `ssh` via subprocess rather than paramiko: it is how every other piece of
automation in this project reaches the fleet, it picks up the same key and
host-key handling, and it avoids a dependency.
"""
import shlex
import subprocess

from . import config


class ActionRefused(RuntimeError):
    """Raised when policy forbids an action. Not an error condition -- it is
    the safety boundary doing its job, and callers should report it as such."""


def _ssh_argv(address, timeout):
    return [
        "ssh",
        "-i", config.SSH_KEY,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout={min(timeout, 15)}",
        "-o", "LogLevel=ERROR",
        f"{config.SSH_USER}@{address}",
    ]


def ssh(address, command, timeout=20):
    """Run a command over SSH. Returns (ok, output).

    Never raises on failure: a dead host is the normal case for InstanceDown,
    and the *fact* that SSH timed out is itself diagnostic information that
    belongs in the bundle rather than an exception that aborts collection.
    """
    if not address:
        return False, "(no address known for this host)"
    argv = _ssh_argv(address, timeout) + [command]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return False, f"(ssh timed out after {timeout}s -- host unreachable or hung)"
    except OSError as e:
        return False, f"(ssh failed to start: {e})"
    out = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, out.strip() or "(no output)"


def host_address(host):
    pol = config.host_policy(host)
    if pol.get("fqdn"):
        return pol["fqdn"]
    hypervisors = config.fleet().get("hypervisors") or {}
    if host in hypervisors:
        return hypervisors[host].get("address")
    return None


def hypervisor_address(host):
    pol = config.host_policy(host)
    name = pol.get("hypervisor")
    if not name:
        return None
    return (config.fleet().get("hypervisors") or {}).get(name, {}).get("address")


def _assert_actionable(host):
    pol = config.host_policy(host)
    if not pol["known"]:
        raise ActionRefused(
            f"'{host}' is not declared in fleet.yml. Unknown hosts are treated as critical "
            f"(fail closed), so no action is taken -- add it to fleet.yml to change that."
        )
    if pol["critical"]:
        raise ActionRefused(
            f"'{host}' is marked critical in fleet.yml and must never be auto-actioned. "
            f"Reason: {pol['reason'] or 'no reason recorded'}"
        )
    return pol


def restart_container(host, container, timeout=90):
    """Restart a Docker container on a host."""
    _assert_actionable(host)
    address = host_address(host)
    # shlex.quote because container names ultimately trace back to alert
    # labels; a name is not a place to trust string interpolation.
    ok, out = ssh(address, f"sudo docker restart {shlex.quote(container)}", timeout=timeout)
    return ok, out


def start_container(host, container, timeout=90):
    """Start a stopped Docker container.

    Distinct from restart_container: `docker restart` on an already-stopped
    container does work (Docker treats it as an implicit start), but a
    caller reasoning explicitly about "the host/container is down, bring it
    up" -- the local model's decision path in particular -- should be able to
    say `start` and have it read that way in the action log, not show up as
    a "restart" of something that was never running to begin with.
    """
    _assert_actionable(host)
    address = host_address(host)
    ok, out = ssh(address, f"sudo docker start {shlex.quote(container)}", timeout=timeout)
    return ok, out


def stop_container(host, container, timeout=90):
    """Stop a Docker container. Unpaired stop (no follow-up start attempt) is
    a real, distinct risk from restart/start -- callers are expected to
    verify and escalate if this was the wrong call, same as any other
    action; this function itself has no opinion, it just stops it."""
    _assert_actionable(host)
    address = host_address(host)
    ok, out = ssh(address, f"sudo docker stop {shlex.quote(container)}", timeout=timeout)
    return ok, out


def restart_service(host, unit, timeout=90):
    """Restart a systemd unit on a host."""
    _assert_actionable(host)
    address = host_address(host)
    ok, out = ssh(address, f"sudo systemctl restart {shlex.quote(unit)}", timeout=timeout)
    if ok:
        _, status = ssh(address, f"systemctl is-active {shlex.quote(unit)}", timeout=20)
        return ok, f"{out}\nis-active: {status}".strip()
    return ok, out


def start_service(host, unit, timeout=90):
    """Start a stopped systemd unit."""
    _assert_actionable(host)
    address = host_address(host)
    ok, out = ssh(address, f"sudo systemctl start {shlex.quote(unit)}", timeout=timeout)
    if ok:
        _, status = ssh(address, f"systemctl is-active {shlex.quote(unit)}", timeout=20)
        return ok, f"{out}\nis-active: {status}".strip()
    return ok, out


def stop_service(host, unit, timeout=90):
    """Stop a systemd unit. Same unpaired-stop caveat as stop_container."""
    _assert_actionable(host)
    address = host_address(host)
    ok, out = ssh(address, f"sudo systemctl stop {shlex.quote(unit)}", timeout=timeout)
    return ok, out


def qm(host, subcommand, timeout=60):
    """Run a `qm` subcommand for a guest on its hypervisor.

    Read-only subcommands (status/config) are permitted against any host,
    including critical ones -- inspecting `vault`'s VM state is exactly the
    kind of diagnostic that should always be allowed. State-changing ones go
    through _assert_actionable().
    """
    readonly = subcommand.split()[0] in ("status", "config", "list")
    if not readonly:
        _assert_actionable(host)

    pol = config.host_policy(host)
    vm_id = pol.get("vm_id")
    address = hypervisor_address(host)
    if not vm_id or not address:
        return False, f"(no hypervisor/vm_id recorded for '{host}' in fleet.yml)"

    parts = subcommand.split()
    verb, rest = parts[0], parts[1:]
    command = f"sudo qm {shlex.quote(verb)} {int(vm_id)} {' '.join(rest)}".strip()
    return ssh(address, command, timeout=timeout)


def restart_host(host, timeout=120):
    """Reboot a guest VM via its hypervisor.

    `qm reboot` rather than `ssh reboot` deliberately: the case that needs this
    is a host that is not answering SSH, where an in-guest reboot is not an
    option. Going through the hypervisor also means the action works
    identically whether the guest is wedged or merely unhealthy.
    """
    _assert_actionable(host)
    ok, out = qm(host, "reboot", timeout=timeout)
    if not ok and "not running" in out.lower():
        # A stopped VM cannot be rebooted; starting it is the equivalent
        # intent and is the actual fix after a hypervisor came up with
        # on_boot unset (the 2026-08-20 outage).
        return qm(host, "start", timeout=timeout)
    return ok, out


def start_host(host, timeout=120):
    """Start a stopped guest VM. Thin wrapper for symmetry with
    start_container/start_service -- qm() already does the real work and is
    already gated through _assert_actionable()."""
    return qm(host, "start", timeout=timeout)


def stop_host(host, timeout=120):
    """Stop a guest VM (not reboot). Same unpaired-stop caveat as
    stop_container/stop_service -- this is the highest-blast-radius verb the
    local tier can now reach, so callers must still verify and escalate if
    stopping the host was not actually the fix."""
    return qm(host, "stop", timeout=timeout)
