#!/usr/bin/env python3
"""One-time bootstrap of Semaphore's project/keys/repository/inventory/
environment/templates/schedule, replicating the 5 legacy Jenkins jobs
(DeployContainer, deploy_datagateway, ManageDockerContainers,
Manage_Theia_Services, Refresh_OS_Baseline -- see
roles/applications/jenkins/files/jobs/*.xml for the originals).

This is idempotency-unaware by design: it's meant to be run once against
a fresh Semaphore instance (e.g. after a `service` VM rebuild), not on
every deploy. Re-running it against an already-configured instance will
create duplicate projects.

Run directly on `service` (has loopback access to Semaphore + the Vault
AppRole needed to read the Semaphore admin password and the SSH/vault
key material this script uploads into Semaphore's own key store):

    python3 roles/applications/semaphore/bootstrap_templates.py

Requires /home/automation/.ssh/automation.pem and
/etc/ansible-vault-password.txt to exist on the host already (both are
provisioned by other roles as part of the normal fleet bootstrap).
"""
import json
import subprocess
import urllib.request
import urllib.error

SEMAPHORE_URL = "http://localhost:3000"
VAULT_ADDR = "http://vault.internal.levantine.io:8200"


def vault_token():
    result = subprocess.run(
        ["bash", "-c", "source /etc/vault-approle.env && echo $VAULT_ROLE_ID:$VAULT_SECRET_ID"],
        capture_output=True, text=True,
    )
    role_id, secret_id = result.stdout.strip().split(":")
    req = urllib.request.Request(
        f"{VAULT_ADDR}/v1/auth/approle/login",
        data=json.dumps({"role_id": role_id, "secret_id": secret_id}).encode(),
        method="POST",
    )
    return json.loads(urllib.request.urlopen(req).read())["auth"]["client_token"]


def vault_read(path, token):
    req = urllib.request.Request(f"{VAULT_ADDR}/v1/{path}", method="GET")
    req.add_header("X-Vault-Token", token)
    return json.loads(urllib.request.urlopen(req).read())["data"]["data"]


vtoken = vault_token()
ADMIN_PASSWORD = vault_read("kv/data/semaphore/admin", vtoken)["admin_password"]

with open("/home/automation/.ssh/automation.pem") as f:
    AUTOMATION_PRIVATE_KEY = f.read()

with open("/etc/ansible-vault-password.txt") as f:
    VAULT_PASSWORD_FILE_CONTENT = f.read().strip()

login_req = urllib.request.Request(
    f"{SEMAPHORE_URL}/api/auth/login",
    data=json.dumps({"auth": "admin", "password": ADMIN_PASSWORD}).encode(),
    method="POST",
)
login_req.add_header("Content-Type", "application/json")
login_resp = urllib.request.urlopen(login_req)
session_cookie = login_resp.headers.get("Set-Cookie").split(";")[0]
print("Logged in")


def api(method, path, body=None):
    url = f"{SEMAPHORE_URL}/api{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Cookie", session_cookie)
    try:
        resp = urllib.request.urlopen(req)
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, (json.loads(raw) if raw else raw.decode(errors="replace"))


# --- project ---
status, body = api("POST", "/projects", {"name": "Homelab Ops", "alert": False, "max_parallel_tasks": 0})
print("create project:", status)
project_id = body["id"]

# --- ssh key (fleet access) ---
status, body = api("POST", f"/project/{project_id}/keys", {
    "name": "automation-ssh",
    "type": "ssh",
    "project_id": project_id,
    "ssh": {"login": "automation", "private_key": AUTOMATION_PRIVATE_KEY},
})
print("create ssh key:", status)
ssh_key_id = body["id"]

# --- vault password key (ansible-vault, for vars_files: vault.yml) ---
status, body = api("POST", f"/project/{project_id}/keys", {
    "name": "ansible-vault-password",
    "type": "login_password",
    "project_id": project_id,
    "login_password": {"password": VAULT_PASSWORD_FILE_CONTENT},
})
print("create vault key:", status)
vault_key_id = body["id"]

# --- "none" key for public repo access ---
status, body = api("POST", f"/project/{project_id}/keys", {
    "name": "none",
    "type": "none",
    "project_id": project_id,
})
print("create none key:", status)
none_key_id = body["id"]

# --- repository ---
status, body = api("POST", f"/project/{project_id}/repositories", {
    "name": "ansible",
    "project_id": project_id,
    "git_url": "https://github.com/Levantine-1/ansible.git",
    "git_branch": "master",
    "ssh_key_id": none_key_id,
})
print("create repository:", status)
repo_id = body["id"]

# --- inventory ---
status, body = api("POST", f"/project/{project_id}/inventory", {
    "name": "production",
    "project_id": project_id,
    "type": "file",
    "inventory": "inventories/production/production.ini",
    "ssh_key_id": ssh_key_id,
})
print("create inventory:", status)
inventory_id = body["id"]

# --- environment ---
status, body = api("POST", f"/project/{project_id}/environment", {
    "name": "default",
    "project_id": project_id,
    "json": json.dumps({}),
    "env": json.dumps({"ANSIBLE_HOST_KEY_CHECKING": "False"}),
})
print("create environment:", status)
environment_id = body["id"]


def make_template(name, playbook, arguments=None, survey_vars=None):
    body = {
        "project_id": project_id,
        "name": name,
        "app": "ansible",
        "playbook": playbook,
        "inventory_id": inventory_id,
        "repository_id": repo_id,
        "environment_id": environment_id,
        # type must be "password", not "" -- an empty type silently
        # doesn't get treated as an ansible-vault password source at
        # runtime (confirmed live: "Attempting to decrypt but no vault
        # secrets found" despite the key linkage being present).
        "vaults": [{"name": "vault-password", "vault_key_id": vault_key_id, "type": "password"}],
    }
    if arguments:
        body["arguments"] = json.dumps(arguments)
    if survey_vars:
        body["survey_vars"] = survey_vars
    status, resp = api("POST", f"/project/{project_id}/templates", body)
    print(f"create template {name}:", status)
    return resp["id"]


# --- Deploy DataGateway (was: deploy_datagateway Jenkins job) ---
make_template(
    "Deploy DataGateway",
    "roles/applications/dataGateway/dataGatewayK8Configs.yml",
    arguments=["-l", "DataGatewayK8Cluster"],
)

# --- Deploy Container (was: DeployContainer Jenkins job) ---
container_choices = ["portfolio", "thisper", "real-estate", "booking-movie-ticket",
                      "education-platform", "dental-care", "pet-care", "processmining",
                      "livecam"]
make_template(
    "Deploy Container",
    "roles/applications/nginx-proxyContainers/deployContainerWrapper.yml",
    survey_vars=[{
        "name": "container_name",
        "title": "Container",
        "type": "enum",
        "required": True,
        "values": [{"name": c, "value": c} for c in container_choices],
    }],
)

# --- Manage Docker Containers (was: ManageDockerContainers Jenkins job) ---
docker_services = ["nginx-proxy", "portfolio", "real-estate", "booking-movie-ticket",
                    "thisper", "education-platform", "dental-care", "pet-care", "processmining",
                    "livecam"]
manage_docker_template_id = make_template(
    "Manage Docker Containers",
    "roles/applications/nginx-proxyContainers/manageDockerContainerState.yml",
    arguments=["-l", "VMWareDockerHosts"],
    survey_vars=[
        {
            "name": "container_action_string",
            "title": "Action",
            "type": "enum",
            "required": True,
            "default_value": "restart",
            "values": [{"name": a, "value": a} for a in ["restart", "start", "stop"]],
        },
        {
            "name": "container_names_string",
            "title": "Containers (comma-separated)",
            "type": "",
            "required": True,
            "default_value": ",".join(docker_services),
        },
    ],
)

# --- Manage Theia Services (was: Manage_Theia_Services Jenkins job) ---
make_template(
    "Manage Theia Services",
    "roles/applications/theia/manage.yml",
    survey_vars=[{
        "name": "theia_action",
        "title": "Action",
        "type": "enum",
        "required": True,
        "values": [{"name": a, "value": a} for a in ["start", "stop", "deploy"]],
    }],
)

# --- Refresh OS Baseline (was: Refresh_OS_Baseline Jenkins job) ---
# The Jenkins job took a free-text `extra_params` (default
# "-l !localhost:!jenkins.internal.levantine.io") since ansible-playbook's
# -l/--limit is a CLI flag, not something a playbook var can set --
# Semaphore survey vars become -e extra-vars, not CLI flags, so there's
# no clean way to expose this as a runtime prompt. Baked in as a fixed
# argument (jenkins exclusion dropped since it's decommissioned); edit
# the template's Arguments in the UI for one-off narrower runs.
make_template(
    "Refresh OS Baseline",
    "roles/os_configs/all.yml",
    arguments=["-l", "!localhost", "--start-at-task", "Check if lock file exists"],
)

# --- nightly container restart schedule (was: ManageDockerContainers' H 3 * * * TimerTrigger) ---
status, body = api("POST", f"/project/{project_id}/schedules", {
    "project_id": project_id,
    "template_id": manage_docker_template_id,
    "name": "Nightly container restart",
    "cron_format": "0 3 * * *",
    "active": True,
})
print("create schedule:", status)

print(f"\nDone. Project id: {project_id}")
