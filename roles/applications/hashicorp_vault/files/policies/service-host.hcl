path "kv/data/aws/iam_access_keys/*" {
  capabilities = ["read"]
}
path "kv/data/ssl_certs/*" {
  capabilities = ["read", "create", "update"]
}
path "kv/metadata/ssl_certs/*" {
  capabilities = ["read", "list"]
}
path "kv/data/splunk/*" {
  capabilities = ["read"]
}
path "kv/data/k8clusters/*" {
  capabilities = ["read", "create", "update"]
}
path "kv/data/proxmox/*" {
  capabilities = ["read"]
}
path "kv/data/jenkins/*" {
  capabilities = ["read"]
}
path "kv/data/ssh/*" {
  capabilities = ["read"]
}
path "kv/data/theia/*" {
  capabilities = ["read"]
}
path "kv/data/github/*" {
  capabilities = ["read"]
}
path "kv/data/opnsense/*" {
  capabilities = ["read"]
}
path "kv/data/semaphore/*" {
  capabilities = ["read"]
}
path "kv/data/monitoring/*" {
  capabilities = ["read"]
}
path "kv/data/zammad/*" {
  capabilities = ["read"]
}
path "kv/data/percona_cluster/*" {
  capabilities = ["read", "create", "update"]
}
# Broad read+list added for the vault_backup role (backup_vault_secrets.py)
# -- it needs to discover and read every secret path to produce a full
# backup, not just the per-app prefixes above. Read-only: doesn't grant
# create/update/delete beyond what the specific paths above already have.
path "kv/metadata/*" {
  capabilities = ["read", "list"]
}
path "kv/data/*" {
  capabilities = ["read"]
}
