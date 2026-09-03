#!/usr/bin/env bash
# Prunes disposable GitHub Actions runner cruft that accumulates forever
# otherwise -- confirmed live (2026-09-03) as the entire cause of a
# DiskSpaceLow incident on dockerhost1 (96% used, 1.3GB free): ten
# self-hosted runners (one per repo, see install.yml's runner_instances)
# each silently accumulated two kinds of waste that nothing ever cleaned up:
#
#   1. _work/_update -- the runner's OWN self-update staging directory.
#      Confirmed stale: the runner's live bin/Runner.Listener already
#      matched this directory's timestamp, meaning the update had already
#      applied over a week earlier and this copy was pure leftover.
#   2. _work/<repo>/<repo>/terraform/.terraform -- Terraform's
#      provider-plugin cache for repos whose CI runs `terraform init`
#      (livecam, real_estate, etc.). Always pure, disposable download
#      cache by design in every Terraform setup (regenerated automatically
#      on the next init) -- confirmed here specifically too: remote state
#      backend, no local .tfstate at risk.
#
# Both totalled ~13.9GB across the fleet the one time this was checked by
# hand. Nothing generates them on purpose; they are a byproduct of the
# runner's update mechanism and of CI running `terraform init`, and upstream
# never cleans either up itself.
#
# Age-gated (-mmin +120, i.e. untouched for 2+ hours) rather than an
# unconditional rm -rf, so this can never step on a self-update or a
# terraform init that happens to be running exactly when the timer fires --
# a real CI job or update finishes in minutes, so anything genuinely in
# progress is far younger than the cutoff, and anything older is
# unambiguously done and abandoned.
set -euo pipefail

log() { logger -t prune-runner-work -- "$@"; echo "$@"; }

shopt -s nullglob
pruned_any=0

for update_dir in /opt/actions-runner/*/_work/_update; do
  if find "$update_dir" -maxdepth 0 -mmin +120 | grep -q .; then
    size=$(du -sh "$update_dir" 2>/dev/null | cut -f1)
    log "removing stale self-update staging dir: $update_dir ($size)"
    rm -rf "$update_dir"
    pruned_any=1
  fi
done

for tf_cache in /opt/actions-runner/*/_work/*/*/terraform/.terraform; do
  if find "$tf_cache" -maxdepth 0 -mmin +120 | grep -q .; then
    size=$(du -sh "$tf_cache" 2>/dev/null | cut -f1)
    log "removing terraform provider cache: $tf_cache ($size)"
    rm -rf "$tf_cache"
    pruned_any=1
  fi
done

if [ "$pruned_any" -eq 0 ]; then
  log "nothing to prune"
fi
