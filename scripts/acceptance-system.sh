#!/usr/bin/env bash
set -euo pipefail

# Temporary, synthetic-data-only system service for manual acceptance testing.
# This does not replace a production service or touch the desktop keyring.
[[ $EUID -eq 0 ]] || { echo 'Administrator privileges required.' >&2; exit 1; }
[[ $# -eq 2 ]] || { echo 'Usage: acceptance-system.sh start|stop <source-directory>' >&2; exit 2; }
source_dir=$(realpath -- "$2")
work=/run/agent-keyring-acceptance
policy=/usr/share/polkit-1/actions/io.github.from-nibly.agent-keyring.policy
case "$1" in
  start)
    [[ ! -e "$work" ]] || { echo 'Acceptance directory already exists; stop it explicitly first.' >&2; exit 1; }
    binary=$(realpath -- "$source_dir/result-acceptance/bin/agent-keyring")
    [[ "$binary" == /nix/store/* && -x "$binary" ]] || { echo 'Build the immutable acceptance binary first.' >&2; exit 1; }
    install -d -m0755 "$work"
    install -m0644 "$source_dir/share/agent-keyring/io.github.from-nibly.agent-keyring.policy" "$work/policy"
    if [[ -e "$policy" ]]; then
      cmp "$work/policy" "$policy" || { echo 'Existing policy differs; refusing to overwrite it.' >&2; exit 1; }
    else
      install -m0644 "$work/policy" "$policy"
      touch "$work/created-policy"
    fi
    touch "$work/acceptance-marker"
    /usr/bin/systemd-run --unit=agent-keyring-acceptance --collect \
      --property=UMask=0077 --property=LimitCORE=0 \
      --property=NoNewPrivileges=yes --property=ProtectSystem=strict \
      --property=ProtectHome=read-only --property="ReadWritePaths=$work" \
      --property=RestrictAddressFamilies=AF_UNIX \
      "$binary" --socket "$work/control.sock" daemon \
        --state-dir "$work/state" --zenity /usr/bin/zenity
    ;;
  stop)
    [[ -f "$work/acceptance-marker" && ! -L "$work" ]] || { echo 'Missing acceptance marker; refusing cleanup.' >&2; exit 1; }
    if [[ $(/usr/bin/systemctl show agent-keyring-acceptance.service -p LoadState --value) != not-found ]]; then
      /usr/bin/systemctl stop agent-keyring-acceptance.service
    fi
    if [[ -f "$work/created-policy" ]] && cmp -s "$work/policy" "$policy"; then
      rm -- "$policy"
    fi
    # The fixed root-owned directory contains only this service's synthetic data.
    rm -f -- "$work/control.sock" "$work/bin/agent-keyring" "$work/policy" "$work/created-policy" \
      "$work/state/vault.sqlite3" "$work/state/vault.sqlite3-journal" "$work/state/daemon.lock" "$work/acceptance-marker"
    [[ ! -d "$work/bin" ]] || rmdir -- "$work/bin"
    [[ ! -d "$work/state" ]] || rmdir -- "$work/state"
    rmdir -- "$work"
    ;;
  *) echo 'Expected start or stop.' >&2; exit 2 ;;
esac
