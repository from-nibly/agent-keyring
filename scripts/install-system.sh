#!/usr/bin/env bash
set -euo pipefail

# Called explicitly by an administrator, never by the request protocol.
if [[ $EUID -ne 0 ]]; then
  printf 'Run this installer with pkexec or sudo. It installs the system daemon and polkit policy.\n' >&2
  exit 1
fi
if [[ $# -ne 2 ]]; then
  printf 'Usage: install-system.sh <package-directory> <absolute-zenity-path>\n' >&2
  exit 2
fi
package=$(realpath -- "$1")
zenity=$(realpath -- "$2")
if [[ ! -x "$package/bin/agent-keyring" || ! -x "$zenity" ]]; then
  printf 'Missing agent-keyring or zenity executable.\n' >&2
  exit 2
fi
# ExecStart is not a shell, but whitespace/specifiers would change its parsing.
if [[ ! "$zenity" =~ ^/[a-zA-Z0-9_./+-]+$ ]]; then
  printf 'Unsupported characters in zenity executable path.\n' >&2
  exit 2
fi
for tool in /usr/bin/pkcheck /usr/bin/loginctl /usr/bin/systemctl; do
  [[ -x "$tool" ]] || { printf 'Required system tool missing: %s\n' "$tool" >&2; exit 1; }
done
share="$package/share/agent-keyring"
[[ -f "$share/agent-keyring.service.in" && -f "$share/io.github.from-nibly.agent-keyring.policy" ]]

install -d -m 0755 /usr/local/libexec /etc/agent-keyring
install -m 0755 "$package/bin/agent-keyring" /usr/local/libexec/agent-keyring.new
mv -f /usr/local/libexec/agent-keyring.new /usr/local/libexec/agent-keyring
install -m 0644 "$share/io.github.from-nibly.agent-keyring.policy" \
  /usr/share/polkit-1/actions/io.github.from-nibly.agent-keyring.policy
service=$(mktemp --suffix=.service)
trap 'rm -f -- "$service"' EXIT
sed "s|@ZENITY@|$zenity|g" "$share/agent-keyring.service.in" > "$service"
/usr/bin/systemd-analyze verify "$service"
install -m 0644 "$service" /etc/systemd/system/agent-keyring.service
/usr/bin/systemctl daemon-reload
/usr/bin/systemctl enable agent-keyring.service
/usr/bin/systemctl restart agent-keyring.service
/usr/bin/systemctl is-active --quiet agent-keyring.service
printf '%s\n%s\n' "$package" "$zenity" > /etc/agent-keyring/install-manifest
chmod 0644 /etc/agent-keyring/install-manifest
printf 'Installed agent-keyring daemon and polkit policy. No existing keyring secrets were imported or changed.\n'
