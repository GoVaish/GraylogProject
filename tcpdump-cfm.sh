#!/usr/bin/env bash
set -euo pipefail


: "${IFACE:=enp0s3}"
: "${PCAP_DIR:=/var/lib/tcpdump}"
: "${ROTATE_SEC:=300}"
: "${KEEP_FILES:=288}"
: "${TCPDUMP_USER:=tcpdump}"

mkdir -p "$PCAP_DIR"
# Ensure the tcpdump user owns the dir and perms are safe
if id "$TCPDUMP_USER" &>/dev/null; then
  chown "$TCPDUMP_USER":"$TCPDUMP_USER" "$PCAP_DIR"
  chmod 0750 "$PCAP_DIR"
fi

# Make sure /usr/sbin/tcpdump has needed caps (one-time; ignore errors)
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump 2>/dev/null || true

exec /usr/sbin/tcpdump \
  -i "$IFACE" \
  -nn -p \
  -s "$SNAPLEN" \
  -U \
  -G "$ROTATE_SEC" \
  -W "$KEEP_FILES" \
  -w "$PCAP_DIR/cfm-%Y%m%d-%H%M%S.pcap" \
  -Z "$TCPDUMP_USER" \
  $BPF_FILTER
