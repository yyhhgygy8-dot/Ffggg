#!/usr/bin/env bash
set -euo pipefail
WG_IFACE="${WG_IFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_SUBNET="${WG_SUBNET:-10.66.66.0/24}"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y wireguard wireguard-tools iptables iproute2
elif command -v dnf >/dev/null; then
  dnf install -y wireguard-tools iptables iproute
elif command -v yum >/dev/null; then
  yum install -y wireguard-tools iptables iproute
elif command -v apk >/dev/null; then
  apk add wireguard-tools iptables iproute2
else
  echo "Unsupported package manager" >&2; exit 1
fi
install -d -m 700 /etc/wireguard
uplink=$(ip route show default | awk 'NR==1{print $5}')
[ -n "$uplink" ] || uplink=eth0
[ -f /etc/wireguard/server_private.key ] || wg genkey > /etc/wireguard/server_private.key
chmod 600 /etc/wireguard/server_private.key
priv=$(cat /etc/wireguard/server_private.key)
printf '%s' "$priv" | wg pubkey > /etc/wireguard/server_public.key
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.src_valid_mark=1\n' > /etc/sysctl.d/99-wireguard-panel.conf
sysctl --system >/dev/null 2>&1 || true
python3 - "$WG_SUBNET" "$WG_IFACE" "$WG_PORT" "$uplink" "$priv" <<'PY' > /etc/wireguard/${WG_IFACE}.conf
import ipaddress,sys
subnet,iface,port,uplink,priv=sys.argv[1:]
net=ipaddress.ip_network(subnet,strict=False)
print('[Interface]')
print(f'Address = {net.network_address+1}/{net.prefixlen}')
print(f'ListenPort = {port}')
print(f'PrivateKey = {priv}')
print(f'PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s {subnet} -o {uplink} -j MASQUERADE')
print(f'PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s {subnet} -o {uplink} -j MASQUERADE')
PY
chmod 600 /etc/wireguard/${WG_IFACE}.conf
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active'; then ufw allow "$WG_PORT/udp"; fi
if command -v systemctl >/dev/null; then
  systemctl enable wg-quick@${WG_IFACE}
  systemctl restart wg-quick@${WG_IFACE}
else
  wg-quick down "$WG_IFACE" 2>/dev/null || true
  wg-quick up "$WG_IFACE"
fi
wg show "$WG_IFACE"
