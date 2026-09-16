# WireGuard Real Auto Panel v2

- Real VPS management over SSH (Paramiko)
- Automatic WireGuard installation on common Linux package managers
- Automatic key generation and wg0 configuration
- IPv4 forwarding + NAT + firewall rule when available
- Create, enable/disable and delete real WireGuard peers
- Client .conf and QR download
- Custom endpoint and DNS
- Expiry worker that disables expired peers
- SQLite persistence
- Flat ZIP: no top-level folder

Change the default admin credentials immediately. Prefer SSH keys and a restricted sudo account on production VPS hosts.
