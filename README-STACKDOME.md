# StackDome deployment

This panel runs on StackDome and manages **real Linux VPS servers over SSH**.

1. Upload the ZIP with files directly at the archive root.
2. Deploy the web service on port 5000.
3. Set ADMIN_USERNAME, ADMIN_PASSWORD and a long random SECRET_KEY.
4. Open the panel, add a Linux VPS with root SSH (or a sudo user), then press Install WireGuard.
5. The panel installs WireGuard, enables IPv4 forwarding/NAT, creates wg0, and can create real client configs/QR codes.

Important: StackDome hosts the panel; the VPN itself runs on the selected real VPS. A normal StackDome container cannot grant itself kernel networking privileges on an unrelated VPS.
