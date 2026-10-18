# Deployment files

- `web-re-engine.service`: systemd unit that runs the backend in production mode on `127.0.0.1:3001`.
- `Caddyfile`: HTTPS reverse proxy (internal CA for IP addresses, or Let's Encrypt for a domain).

The full installation, upgrade, backup and troubleshooting guide is in the main
[README](../README.md#installing-on-a-fresh-server), so the steps live in one place.
