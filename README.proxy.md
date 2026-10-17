## Reverse proxy and TLS

You can protect the CasaOS Native Panel with an Nginx reverse proxy and a Let's Encrypt TLS certificate using the helper script.

Do you want to install Let's Encrypt and Nginx for better security? If you run the helper script it will prompt you for confirmation before making changes.

Usage (will ask for confirmation):

sudo bash scripts/reverse-proxy-setup.sh your.domain.tld

This will:
- install nginx and certbot
- create a site config that proxies traffic to the panel (listening on 127.0.0.1:8080)
- request and install a TLS certificate for your domain via certbot

Ensure DNS for your domain points to the server's public IP before running.

## Admin credentials

Set the admin account by environment variables for the systemd service (example):

Environment=CASAOS_ADMIN_USER=admin
Environment=CASAOS_ADMIN_PASSWORD=secret

Both variables are required; the panel refuses to start without them (password min. 8 characters).
Restart the service after updating the unit file.
