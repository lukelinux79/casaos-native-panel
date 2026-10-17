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

The first admin account is created from environment variables on first start, e.g. in `/etc/casaos-native-panel.env`:

    CASAOS_ADMIN_USER=admin
    CASAOS_ADMIN_PASSWORD=secret-with-8-chars-or-more

After the first login further accounts are managed in the panel under *Panel accounts*; the variables can then be removed.
Behind the proxy set `CASAOS_HOST=127.0.0.1` so the panel is only reachable through Nginx.
The session cookie is marked `Secure` automatically when Nginx forwards `X-Forwarded-Proto: https`.
