#!/usr/bin/env bash
set -euo pipefail

# Simple helper to install nginx + certbot and create a reverse-proxy for CasaOS Native Panel
# Usage: sudo bash scripts/reverse-proxy-setup.sh your.domain.tld

DOMAIN="${1:-}"
if [ -z "${DOMAIN}" ]; then
  echo "Usage: $0 your.domain.tld"
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root"
  exit 1
fi

# Ask user for confirmation
read -r -p "Do you want to install Let's Encrypt (certbot) and Nginx for better security and enable HTTPS for ${DOMAIN}? [Y/n] " response
response=${response:-Y}
if [[ ! "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
  echo "Aborting: user declined installation of Nginx/Let's Encrypt."
  exit 0
fi

apt-get update
apt-get install -y nginx certbot python3-certbot-nginx

NGINX_CONF="/etc/nginx/sites-available/casaos_native"
cat > "${NGINX_CONF}" <<EOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:8080/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

ln -sf "${NGINX_CONF}" /etc/nginx/sites-enabled/casaos_native
nginx -t
systemctl reload-or-restart nginx

# Obtain TLS cert with certbot
certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos -m "admin@${DOMAIN}"

echo "Reverse proxy configured for ${DOMAIN}. HTTPS should be active."
echo "Set CASAOS_HOST=127.0.0.1 in /etc/casaos-native-panel.env and restart the panel so it is only reachable through Nginx."
