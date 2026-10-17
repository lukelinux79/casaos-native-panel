# CasaOS Native Panel

A simple, debian-first management panel based on CasaOS concepts but designed for native Debian 12 systems with optional Docker support.

## Goals
- Keep a clean and simple admin UI
- Support native Debian 12 x86_64 installation without Docker
- Support Docker mode as an optional compatibility layer
- Manage services, users, groups, packages, networks, Samba, and logs
- Keep the experience easy for everyday use and powerful for advanced users

## Features
- Dashboard with live metrics (load, RAM, disk, uptime, traffic)
- Linux users and groups: create, delete, passwords, group membership
- SMB: share editor (path, read only, guest, allowed users or `@groups`, write list),
  Samba logins per user, raw `smb.conf` editor
- Every `smb.conf` change is validated with `testparm` (unknown parameters, usually typos, are rejected too), backed up (`smb.conf.bak.<time>`) and smbd is reloaded
- Several panel accounts with roles, login with session cookie, audit log of all changes
- Network overview (interfaces, addresses, gateway, DNS) – read only
- Log viewer for the systemd journal, per service and priority
- Services with running state and autostart, start / stop / restart, package list

Not included yet: changing the network configuration, installing packages from the UI, Docker app management.

## Panel accounts and roles

Panel accounts control who may use the panel. They are separate from Linux and Samba users.

| Role | Can |
|---|---|
| `viewer` | see dashboard, users, groups, shares, network, services, packages |
| `operator` | additionally manage Linux users, groups, shares, Samba logins and services, read logs |
| `admin` | additionally edit raw `smb.conf`, manage panel accounts, read the audit log |

- On first start `CASAOS_ADMIN_USER` and `CASAOS_ADMIN_PASSWORD` create the first admin. Afterwards they are ignored and further accounts are managed under *Panel accounts*.
- Accounts are stored in `$CASAOS_DATA_DIR/accounts.json` (bcrypt hashes, mode 0600), the audit log in `$CASAOS_DATA_DIR/audit.log`.
- Operators cannot add or remove members of privileged groups (`sudo`, `root`, `adm`, `docker`, …) or change Linux users in them; that requires an admin, otherwise an operator could gain root.
- The last admin cannot be deleted or demoted. Role changes and deletions apply to open sessions immediately.
- After 5 failed logins from one IP further attempts are blocked for 15 minutes.
- Forgot the password? `sudo CASAOS_DATA_DIR=/var/lib/casaos-native-panel /opt/casaos-native-panel/casaos-native-panel passwd <name>` sets a new one (and creates an admin with that name if missing). The running panel picks it up without restart.
- Scripts can use HTTP Basic auth with a panel account, e.g. `curl -u admin:pass http://host:8080/api/v1/users`.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CASAOS_ADMIN_USER` / `CASAOS_ADMIN_PASSWORD` | – | Creates the first admin (password min. 8 chars) |
| `CASAOS_AUTH_DISABLED` | – | `true` runs without login. Local testing only. |
| `CASAOS_DATA_DIR` | `/var/lib/casaos-native-panel` | Panel accounts and audit log |
| `CASAOS_MODE` | `system` | `system` or `docker` |
| `CASAOS_HOST` / `CASAOS_PORT` | `0.0.0.0` / `8080` | Listen address. Use `127.0.0.1` behind the Nginx proxy. |
| `CASAOS_WEB_DIR` | `web` | Directory of the static UI |

The panel must run as root in `system` mode (it calls `useradd`, `smbpasswd`, `systemctl`, `journalctl` and writes `/etc/samba/smb.conf`).
System accounts (UID/GID < 1000) are shown read-only and cannot be changed or deleted through the panel.

## Installation (Debian 12)

```bash
# Debian 12 ships Go 1.19, which is too old: install Go >= 1.22 from https://go.dev/dl/
sudo apt install samba git
git clone https://github.com/lukelinux79/casaos-native-panel && cd casaos-native-panel
make build && sudo make install
printf 'CASAOS_ADMIN_USER=admin\nCASAOS_ADMIN_PASSWORD=change-me-please\n' | sudo tee /etc/casaos-native-panel.env
sudo chmod 600 /etc/casaos-native-panel.env
sudo systemctl enable --now casaos-native-panel
```

Then open `http://<server>:8080`. After the first login the two variables can be removed from the env file.
For TLS see [README.proxy.md](README.proxy.md).

## API (v1)

All endpoints except `health` and `auth/login` require a session cookie or Basic auth. The minimum role is in brackets.

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/auth/login` / `logout` | Sign in (`username`, `password`) / out |
| GET | `/api/v1/auth/me` | Current account and role |
| PUT | `/api/v1/auth/password` | Change own password (`current_password`, `new_password`) |
| GET | `/api/v1/dashboard` | Overview, services and metrics (viewer) |
| GET | `/api/v1/network` | Interfaces, gateway, DNS (viewer) |
| GET | `/api/v1/logs?unit=smbd&priority=err&lines=200` | Journal entries (operator) |
| GET/POST | `/api/v1/users` | List (viewer) / create (operator): `username`, `password`, `groups`, `shell`, `samba` |
| DELETE | `/api/v1/users/{name}?remove_home=true` | Delete user and Samba login (operator) |
| PUT | `/api/v1/users/{name}/password` | Set Linux password (operator) |
| GET/POST | `/api/v1/groups` | List (viewer) / create (operator) |
| DELETE | `/api/v1/groups/{name}` | Delete group (operator) |
| POST / DELETE | `/api/v1/groups/{name}/members[/{user}]` | Add / remove member (operator) |
| GET | `/api/v1/samba/shares` | List shares (viewer) |
| PUT / DELETE | `/api/v1/samba/shares/{name}` | Create or update / delete share (operator) |
| GET | `/api/v1/samba/users` | Users with Samba login (viewer) |
| PUT / DELETE | `/api/v1/samba/users/{name}` | Set Samba password / remove Samba login (operator) |
| GET/PUT | `/api/v1/samba/config` | Raw smb.conf (admin) |
| POST | `/api/v1/services/{name}/{start,stop,restart}` | Control a systemd service (operator) |
| GET/POST | `/api/v1/accounts` | List / create panel accounts (admin) |
| PUT / DELETE | `/api/v1/accounts/{name}` | Change `role` or `password` / delete (admin) |
| GET | `/api/v1/audit` | Last 500 audit entries (admin) |

POST and PUT requests must use `Content-Type: application/json` (protection against CSRF).

## High-level architecture

- Frontend: a single static page (`web/index.html`, plain HTML/JS, no build step)
- Backend: Go API service (`internal/api`)
- Runtime abstraction layer (`internal/runtime`): adapter for the native system and a Docker compatibility mode
- `internal/accounts`, `internal/auth`, `internal/audit`: panel accounts, sessions, audit log
- `internal/samba`: smb.conf parser that keeps comments and unknown parameters
- `internal/system`: metrics, network info, safe smb.conf writer
- `internal/validate`: input validation for everything passed to system commands

## Default operating modes
- `system`: native Debian mode, no Docker required
- `docker`: CasaOS-style Docker container management mode

## Development workflow

Requires Go 1.22 or newer.

```bash
# install Go dependencies
make deps

# build backend
make build

# run backend in development mode
sudo CASAOS_DATA_DIR=./data CASAOS_ADMIN_USER=admin CASAOS_ADMIN_PASSWORD='change-me-please' make run

# run tests
make test
```

## License
MIT
