# CasaOS Native Panel

A simple, debian-first management panel based on CasaOS concepts but designed for native Debian 12 systems with optional Docker support.

## Goals
- Keep a clean and simple admin UI
- Support native Debian 12 x86_64 installation without Docker
- Support Docker mode as an optional compatibility layer
- Manage services, users, groups, packages, networks, Samba, and logs
- Keep the experience easy for everyday use and powerful for advanced users

## Project status
- Native system runtime with dashboard metrics
- User and group management (create, delete, passwords, group membership)
- SMB management: shares (structured editor), Samba logins, raw smb.conf editor
- Every smb.conf change is validated with `testparm`, backed up and smbd is reloaded
- Not yet: multiple panel admins / roles, logs, networks

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CASAOS_ADMIN_USER` / `CASAOS_ADMIN_PASSWORD` | – | Panel login (required, password min. 8 chars) |
| `CASAOS_AUTH_DISABLED` | – | `true` runs without login. Local testing only. |
| `CASAOS_MODE` | `system` | `system` or `docker` |
| `CASAOS_HOST` / `CASAOS_PORT` | `0.0.0.0` / `8080` | Listen address |
| `CASAOS_WEB_DIR` | `web` | Directory of the static UI |

The panel must run as root in `system` mode (it calls `useradd`, `smbpasswd`, `systemctl` and writes `/etc/samba/smb.conf`).
System accounts (UID/GID < 1000) are shown read-only and cannot be changed or deleted through the panel.

## API (v1)

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/dashboard` | Overview, services and metrics |
| GET/POST | `/api/v1/users` | List / create (`username`, `password`, `groups`, `shell`, `samba`) |
| DELETE | `/api/v1/users/{name}?remove_home=true` | Delete user (and Samba login) |
| PUT | `/api/v1/users/{name}/password` | Set Linux password |
| GET/POST | `/api/v1/groups` | List / create group |
| DELETE | `/api/v1/groups/{name}` | Delete group |
| POST / DELETE | `/api/v1/groups/{name}/members[/{user}]` | Add / remove member |
| GET | `/api/v1/samba/shares` | List shares |
| PUT / DELETE | `/api/v1/samba/shares/{name}` | Create or update / delete share |
| GET | `/api/v1/samba/users` | Users with Samba login |
| PUT / DELETE | `/api/v1/samba/users/{name}` | Set Samba password / remove Samba login |
| GET/PUT | `/api/v1/samba/config` | Raw smb.conf |
| POST | `/api/v1/services/{name}/{start,stop,restart}` | Control a systemd service |

POST and PUT requests must use `Content-Type: application/json`.

## High-level architecture

- Frontend: Vue-based UI that exposes a simple management dashboard
- Backend: Go API service
- Runtime abstraction layer: adapter for Docker and native system
- System operations:
  - systemd service control
  - apt package management
  - user/group management
  - Samba config editing
  - log viewing

## Default operating modes
- `system`: native Debian mode, no Docker required
- `docker`: CasaOS-style Docker container management mode

## Repository structure

```text
.
├── README.md
├── Makefile
├── .github/
│   └── workflows/
├── cmd/
│   └── server/
├── internal/
│   ├── api/
│   ├── config/
│   ├── runtime/
│   ├── system/
│   ├── samba/
│   ├── users/
│   └── app/
├── web/
│   └── ui/
├── scripts/
│   ├── install.sh
│   └── install-system.sh
├── docs/
│   └── architecture.md
└── go.mod
```

## Development workflow

Requires Go 1.22 or newer.

```bash
# install Go dependencies
make deps

# build backend
make build

# run backend in development mode
sudo CASAOS_ADMIN_USER=admin CASAOS_ADMIN_PASSWORD='change-me-please' make run

# run tests
make test
```

## License
MIT
