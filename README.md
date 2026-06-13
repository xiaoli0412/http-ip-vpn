# HTTP IP VPN

A lightweight HTTP proxy server with IP whitelist, admin dashboard, traffic monitoring, and full management panel — deployable via Docker.

## Features

- **HTTP/HTTPS Proxy** — Forward proxy supporting HTTP and CONNECT tunneling
- **IP Whitelist** — Dynamic IP allowlist managed via admin panel or API
- **Admin Dashboard** — Real-time traffic overview with charts (line, bar, trend)
- **Traffic Statistics** — Per-IP and per-host breakdown, recent activity log
- **Blocked Access Log** — Records all unauthorized connection attempts
- **System Logs** — Activity logging with auto-clear support
- **Multi-language UI** — Chinese and English interface
- **Dark/Light Theme** — Toggleable theme with persistent preference
- **Credential Management** — Change admin username/password from settings panel

## Quick Start

### Prerequisites

- Docker & Docker Compose

### Deploy

```bash
# Clone or download, then:
docker compose up -d --build
```

### Configure

1. Open admin panel: `http://your-server:9090`
2. Login with default credentials: `admin` / `admin`
3. Go to **IP Whitelist** → Add your home IP address
4. Set your device's HTTP proxy to `your-server:8088`

## Usage

### Proxy

Set your browser or device HTTP proxy to:

```
Server: your-server-ip
Port: 8088
Protocol: HTTP
```

Only whitelisted IPs can use the proxy. Unauthorized requests return 403 and are logged.

### Admin Panel

```
http://your-server:9090
```

| Section | Description |
|---------|-------------|
| Dashboard | Real-time stats, request/bandwidth charts, 7-day trend, top targets |
| IP Whitelist | Add/remove allowed client IPs |
| Statistics | Per-IP and per-host traffic breakdown, recent requests |
| Logs | System activity with filtering and auto-clear |
| Blocked | Unauthorized access attempts |
| Settings | Change credentials, theme, language |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_PORT` | `8088` | Proxy server port |
| `ADMIN_PORT` | `9090` | Admin panel port |
| `ADMIN_USER` | `admin` | Admin panel username |
| `ADMIN_PASS` | `admin` | Admin panel password |
| `TIMEOUT_SECONDS` | `300` | Proxy connection timeout |

## Deployment

### Deploy to Remote Server

The included `deploy.py` script uses paramiko to upload and deploy:

```bash
# Edit deploy.py with your server details, then:
python deploy.py
```

### Manual Deployment

```bash
# Copy files to server, then:
docker compose up -d --build
```

## API Endpoints

All admin API endpoints require Basic Auth.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/config` | Get admin config |
| PUT | `/api/config/credentials` | Update credentials |
| PUT | `/api/config/autoclear` | Update auto-clear settings |
| GET | `/api/whitelist` | List whitelisted IPs |
| POST | `/api/whitelist` | Add IP to whitelist |
| DELETE | `/api/whitelist/:ip` | Remove IP from whitelist |
| GET | `/api/stats/summary` | Get summary statistics |
| GET | `/api/stats/byip` | Per-IP statistics |
| GET | `/api/stats/byhost` | Per-host statistics |
| GET | `/api/stats/history` | Recent request history |
| GET | `/api/stats/timeline` | Aggregated timeline for charts |
| POST | `/api/stats/reset` | Reset all statistics |
| GET | `/api/unauthorized` | Get blocked access records |
| DELETE | `/api/unauthorized` | Clear blocked records |
| GET | `/api/logs` | Get system logs |
| DELETE | `/api/logs` | Clear system logs |

## Project Structure

```
├── proxy-server.js      # Backend server (proxy + admin API)
├── public/index.html    # Admin panel frontend
├── Dockerfile           # Docker image
├── docker-compose.yml   # Docker Compose config
├── package.json         # Node.js dependencies
├── deploy.py            # Remote deployment script
├── .gitignore
├── .dockerignore
└── data/                # Runtime data (excluded from git)
    ├── config.json      # Admin credentials & settings
    ├── whitelist.json   # IP whitelist
    ├── stats.json       # Traffic statistics
    ├── logs.json        # System logs
    └── unauthorized.json # Blocked access records
```

## License

MIT
