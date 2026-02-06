# Grafana SSRF Scanner

Simple port scanner that exploits grafana ssrf via add datasource to scan internal network. Create datasource → probe proxy → delete.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 grafana_ssrf_scanner.py -u http://grafana:3000 -t 192.168.1.100 -p "80,443,8080"
python3 grafana_ssrf_scanner.py -u http://grafana:3000 -t host.example.com -p "80-1024" -o results.json
```

With token (used for proxy; create/delete use no auth):

```bash
python3 grafana_ssrf_scanner.py -u http://grafana:3000 --token glsa_xxx -t 192.168.1.100 -p 8080
```

## Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Grafana base URL (required) |
| `-t, --target` | Target host to scan (required) |
| `-p, --ports` | Ports: `80,443` or `80-90` or both (required) |
| `--token` | Grafana token (optional; proxy uses it) |
| `-o, --output` | Write results JSON to file |
| `-v, --verbose` | Show response snippet for open ports |

## How it works

If the Grafana does not require authentication, then you should create a service token. Second step can't be done without authentication =/

1. Create a datasource without authentication.
2. Call proxy `/api/datasources/proxy/{id}/api/v1/query` with token.
3. Treat HTTP 200 as open, else closed/filtered.
4. Delete the datasource (same no-auth session).
5. Repeat per port. Names use a run id to avoid collisions with stale datasources.
