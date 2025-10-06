#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
proxy_updater.py — Aggregating SOCKS5 updater for proxychains (Kali-friendly)

Single-file, copy-paste-ready script.

Features:
- Fetches SOCKS5 proxy lists from multiple public sources (text, JSON, HTML).
- Parses, validates and deduplicates IP:PORT entries.
- Optional reachability testing for top N proxies (requires requests + pysocks).
- Backs up existing /etc/proxychains*.conf and replaces the [ProxyList] section with
  "socks5 <ip> <port>" lines (respects proxychains format).
- CLI: --url, --test, --test-count, --no-write, --target, --max
- Designed to be used responsibly. Public proxies may be unreliable or malicious.

Usage examples:
  python3 proxy_updater.py                 # fetch & write (needs sudo to write /etc)
  python3 proxy_updater.py --no-write      # fetch & print top results only
  python3 proxy_updater.py --test --test-count 30
  python3 proxy_updater.py --target ./test_proxychains.conf

Note: install dependencies in Kali either via venv or apt:
  python3 -m venv .venv
  source .venv/bin/activate
  pip install requests pysocks
or
  sudo apt install python3-requests python3-pysocks
"""

from __future__ import annotations
import argparse
import shutil
import sys
import re
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Set, Tuple, Optional

# Try to import requests; provide helpful error if missing when network operations required.
try:
    import requests
except Exception:  # pragma: no cover - runtime environment may not have requests
    requests = None

# --- Configuration ---
SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",  # plain ip:port per line
    "https://api.proxyscan.io/api/proxy?type=socks5&format=json&limit=500",      # JSON
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=1000&country=all&ssl=all&anonymity=elite",  # legacy text
    "https://www.socks-proxy.net/",  # HTML table with proxies
]

PROXYCHAINS_CANDIDATES = [Path("/etc/proxychains.conf"), Path("/etc/proxychains4.conf")]
BACKUP_DIR = Path("/etc/proxychains_backups")
REQUEST_TIMEOUT = 12  # seconds for fetching
DEFAULT_TEST_COUNT = 20
MAX_WRITE = 500  # safety cap on number of proxies written

IP_PORT_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3}):(?:\d{1,5})")
IP_ONLY_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")
PORT_RE = re.compile(r":(\d{1,5})$")


def now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def fetch_text(url: str, timeout: int = REQUEST_TIMEOUT) -> str:
    if requests is None:
        raise RuntimeError("requests library is required to fetch URLs. Install it in a venv or system package.")
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def parse_plain_text_for_ipports(text: str) -> List[str]:
    """
    Find strings like 1.2.3.4:1080 in a plain text blob. Returns unique list in order found.
    """
    seen = []
    for match in IP_PORT_RE.finditer(text):
        ipport = match.group(0)
        # basic port validation
        mport = PORT_RE.search(ipport)
        if not mport:
            continue
        port = int(mport.group(1))
        if 1 <= port <= 65535:
            if ipport not in seen:
                seen.append(ipport)
    return seen


def parse_proxyscan_json(text: str) -> List[str]:
    """
    proxyscan returns list of objects with ip and port fields.
    """
    try:
        data = json.loads(text)
    except Exception:
        return []
    out = []
    if isinstance(data, list):
        for item in data:
            try:
                ip = item.get("ip") or item.get("Ip") or item.get("host")
                port = item.get("port") or item.get("Port")
                if ip and port:
                    s = f"{ip}:{int(port)}"
                    out.append(s)
            except Exception:
                continue
    return out


def parse_socks_proxy_net_html(html: str) -> List[str]:
    """
    socks-proxy.net provides an HTML table. We extract IP and Port pairs by searching for the table rows.
    This is a best-effort simple parser (no beautifulsoup dependency).
    """
    out = []
    # look for patterns like <td>1.2.3.4</td><td>1080</td>
    # remove newlines to simplify
    compact = html.replace("\n", " ")
    # find all ip occurrences then capture nearby port
    for ip_match in IP_ONLY_RE.finditer(compact):
        ip = ip_match.group(0)
        # search ahead for a nearby port within 200 characters
        tail = compact[ip_match.end(): ip_match.end() + 200]
        port_match = re.search(r"<td[^>]*>\s*(\d{2,5})\s*</td>", tail)
        if port_match:
            port = port_match.group(1)
            candidate = f"{ip}:{port}"
            if IP_PORT_RE.fullmatch(candidate):
                out.append(candidate)
    # deduplicate preserving order
    dedup = []
    for p in out:
        if p not in dedup:
            dedup.append(p)
    return dedup


def aggregate_from_sources(sources: List[str]) -> List[str]:
    """
    Fetch each source and extract ip:port entries. Returns deduplicated list preserving first-seen priority.
    """
    results: List[str] = []
    seen: Set[str] = set()
    for url in sources:
        try:
            text = fetch_text(url)
        except Exception as e:
            # skip failing sources but log to stdout
            print(f"[{now_iso()}] Warning: failed to fetch {url}: {e}")
            continue

        # choose parser heuristically
        lower = url.lower()
        found: List[str] = []
        # JSON API from proxyscan
        if "proxyscan.io" in lower:
            found = parse_proxyscan_json(text)
        elif "socks-proxy.net" in lower:
            found = parse_socks_proxy_net_html(text)
        else:
            # fallback: plain text extraction (works for many raw lists)
            found = parse_plain_text_for_ipports(text)

        # append deduped
        for p in found:
            if p not in seen:
                seen.add(p)
                results.append(p)

        print(f"[{now_iso()}] Source {url} -> found {len(found)} proxies (total aggregated: {len(results)})")

    return results


def basic_validate_ip_port(ipport: str) -> bool:
    if not IP_PORT_RE.fullmatch(ipport):
        return False
    try:
        ip, port_s = ipport.split(":", 1)
        octs = ip.split(".")
        if len(octs) != 4:
            return False
        for o in octs:
            oi = int(o)
            if oi < 0 or oi > 255:
                return False
        port = int(port_s)
        if port < 1 or port > 65535:
            return False
    except Exception:
        return False
    return True


def test_proxy_socks5(proxy: str, timeout: float = 8.0) -> bool:
    """
    Tests a SOCKS5 proxy by performing a GET to https://httpbin.org/ip through the proxy.
    Requires requests and pysocks installed.
    """
    if requests is None:
        print("requests not installed; skipping proxy tests.")
        return False
    try:
        # ensure PySocks is importable by requests' socks support
        import socks  # type: ignore
    except Exception:
        print("pysocks (or socks) not installed; install pysocks and requests[socks] to enable proxy testing.")
        return False

    proxies = {
        "http": f"socks5://{proxy}",
        "https": f"socks5://{proxy}",
    }
    try:
        resp = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout)
        if resp.status_code == 200:
            return True
    except Exception:
        return False
    return False


def find_proxychains_path() -> Path:
    """Return the first existing proxychains path or default to /etc/proxychains4.conf"""
    for p in PROXYCHAINS_CANDIDATES:
        if p.exists():
            return p
    # default to proxychains4.conf (common on modern systems)
    return PROXYCHAINS_CANDIDATES[-1]


def backup_file(path: Path) -> Path:
    """Create backup copy in BACKUP_DIR and return backup path"""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = BACKUP_DIR / f"{path.name}.backup.{ts}"
    shutil.copy2(path, dest)
    return dest


def replace_proxylist_section(original: str, proxies: List[str]) -> str:
    """
    Replace or append the [ProxyList] section in a proxychains config file.
    Returns new content as string.
    """
    header = "[ProxyList]"
    lower = original.lower()
    idx = lower.find(header.lower())
    if idx == -1:
        # append header
        new = original.rstrip() + "\n\n[ProxyList]\n"
    else:
        # keep everything up to the header
        start = idx
        # find newline after header in original to maintain formatting
        # We will keep everything up to the header start and then rewrite from header onwards
        new = original[:start]
        new += "[ProxyList]\n"
    # add proxies as "socks5 <ip> <port>"
    count = 0
    for p in proxies:
        if not basic_validate_ip_port(p):
            continue
        ip, port = p.split(":", 1)
        new += f"socks5 {ip} {port}\n"
        count += 1
        if count >= MAX_WRITE:
            break
    return new


def update_proxychains_file(path: Path, proxies: List[str]) -> Tuple[bool, str]:
    """
    Safely update the proxychains file at 'path' with the provided proxies.
    Returns (success, message).
    """
    if not proxies:
        return False, "No proxies provided to write."

    # read existing content or create minimal template
    if path.exists():
        try:
            orig = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return False, f"Failed reading {path}: {e}"
    else:
        orig = ("# proxychains config generated by proxy_updater.py\n\n"
                "strict_chain\nproxy_dns\nremote_dns_subnet 224\n\n[ProxyList]\n")

    # backup
    if path.exists():
        try:
            b = backup_file(path)
            print(f"[{now_iso()}] Backed up {path} -> {b}")
        except Exception as e:
            return False, f"Failed to backup {path}: {e}"

    new_content = replace_proxylist_section(orig, proxies)
    try:
        path.write_text(new_content, encoding="utf-8")
    except PermissionError:
        return False, f"Permission denied writing {path} — run with sudo."
    except Exception as e:
        return False, f"Failed to write {path}: {e}"

    return True, f"Wrote {min(len(proxies), MAX_WRITE)} proxies to {path}"


def cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Aggregate and update SOCKS5 proxies into proxychains config")
    p.add_argument("--url", help="Single source URL (overrides built-in SOURCES)", default=None)
    p.add_argument("--test", action="store_true", help="Test top N proxies for reachability (requires pysocks)")
    p.add_argument("--test-count", type=int, default=DEFAULT_TEST_COUNT, help="How many proxies to test when --test used")
    p.add_argument("--no-write", action="store_true", help="Fetch and display proxies but do not modify proxychains file")
    p.add_argument("--target", type=str, default=None, help="Path to proxychains config file to update (optional)")
    p.add_argument("--max", type=int, default=MAX_WRITE, help="Maximum proxies to write into proxychains config")
    return p.parse_args()


def main() -> int:
    args = cli()
    sources = [args.url] if args.url else SOURCES

    print(f"[{now_iso()}] Starting proxy aggregation from {len(sources)} source(s).")

    try:
        proxies = aggregate_from_sources(sources)
    except RuntimeError as e:
        print(f"Error: {e}")
        return 2

    # basic filter/validate
    proxies = [p for p in proxies if basic_validate_ip_port(p)]
    print(f"[{now_iso()}] Aggregated {len(proxies)} valid SOCKS5 proxies (pre-test).")

    # optionally test top N proxies
    tested: List[str] = []
    if args.test and proxies:
        n = min(args.test_count, len(proxies))
        print(f"[{now_iso()}] Testing first {n} proxies for reachability (this may take a while)...")
        for p in proxies[:n]:
            ok = test_proxy_socks5(p, timeout=8.0)
            print(f"  {p} -> {'OK' if ok else 'FAIL'}")
            if ok:
                tested.append(p)
        # prioritize tested working proxies
        if tested:
            proxies = tested + [p for p in proxies if p not in tested]
        print(f"[{now_iso()}] After testing, {len(tested)} proxies confirmed working.")

    # Deduplicate & cap
    seen = set()
    final = []
    for p in proxies:
        if p not in seen:
            seen.add(p)
            final.append(p)
        if len(final) >= args.max:
            break

    print(f"[{now_iso()}] Final proxy list size (to use): {len(final)}")

    if args.no_write:
        print("No-write mode: showing top proxies:")
        for p in final[:100]:
            print(p)
        print("Done.")
        return 0

    # determine target proxychains file
    if args.target:
        target = Path(args.target)
    else:
        target = find_proxychains_path()

    print(f"[{now_iso()}] Updating proxychains config at: {target}")
    ok, msg = update_proxychains_file(target, final)
    if not ok:
        print("Error:", msg)
        return 3
    print(msg)
    print(f"[{now_iso()}] Completed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted by user.")
        raise SystemExit(1)
