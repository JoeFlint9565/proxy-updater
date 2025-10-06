# Proxy Updater for Kali Linux (proxychains)

**What this project does**
- Downloads a list of SOCKS5 **elite** proxies from ProxyScrape (public API).
- Filters and validates the list, optionally tests reachability for the top N proxies.
- Safely backs up your existing `proxychains` configuration and replaces the `[ProxyList]` section
  with the fresh list of SOCKS5 proxies in `ip port` format (proxychains expects: `socks5 <ip> <port>`).
- Intended to be run periodically (e.g. every 6 hours) via `cron` to keep proxies fresh.

> **Important legal & ethical note:** Proxies can be used for privacy and legitimate pentesting purposes.
> Do **not** use this tool to commit illegal activities, evade law enforcement, or perform unauthorized access.
> Use only in contexts where you have permission to do so (your own tests, authorized pentests, privacy within law).

---

## Files included
- `proxy_updater.py` — main Python script
- `README.md` — this file
- `.gitignore` — common ignores
- `LICENSE` — MIT license
- `proxy_updater_package.zip` — this archive (if you downloaded the ZIP)

---

## Requirements

- **Python 3.8+** (works with Python 3.8, 3.9, 3.10, 3.11)
- `pip` for installing optional dependencies
- For simply fetching and updating proxychains: `requests` is required.
  ```bash
  sudo apt update
  sudo apt install -y python3-pip
  pip3 install --user requests
  ```
- If you want to test proxies (recommended but optional): install socks support:
  ```bash
  pip3 install --user pysocks requests[socks]
  ```

---

## Installation on Kali Linux

1. Copy the project directory to your Kali machine (via GitHub, SCP, USB, etc.).
2. Move into the project folder and ensure the script is executable:
   ```bash
   chmod +x proxy_updater.py
   ```
3. (Optional) Install dependencies system-wide (or use a virtualenv):
   ```bash
   sudo apt install -y python3-pip
   pip3 install requests
   pip3 install pysocks requests[socks]  # optional for testing
   ```

---

## Usage

Run once (will attempt to detect `/etc/proxychains.conf` or `/etc/proxychains4.conf` and update it — **requires sudo**):
```bash
sudo python3 proxy_updater.py
```

Fetch and show proxies without writing to config:
```bash
python3 proxy_updater.py --no-write
```

Fetch and test the top 20 proxies (requires pysocks and requests[socks]):
```bash
sudo python3 proxy_updater.py --test --test-count 20
```

Specify a custom proxychains config file (useful for testing locally):
```bash
python3 proxy_updater.py --target ./test_proxychains.conf
```

---

## Backups & Restore

- Before replacing `/etc/proxychains*.conf`, the script will copy the original into `/etc/proxychains_backups/` with a timestamp.
- To restore a backup manually:
```bash
sudo cp /etc/proxychains_backups/proxychains.conf.backup.YOURTIMESTAMP /etc/proxychains.conf
# OR, if working with proxychains4.conf:
sudo cp /etc/proxychains_backups/proxychains4.conf.backup.YOURTIMESTAMP /etc/proxychains4.conf
```

---

## Automate with cron (every 6 hours)

Edit root's crontab (since we modify /etc/proxychains.conf):
```bash
sudo crontab -e
```
Add a line like this to run every 6 hours at minute 0 (midnight, 6am, 12pm, 6pm):
```
0 */6 * * * /usr/bin/python3 /path/to/project/proxy_updater.py >> /var/log/proxy_updater.log 2>&1
```

- Make sure `/path/to/project/proxy_updater.py` is replaced with the absolute path.
- The cron job runs as root (via sudo crontab), so it can write to `/etc` and create backups. If you prefer running as a non-root user, use `--target` to point to a custom config file.

---

## Uploading to GitHub

1. Initialize git and create a repository locally:
    ```bash
    git init
    git add .
    git commit -m "Initial commit: proxy_updater"
    ```
2. Create a new repository on GitHub (via web UI) and follow the instructions shown there, for example:
    ```bash
    git remote add origin git@github.com:<yourusername>/proxy_updater.git
    git branch -M main
    git push -u origin main
    ```
3. Alternatively use HTTPS remote URL if you don't use SSH keys:
    ```bash
    git remote add origin https://github.com/<yourusername>/proxy_updater.git
    git push -u origin main
    ```

---

## Notes & Troubleshooting

- If the script cannot write `/etc/proxychains.conf`, ensure you run it with `sudo` or as root.
- Proxy providers and public lists change frequently; API endpoints may evolve. If the default `proxyscrape` URL stops working, you can supply another source with `--url`.
- The "elite" anonymity filter is relied on from the provider. The script does basic format checks but does not comprehensively verify anonymity beyond what the source claims.
- If you rely on proxies for sensitive operations, consider running your own proxy/vpn infrastructure or audited commercial services rather than public open proxies (public proxies are often unreliable and may be malicious or logged).

---

## License
This project is distributed under the MIT license. See LICENSE file.
