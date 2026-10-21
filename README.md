# asm-recon

Attack-surface recon pipeline in a single container. Feed it IPs and domains;
it enumerates subdomains, probes every host over HTTP, and fingerprints PHP
(with version where exposed).

```
assets (IP / CIDR / domain)
        │
        ├─ 1. subdomain discovery   findomain (+ optional subfinder, assetfinder, amass, crt.sh, dns-brute)
        ├─ 2. fast HTTP probe        httpx  (concurrent, JSON output, optional naabu port scan first)
        └─ 3. PHP fingerprint        header / cookie / CMS indicators + version extraction
        │
        ▼
   table on stdout  +  <prefix>.csv  +  <prefix>.json
```

> **Authorised use only.** Run this against assets you own or have explicit
> written permission to test. Subdomain enumeration and HTTP probing are active
> against third-party infrastructure.

## Requirements

Just **Docker**. All recon tools (findomain, httpx, naabu, subfinder,
assetfinder) are baked into the image. The host installs nothing else.

## Quick start

The first `./run.sh` builds the image automatically (one time), then runs.
You need nothing on the host but Docker.

```bash
# 1. Scan a single domain — just pass it, no flags needed. Discovery runs
#    findomain + subfinder + assetfinder + crt.sh + DNS brute-force by default.
./run.sh example.com

# 2. Quieter, passive-only run (skip the active DNS brute-force):
./run.sh example.com --no-dns-brute

# 3. Go deeper on PHP: extra /index.php probe for hosts showing no signal.
./run.sh example.com --php-deep

# 4. Scan a list. Edit ./assets.txt on the host — it is mounted live, so your
#    latest edits are used on the next run with no rebuild.
printf 'example.com\n93.184.216.34\n10.0.0.0/28\n' > assets.txt
./run.sh -a assets.txt --all-sources

# 5. Stuck? Add -D for verbose diagnostics (resolved paths, every command, timings).
./run.sh -D example.com
```

PHP hosts are highlighted in **red** in the table, and the results are written
to `./data/asm_<UTC-timestamp>.csv` and `.json` on your host.

### Other ways to run

```bash
# Raw Docker
docker build -t asm-recon:latest .
mkdir -p data
docker run --rm -v "$PWD/data:/data" asm-recon:latest example.com --crtsh

# docker compose
docker compose run --rm asm-recon example.com --all-sources
```

### How the mounts work

`run.sh` wires two live bind-mounts (host edits reflected immediately, no rebuild):

| host path | container path | purpose |
|-----------|----------------|---------|
| `./data` | `/data` (also the working dir) | input files **and** output CSV/JSON |
| `./assets.txt` | `/data/assets.txt` | a single, directly-editable input file — read it with `-a assets.txt` |

So the fast path is: **edit `./assets.txt`, run `./run.sh -a assets.txt`.** For
other input files, drop them in `./data` and reference them as `/data/<name>`.
Point the convenience mount at a different file with
`ASSETS_FILE=/path/to/list.txt ./run.sh -a assets.txt`.

## Inputs

| flag | meaning |
|------|---------|
| *(positional)*  | asset(s) passed directly, e.g. `./run.sh example.com 1.2.3.4` |
| `-t, --target`  | inline asset (domain or IP), repeatable |
| `-a, --assets`  | file of mixed assets (IP / CIDR / domain), one per line, repeatable |
| `-d, --domains` | file of domains only |
| `-i, --ips`     | file of IPs / CIDRs only |

Tokens are auto-classified, comments (`#`) and junk are ignored, and URLs are
reduced to their host.

## Discovery options (step 1)

**findomain, subfinder, assetfinder, crt.sh and dns-brute all run by default.**
Each default source can be turned off individually with its `--no-…` form.

| flag | source | default |
|------|--------|---------|
| `--subfinder` / `--no-subfinder`     | ProjectDiscovery subfinder | **on** |
| `--assetfinder` / `--no-assetfinder` | tomnomnom assetfinder | **on** |
| `--crtsh` / `--no-crtsh`             | crt.sh certificate transparency (no tool needed) | **on** |
| `--dns-brute` / `--no-dns-brute`     | **active** DNS brute-force of a wordlist — finds hosts passive sources miss (wildcard-aware, no tool needed) | **on** |
| `--amass`        | OWASP amass (passive) — only if built in, see below | off |
| `--wordlist F`   | custom wordlist for dns-brute (one label per line; built-in list otherwise) | — |
| `--dns-timeout N`| per-name DNS timeout for dns-brute | 3s |
| `--all-sources`  | also enable amass on top of the defaults | off |
| `--no-discovery` | skip enumeration entirely, probe assets as given | off |
| `--findomain-args ...` | pass extra flags straight to findomain (put last) | — |

findomain always runs and cannot be disabled. amass stays off because it isn't
in the image unless you build with `INSTALL_AMASS=true`, and it's slow.

To run only the quiet passive sources (no active DNS brute-force):

```bash
./run.sh example.com --no-dns-brute
```

> **Passive vs. active.** findomain, subfinder, assetfinder, amass and crt.sh are
> *passive* — they only surface names published in Certificate Transparency logs
> or OSINT datasets. A host that resolves in DNS but was never logged there is
> invisible to them; `--dns-brute` is what actually catches those.

Some passive sources (subfinder, amass) give far better results with API keys.
Mount a config into the container, e.g.:

```bash
docker run --rm -v "$PWD/data:/data" \
  -v "$HOME/.config/subfinder:/home/recon/.config/subfinder:ro" \
  asm-recon:latest -d /data/domains.txt --subfinder
```

## Scan / probe options (step 2)

| flag | meaning | default |
|------|---------|---------|
| `--ports`            | ports for httpx | `80,443,8080,8443,8000,8888` |
| `--naabu`            | fast port scan with naabu first, feed open ports to httpx | off |
| `--top-ports N`      | naabu top-N ports | — |
| `--threads N`        | httpx concurrency | 50 |
| `--rate-limit N`     | cap requests/sec | — |
| `--http-timeout N`   | per-request timeout (s) | 10 |
| `--follow-redirects` | follow redirects in httpx | off |
| `--httpx-args ...`   | pass extra flags straight to httpx (put last) | — |

CIDRs up to /20 (4096 hosts) are expanded automatically; larger ranges should
go through `--naabu`.

## PHP detection (step 3)

A host is flagged PHP when **any** indicator fires, and the version is pulled
from whichever exposes it. All of these are passive — read from the single
httpx response, no extra requests:

1. **`X-Powered-By`** header contains PHP (most direct, often carries version)
2. **`Server`** header mentions PHP (e.g. `Apache/2.4.52 PHP/7.4.3`)
3. **Session / framework cookies** in `Set-Cookie` — `PHPSESSID`, plus Laravel,
   CodeIgniter, CakePHP, Symfony, phpBB, Moodle, PrestaShop, FuelPHP, Xdebug
4. **Wappalyzer** tech-detect from httpx reports PHP
5. **`.php`** in the final URL, `Location`, or `Content-Location`
6. **PHP-based CMS fingerprints** in headers — WordPress (`X-Pingback`,
   `Link: …/wp-json`, `X-Redirect-By`), Drupal (`X-Drupal-*`, `X-Generator`),
   and Joomla / TYPO3 / Magento / Shopware / Bitrix / Concrete / SilverStripe

The table shows *which* indicators fired (e.g. `cookie:Laravel`, `CMS:WordPress`),
and PHP rows are highlighted in red (disable with `--no-color` or `NO_COLOR=1`).

`--php-deep` adds one extra `GET /index.php` request *only* for hosts that
showed no signal, to catch servers that hide PHP until a `.php` path is hit.

`--php-only` keeps only PHP hosts in the output.

## Output

A table prints to stdout (PHP hosts first). Two files are written to the output
prefix (default `/data/asm_<UTC-timestamp>`):

* `*.json` — full records (host, url, ip, status, server, title, tech, php, version, indicators)
* `*.csv`  — same, flat, for spreadsheets/BI

## Building with amass included

amass is large and slow to compile, so it's off by default:

```bash
docker build --build-arg INSTALL_AMASS=true -t asm-recon:latest .
# then --amass / --all-sources will use it
```

## naabu SYN scanning

The default CONNECT scan needs no privileges. For raw-socket SYN scans add
capabilities:

```bash
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v "$PWD/data:/data" asm-recon:latest -t example.com --naabu --top-ports 1000
```

## Pinning tool versions

Override any version at build time:

```bash
docker build \
  --build-arg HTTPX_VERSION=v1.6.10 \
  --build-arg FINDOMAIN_VERSION=10.0.1 \
  -t asm-recon:latest .
```
