#!/usr/bin/env python3
"""
asm_recon.py — Attack-surface recon pipeline.

Pipeline:
  1. Load base assets (IPs, CIDRs, domains, hostnames) from files and/or CLI.
  2. Enumerate subdomains for each domain with findomain (plus optional extra sources).
  3. Probe every candidate host with httpx (fast, concurrent HTTP prober).
  4. Flag PHP using multiple independent indicators and extract the version when exposed.
  5. Emit a table to stdout, plus CSV and JSON files.

Required on PATH:   findomain, httpx   (ProjectDiscovery httpx, NOT python-httpx)
Optional on PATH:   subfinder, assetfinder, amass, naabu
                    (crt.sh source needs no tool — it uses plain HTTPS)

Only run this against assets you own or are explicitly authorised to test.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# --------------------------------------------------------------------------- #
# Debug / diagnostics
# --------------------------------------------------------------------------- #

DEBUG = False


def dbg(msg):
    """Write a debug line to stderr, but only when --debug is active."""
    if DEBUG:
        sys.stderr.write(f"[D] {msg}\n")


# --------------------------------------------------------------------------- #
# Asset classification
# --------------------------------------------------------------------------- #

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$")


def classify(token):
    """Return 'ip', 'cidr', 'domain', or None for a raw token."""
    token = token.strip().strip(",")
    if not token or token.startswith("#"):
        return None, token
    # strip scheme / path if someone pasted a URL
    token = re.sub(r"^[a-zA-Z]+://", "", token).split("/")[0].split(":")[0]
    if not token:
        return None, token
    try:
        ipaddress.ip_address(token)
        return "ip", token
    except ValueError:
        pass
    try:
        ipaddress.ip_network(token, strict=False)
        if "/" in token:
            return "cidr", token
    except ValueError:
        pass
    if DOMAIN_RE.match(token):
        return "domain", token.lower()
    return None, token


def load_tokens(paths, inline):
    raw = list(inline or [])
    if inline:
        dbg(f"load_tokens: {len(inline)} inline target(s): {', '.join(inline)}")
    for p in paths or []:
        abspath = os.path.abspath(p)
        dbg(f"load_tokens: opening {p!r} -> {abspath} (cwd={os.getcwd()})")
        if not os.path.exists(p):
            # A missing input file is the single most common failure here,
            # usually because the path isn't visible inside the container.
            listing = ""
            parent = os.path.dirname(abspath) or "."
            try:
                listing = ", ".join(sorted(os.listdir(parent))[:20]) or "(empty)"
            except OSError as e:
                listing = f"(could not list {parent}: {e})"
            sys.exit(
                f"[x] Input file not found: {p!r}\n"
                f"    Resolved to: {abspath}\n"
                f"    Working dir: {os.getcwd()}\n"
                f"    In {parent}: {listing}\n"
                f"    Hint: run.sh only mounts ./data into the container as /data,\n"
                f"          so put the file in ./data and pass it as /data/<name>."
            )
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
        dbg(f"load_tokens: read {len(lines)} line(s) from {abspath}")
        raw.extend(lines)
    domains, ips, cidrs, skipped = set(), set(), set(), []
    for line in raw:
        for tok in re.split(r"[\s,]+", line.strip()):
            kind, val = classify(tok)
            if kind == "domain":
                domains.add(val)
            elif kind == "ip":
                ips.add(val)
            elif kind == "cidr":
                cidrs.add(val)
            elif val:
                skipped.append(val)
    dbg(f"load_tokens: classified {len(domains)} domains, {len(ips)} IPs, "
        f"{len(cidrs)} CIDRs, {len(skipped)} skipped")
    return domains, ips, cidrs, skipped


# --------------------------------------------------------------------------- #
# Subdomain / asset discovery
# --------------------------------------------------------------------------- #

def have(tool):
    path = shutil.which(tool)
    dbg(f"have({tool}) -> {path or 'NOT FOUND'}")
    return path is not None


def run(cmd, timeout=None, stdin_data=None):
    """Run a command, return (rc, stdout_text). Never raises on tool errors."""
    dbg(f"run: {' '.join(cmd)}" + (f"  (timeout={timeout}s)" if timeout else "")
        + (f"  [{stdin_data.count(chr(10))} stdin lines]" if stdin_data else ""))
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        dbg(f"run: rc={proc.returncode} in {elapsed:.1f}s, "
            f"{len(proc.stdout)} stdout bytes, {len(proc.stderr)} stderr bytes")
        if DEBUG and proc.returncode != 0 and proc.stderr:
            dbg(f"run: stderr tail: {proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ''}")
        return proc.returncode, proc.stdout
    except FileNotFoundError:
        dbg(f"run: command not found: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired as e:
        dbg(f"run: TIMEOUT after {timeout}s: {cmd[0]}")
        return 124, (e.stdout or "")


def findomain_subs(domain, extra_args, timeout):
    """findomain -t <domain> -q  -> subdomains on stdout (one per line)."""
    cmd = ["findomain", "-t", domain, "-q"] + list(extra_args or [])
    rc, out = run(cmd, timeout=timeout)
    subs = {l.strip().lower() for l in out.splitlines() if l.strip()}
    return subs


def subfinder_subs(domain, timeout):
    rc, out = run(["subfinder", "-d", domain, "-silent"], timeout=timeout)
    return {l.strip().lower() for l in out.splitlines() if l.strip()}


def assetfinder_subs(domain, timeout):
    rc, out = run(["assetfinder", "--subs-only", domain], timeout=timeout)
    return {l.strip().lower() for l in out.splitlines() if l.strip()}


def amass_subs(domain, timeout):
    rc, out = run(["amass", "enum", "-passive", "-d", domain, "-silent"], timeout=timeout)
    return {l.strip().lower() for l in out.splitlines() if l.strip()}


def crtsh_subs(domain, timeout):
    """Query crt.sh certificate transparency JSON — no external tool needed."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    found = set()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "asm-recon"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
        for row in data:
            for name in str(row.get("name_value", "")).splitlines():
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and DOMAIN_RE.match(name):
                    found.add(name)
    except Exception as e:
        sys.stderr.write(f"[!] crt.sh lookup failed for {domain}: {e}\n")
    return found


# --------------------------------------------------------------------------- #
# Active DNS enumeration (brute-force + resolve)
#
# Passive sources (findomain, subfinder, crt.sh, ...) only surface names that
# were published in Certificate Transparency logs or OSINT datasets. A host
# that resolves in DNS but was never CT-logged (e.g. ai.baldur.dk) is invisible
# to them. This source validates candidate labels against DNS directly, so such
# hosts are actually discovered.
# --------------------------------------------------------------------------- #

# Small, high-signal default wordlist. Override with --wordlist for more.
DEFAULT_WORDLIST = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "mx", "ns1", "ns2", "ns",
    "remote", "vpn", "portal", "gateway", "gw", "proxy", "api", "api2", "app",
    "apps", "ai", "m", "mobile", "admin", "dashboard", "panel", "cpanel",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "uat",
    "demo", "beta", "preview", "sandbox", "internal", "intranet", "corp",
    "git", "gitlab", "github", "ci", "cd", "jenkins", "build", "registry",
    "docs", "doc", "wiki", "support", "help", "helpdesk", "status", "kb",
    "blog", "news", "shop", "store", "cart", "pay", "payments", "checkout",
    "cdn", "static", "assets", "img", "images", "media", "files", "download",
    "auth", "login", "sso", "accounts", "id", "oauth", "idp", "secure",
    "db", "sql", "mysql", "postgres", "redis", "cache", "mongo", "es", "search",
    "grafana", "kibana", "prometheus", "monitor", "monitoring", "metrics",
    "log", "logs", "cloud", "k8s", "kube", "kubernetes", "docker", "node",
    "server", "host", "vps", "web", "web2", "ftp", "sftp", "ssh", "backup",
]


def _resolve_host(host):
    """Return the set of IPs host resolves to (A/AAAA), or empty set."""
    try:
        infos = socket.getaddrinfo(host, None)
        return {info[4][0] for info in infos}
    except (socket.gaierror, UnicodeError):
        return set()
    except Exception:
        return set()


def _detect_wildcard(domain):
    """Resolve two random labels; return the set of wildcard IPs if any."""
    import random
    import string
    wildcard_ips = set()
    for _ in range(2):
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        wildcard_ips |= _resolve_host(f"{rand}.{domain}")
    return wildcard_ips


def dns_brute_subs(domain, words, threads, timeout):
    """Resolve <word>.<domain> for every word; return the ones that exist.

    Wildcard DNS is handled by resolving random labels first and dropping any
    candidate whose IPs are only the wildcard IPs.
    """
    # NB: getaddrinfo's respect for this timeout is OS-dependent; it is a
    # best-effort bound. Concurrency is what keeps the whole pass fast.
    prev_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        wildcard_ips = _detect_wildcard(domain)
        if wildcard_ips:
            dbg(f"dns-brute {domain}: wildcard DNS detected ({', '.join(sorted(wildcard_ips))}); "
                f"filtering candidates that only match it")

        candidates = {f"{w.strip().lower()}.{domain}" for w in words if w.strip()
                      and not w.strip().startswith("#")}
        dbg(f"dns-brute {domain}: resolving {len(candidates)} candidate labels "
            f"with {threads} threads (timeout {timeout}s)")

        found = set()
        with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            futs = {ex.submit(_resolve_host, host): host for host in candidates}
            for fut in as_completed(futs):
                host = futs[fut]
                ips = fut.result()
                if not ips:
                    continue
                # Skip hosts that resolve ONLY to the wildcard address(es).
                if wildcard_ips and ips <= wildcard_ips:
                    dbg(f"dns-brute {domain}: {host} -> wildcard, skipping")
                    continue
                found.add(host)
                dbg(f"dns-brute {domain}: {host} -> {', '.join(sorted(ips))}")
    finally:
        socket.setdefaulttimeout(prev_timeout)
    return found


def load_wordlist(path):
    """Read a wordlist file, one label per line; fall back to the built-in."""
    if not path:
        return DEFAULT_WORDLIST
    abspath = os.path.abspath(path)
    dbg(f"load_wordlist: {path!r} -> {abspath}")
    if not os.path.exists(path):
        sys.exit(f"[x] Wordlist not found: {path!r} (resolved to {abspath}). "
                 f"Remember run.sh only mounts ./data as /data.")
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        words = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    dbg(f"load_wordlist: {len(words)} labels from {abspath}")
    return words


def discover(domains, args):
    """Run all enabled discovery sources over each domain, return the union set."""
    all_hosts = set(domains)  # always keep the seed domains themselves
    sources = [("findomain", lambda d: findomain_subs(d, args.findomain_args, args.disc_timeout))]
    if args.subfinder:
        sources.append(("subfinder", lambda d: subfinder_subs(d, args.disc_timeout)))
    if args.assetfinder:
        sources.append(("assetfinder", lambda d: assetfinder_subs(d, args.disc_timeout)))
    if args.amass:
        sources.append(("amass", lambda d: amass_subs(d, args.disc_timeout)))
    if args.crtsh:
        sources.append(("crt.sh", lambda d: crtsh_subs(d, args.disc_timeout)))
    if args.dns_brute:
        words = load_wordlist(args.wordlist)
        sources.append(("dns-brute", lambda d: dns_brute_subs(
            d, words, args.threads, args.dns_timeout)))

    dbg(f"discover: {len(domains)} seed domain(s), sources enabled: "
        f"{', '.join(n for n, _ in sources)}")
    # Sources that need no external binary on PATH.
    NO_TOOL = {"crt.sh", "dns-brute"}
    for name, fn in sources:
        tool = name.split()[0].replace(".sh", "")
        if name in NO_TOOL:
            pass
        elif not have(tool):
            sys.stderr.write(f"[!] {tool} not found on PATH — skipping that source.\n")
            continue
        for d in sorted(domains):
            try:
                hits = fn(d)
            except Exception as e:
                sys.stderr.write(f"[!] {name} error on {d}: {e}\n")
                hits = set()
            new = hits - all_hosts
            all_hosts |= hits
            sys.stderr.write(f"[*] {name:<11} {d}: +{len(new)} new ({len(hits)} total)\n")
    return all_hosts


# --------------------------------------------------------------------------- #
# Optional fast port scan (naabu) to feed httpx open ports
# --------------------------------------------------------------------------- #

def naabu_scan(targets, ports, top_ports, timeout):
    """Return a set of 'host:port' strings for open ports, via naabu."""
    if not have("naabu"):
        sys.stderr.write("[!] naabu not found — falling back to httpx default port list.\n")
        return None
    cmd = ["naabu", "-silent"]
    if top_ports:
        cmd += ["-top-ports", str(top_ports)]
    elif ports:
        cmd += ["-p", ports]
    rc, out = run(cmd, timeout=timeout, stdin_data="\n".join(targets) + "\n")
    hostports = {l.strip() for l in out.splitlines() if l.strip()}
    sys.stderr.write(f"[*] naabu found {len(hostports)} open host:port pairs.\n")
    return hostports


# --------------------------------------------------------------------------- #
# HTTP probing with httpx
# --------------------------------------------------------------------------- #

def run_httpx(targets, args):
    """Feed targets to httpx via stdin, return a list of parsed JSON records."""
    if not have("httpx"):
        sys.exit("[x] httpx (ProjectDiscovery) not found on PATH. Install it and retry.")

    cmd = [
        "httpx",
        "-json",
        "-tech-detect",            # Wappalyzer: PHP + version among others
        "-include-response-header",# puts X-Powered-By / Set-Cookie into JSON
        "-status-code",
        "-title",
        "-web-server",
        "-location",
        "-follow-redirects" if args.follow_redirects else "-no-fallback",
        "-threads", str(args.threads),
        "-timeout", str(args.http_timeout),
        "-silent",
    ]
    if args.rate_limit:
        cmd += ["-rate-limit", str(args.rate_limit)]
    # Only pass -ports when targets are bare hosts (no port already attached).
    if args.ports and not args.naabu:
        cmd += ["-ports", args.ports]
    if args.httpx_args:
        cmd += list(args.httpx_args)

    sys.stderr.write(f"[*] Probing {len(targets)} targets with httpx...\n")
    rc, out = run(cmd, stdin_data="\n".join(sorted(targets)) + "\n")
    records = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    sys.stderr.write(f"[*] httpx returned {len(records)} live endpoints.\n")
    return records


# --------------------------------------------------------------------------- #
# PHP detection
# --------------------------------------------------------------------------- #

PHP_VER_RE = re.compile(r"php[/ _-]?v?([0-9]+(?:\.[0-9]+){1,3})", re.I)

# Cookie-name substrings that imply a PHP backend -> indicator label.
# Ordered most-specific first; each is a strong, passive PHP tell.
PHP_COOKIE_SIGNS = [
    ("phpsessid", "PHPSESSID"),
    ("laravel_session", "cookie:Laravel"),
    ("ci_session", "cookie:CodeIgniter"),
    ("cakephp", "cookie:CakePHP"),
    ("symfony", "cookie:Symfony"),
    ("wordpress_", "cookie:WordPress"),
    ("wp-settings", "cookie:WordPress"),
    ("phpbb3_", "cookie:phpBB"),
    ("moodlesession", "cookie:Moodle"),
    ("prestashop", "cookie:PrestaShop"),
    ("fuel_csrf_token", "cookie:FuelPHP"),
    ("xdebug_session", "cookie:Xdebug"),
]


def normalize_headers(rec):
    """Flatten httpx's header map to lowercase keys; values joined if lists."""
    headers = {}
    raw = rec.get("header") or rec.get("response_header") or {}
    if isinstance(raw, dict):
        for k, v in raw.items():
            if isinstance(v, list):
                v = "; ".join(str(x) for x in v)
            headers[k.lower().replace("_", "-")] = str(v)
    return headers


def detect_php(rec):
    """Return (indicators:list[str], version:str|None)."""
    indicators = []
    version = None
    headers = normalize_headers(rec)

    def grab_version(text):
        nonlocal version
        if version:
            return
        m = PHP_VER_RE.search(text or "")
        if m:
            version = m.group(1)

    # 1) X-Powered-By header — the most direct signal
    xpb = headers.get("x-powered-by", "")
    if "php" in xpb.lower():
        indicators.append("X-Powered-By")
        grab_version(xpb)

    # 2) Server header mentioning PHP (e.g. "Apache/2.4 PHP/7.4.3")
    server = rec.get("webserver") or headers.get("server", "")
    if "php" in server.lower():
        indicators.append("Server")
        grab_version(server)

    # 3) Session / framework cookies that imply a PHP backend.
    cookie = headers.get("set-cookie", "").lower()
    for needle, label in PHP_COOKIE_SIGNS:
        if needle in cookie and label not in indicators:
            indicators.append(label)

    # 4) Wappalyzer tech-detect from httpx
    for t in rec.get("tech", []) or []:
        if "php" in t.lower():
            indicators.append(f"tech:{t}")
            grab_version(t)

    # 5) .php in the final URL or any location-ish header.
    url = rec.get("url", "") or ""
    loc = " ".join(headers.get(h, "") for h in ("location", "content-location"))
    if re.search(r"\.php(\?|/|$)", url, re.I) or re.search(r"\.php(\?|/|$)", loc, re.I):
        indicators.append(".php URL")

    # 6) PHP-based CMS fingerprints in headers (WordPress/Drupal/Joomla/...).
    #    These apps rarely expose raw PHP, but their own headers give it away.
    #    All imply PHP, so each counts as a detection.
    pingback = headers.get("x-pingback", "")
    link = headers.get("link", "").lower()
    if "xmlrpc.php" in pingback.lower() or "wp-json" in link or "api.w.org" in link:
        _add(indicators, "CMS:WordPress")
    if "wordpress" in headers.get("x-redirect-by", "").lower():
        _add(indicators, "CMS:WordPress")
    if any(k.startswith("x-drupal") for k in headers) \
            or "drupal" in headers.get("x-generator", "").lower():
        _add(indicators, "CMS:Drupal")
    gen = headers.get("x-generator", "").lower() + " " + headers.get("x-powered-cms", "").lower()
    for cms in ("joomla", "typo3", "magento", "shopware", "bitrix", "concrete", "silverstripe"):
        if cms in gen:
            _add(indicators, f"CMS:{cms.capitalize()}")

    return indicators, version


def _add(lst, item):
    """Append item to lst only if not already present (keeps order)."""
    if item not in lst:
        lst.append(item)


def php_deep_probe(base_url, timeout):
    """
    Optional extra request: does /index.php resolve?
    Returns an indicator string or None. Kept opt-in to limit extra traffic.
    """
    target = base_url.rstrip("/") + "/index.php"

    def _headers(h):
        xpb = h.get("X-Powered-By", "") if h else ""
        server = h.get("Server", "") if h else ""
        cookie = h.get("Set-Cookie", "") if h else ""
        return xpb, server, cookie

    try:
        req = urllib.request.Request(target, method="GET",
                                     headers={"User-Agent": "asm-recon"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            xpb, server, cookie = _headers(resp.headers)
    except urllib.error.HTTPError as e:
        code = e.code
        xpb, server, cookie = _headers(e.headers)
    except Exception:
        return None, None

    ver = None
    m = PHP_VER_RE.search(f"{xpb} {server}")
    if m:
        ver = m.group(1)
    # /index.php existing is itself a signal; a PHP header/cookie makes it firm.
    strong = "php" in f"{xpb} {server}".lower() or "phpsessid" in cookie.lower()
    if code in (200, 301, 302, 401, 403, 500):
        tag = "index.php+hdr" if strong else f"index.php[{code}]"
        return tag, ver
    return None, None


# --------------------------------------------------------------------------- #
# Enrichment + output
# --------------------------------------------------------------------------- #

def enrich(records, args):
    rows = []
    deep_targets = []
    for rec in records:
        inds, ver = detect_php(rec)
        ips = rec.get("a") or []
        row = {
            "input": rec.get("input", ""),
            "url": rec.get("url", ""),
            "host": rec.get("host", ""),
            "port": rec.get("port", ""),
            "ip": ", ".join(ips) if isinstance(ips, list) else str(ips),
            "status_code": rec.get("status_code", ""),
            "webserver": rec.get("webserver", ""),
            "title": (rec.get("title", "") or "").replace("\n", " ")[:80],
            "tech": ", ".join(rec.get("tech", []) or []),
            "php": "yes" if inds else "no",
            "php_version": ver or "",
            "php_indicators": ", ".join(inds),
        }
        rows.append(row)
        if args.php_deep and not inds and rec.get("url"):
            deep_targets.append((row, rec.get("url")))

    # Deep probe only the hosts with no signal yet (concurrently)
    if deep_targets:
        sys.stderr.write(f"[*] Deep PHP probe on {len(deep_targets)} unflagged hosts...\n")
        with ThreadPoolExecutor(max_workers=min(20, args.threads)) as ex:
            futs = {ex.submit(php_deep_probe, url, args.http_timeout): row
                    for row, url in deep_targets}
            for fut in as_completed(futs):
                row = futs[fut]
                ind, ver = fut.result()
                if ind:
                    row["php"] = "yes"
                    row["php_indicators"] = ind
                    if ver and not row["php_version"]:
                        row["php_version"] = ver
    return rows


# ANSI styling for the status table.
ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[91m",       # bright red
    "on_red": "\033[41m",    # red background
    "white": "\033[97m",
}


def _use_color(stream, force_off=False):
    """Decide whether to emit ANSI codes for a given stream."""
    if force_off or os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return stream.isatty()
    except Exception:
        return False


# Big ASCII font (5 rows tall) for the program banner.
_FONT = {
    " ": ["     ", "     ", "     ", "     ", "     "],
    "A": [" XXX ", "X   X", "XXXXX", "X   X", "X   X"],
    "E": ["XXXXX", "X    ", "XXXX ", "X    ", "XXXXX"],
    "G": [" XXXX", "X    ", "X  XX", "X   X", " XXXX"],
    "H": ["X   X", "X   X", "XXXXX", "X   X", "X   X"],
    "I": ["XXXXX", "  X  ", "  X  ", "  X  ", "XXXXX"],
    "M": ["X   X", "XX XX", "X X X", "X   X", "X   X"],
    "N": ["X   X", "XX  X", "X X X", "X  XX", "X   X"],
    "P": ["XXXX ", "X   X", "XXXX ", "X    ", "X    "],
    "R": ["XXXX ", "X   X", "XXXX ", "X  X ", "X   X"],
    "U": ["X   X", "X   X", "X   X", "X   X", " XXX "],
    "W": ["X   X", "X   X", "X X X", "XX XX", "X   X"],
}


def _render_big(text):
    """Render text as a list of 5 strings using the block font."""
    rows = ["", "", "", "", ""]
    for ch in text.upper():
        glyph = _FONT.get(ch, _FONT[" "])
        for i in range(5):
            rows[i] += glyph[i].replace("X", "█") + "  "
    return [r.rstrip() for r in rows]


def banner(use_color=True):
    """Print the program's big ASCII header to stderr, with some padding."""
    pad = "    "  # left margin
    lines = _render_big("WHERE AM I") + [""] + _render_big("RUNNING PHP")
    on = ANSI["bold"] + ANSI["red"] if use_color else ""
    off = ANSI["reset"] if use_color else ""
    body = "\n".join(f"{pad}{on}{l}{off}" for l in lines)
    sys.stderr.write(f"\n\n{body}\n\n")


def print_table(rows, use_color=True):
    cols = [("url", 42), ("ip", 16), ("status_code", 4), ("webserver", 20),
            ("php", 3), ("php_version", 10), ("php_indicators", 30)]
    header = "  ".join(f"{name.upper():<{w}}" for name, w in cols)
    if use_color:
        print(f"{ANSI['bold']}{header}{ANSI['reset']}")
    else:
        print(header)
    print("-" * len(header))
    for r in sorted(rows, key=lambda x: (x["php"] != "yes", x["url"])):
        line = "  ".join(f"{str(r.get(name,''))[:w]:<{w}}" for name, w in cols)
        if use_color and r["php"] == "yes":
            # PHP detected: bold, bright red, with a highlighted PHP marker.
            print(f"{ANSI['bold']}{ANSI['red']}{line}{ANSI['reset']}")
        else:
            print(line)


def write_outputs(rows, prefix):
    import csv
    json_path = f"{prefix}.json"
    csv_path = f"{prefix}.csv"
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)
    if rows:
        fields = list(rows[0].keys())
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            w.writeheader()
            w.writerows(rows)
    sys.stderr.write(f"[*] Wrote {json_path} and {csv_path}\n")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        description="Attack-surface recon: subdomains -> httpx probe -> PHP fingerprint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inp = p.add_argument_group("inputs")
    inp.add_argument("-a", "--assets", action="append", default=[],
                     help="file with mixed assets (IPs, CIDRs, domains); one per line. Repeatable.")
    inp.add_argument("-d", "--domains", action="append", default=[],
                     help="file with domains only. Repeatable.")
    inp.add_argument("-i", "--ips", action="append", default=[],
                     help="file with IPs/CIDRs only. Repeatable.")
    inp.add_argument("-t", "--target", action="append", default=[],
                     help="inline asset (domain or IP). Repeatable.")
    inp.add_argument("targets", nargs="*", default=[], metavar="TARGET",
                     help="asset(s) passed directly without a flag, "
                          "e.g. `asm_recon.py example.com`. Same as -t.")

    disc = p.add_argument_group("discovery (subdomains / assets)")
    # The free, dependency-light sources run by default; disable with --no-<name>.
    disc.add_argument("--subfinder", action=argparse.BooleanOptionalAction, default=True,
                      help="use subfinder (default: on).")
    disc.add_argument("--assetfinder", action=argparse.BooleanOptionalAction, default=True,
                      help="use assetfinder (default: on).")
    disc.add_argument("--crtsh", action=argparse.BooleanOptionalAction, default=True,
                      help="query crt.sh certificate transparency, no tool needed (default: on).")
    disc.add_argument("--dns-brute", action=argparse.BooleanOptionalAction, default=True,
                      help="ACTIVE DNS brute-force of a wordlist — finds hosts passive sources "
                           "miss, e.g. non-CT-logged names (default: on; --no-dns-brute to skip).")
    disc.add_argument("--amass", action="store_true",
                      help="also use amass (passive); off by default — needs "
                           "INSTALL_AMASS=true at build time and is slow.")
    disc.add_argument("--wordlist", default=None,
                      help="wordlist for --dns-brute (one label per line); "
                           "uses a built-in list if omitted.")
    disc.add_argument("--dns-timeout", type=float, default=3.0,
                      help="per-name DNS resolution timeout seconds for --dns-brute (default 3).")
    disc.add_argument("--all-sources", action="store_true",
                      help="also enable amass on top of the default sources.")
    disc.add_argument("--findomain-args", nargs=argparse.REMAINDER, default=[],
                      help="extra args passed straight to findomain (put LAST).")
    disc.add_argument("--disc-timeout", type=int, default=120,
                      help="per-source, per-domain timeout seconds (default 120).")
    disc.add_argument("--no-discovery", action="store_true",
                      help="skip subdomain enumeration; probe the given assets as-is.")

    scan = p.add_argument_group("scanning / probing")
    scan.add_argument("--ports", default="80,443,8080,8443,8000,8888",
                      help="ports for httpx (default web ports).")
    scan.add_argument("--naabu", action="store_true",
                      help="fast port scan with naabu first, feed open ports to httpx.")
    scan.add_argument("--top-ports", type=int, default=None,
                      help="naabu top-N ports (overrides --ports for the scan).")
    scan.add_argument("--threads", type=int, default=50, help="httpx threads (default 50).")
    scan.add_argument("--rate-limit", type=int, default=None, help="httpx requests/sec cap.")
    scan.add_argument("--http-timeout", type=int, default=10, help="per-request timeout secs.")
    scan.add_argument("--follow-redirects", action="store_true", help="follow redirects in httpx.")
    scan.add_argument("--php-deep", action="store_true",
                      help="extra /index.php probe for hosts with no PHP signal.")
    scan.add_argument("--httpx-args", nargs=argparse.REMAINDER, default=[],
                      help="extra args passed straight to httpx (put LAST).")

    out = p.add_argument_group("output")
    out.add_argument("-o", "--out", default=None,
                     help="output file prefix (default asm_<timestamp>).")
    out.add_argument("--php-only", action="store_true", help="only show/keep PHP hosts.")
    out.add_argument("--no-color", action="store_true",
                     help="disable ANSI colors in the status table.")

    diag = p.add_argument_group("diagnostics")
    diag.add_argument("-D", "--debug", action="store_true",
                      help="verbose debug output to stderr (paths, commands, timings).")
    return p


def main():
    args = build_parser().parse_args()
    global DEBUG
    DEBUG = args.debug
    banner(use_color=_use_color(sys.stderr, force_off=args.no_color))
    dbg(f"argv: {sys.argv}")
    dbg(f"cwd: {os.getcwd()}")
    dbg(f"parsed args: {vars(args)}")
    if args.all_sources:
        args.subfinder = args.assetfinder = args.crtsh = True
        args.dns_brute = args.amass = True

    domains, ips, cidrs, skipped = load_tokens(
        args.assets + args.domains + args.ips, args.target + args.targets
    )
    if skipped:
        sys.stderr.write(f"[!] Ignored {len(skipped)} unrecognised tokens: "
                         f"{', '.join(skipped[:8])}{'...' if len(skipped) > 8 else ''}\n")
    if not (domains or ips or cidrs):
        sys.exit("[x] No valid assets. Pass a domain directly (e.g. "
                 "`asm_recon.py example.com`) or use -a/-d/-i/-t. See --help.")

    sys.stderr.write(f"[*] Seed: {len(domains)} domains, {len(ips)} IPs, {len(cidrs)} CIDRs\n")

    # 1-2) Discovery
    if args.no_discovery or not domains:
        hosts = set(domains)
    else:
        hosts = discover(domains, args)
    sys.stderr.write(f"[*] {len(hosts)} hostnames after discovery.\n")

    # Build the probe target set: hosts + IPs + expanded CIDRs
    targets = set(hosts) | set(ips)
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        if net.num_addresses <= 4096:
            targets |= {str(h) for h in net.hosts()}
        else:
            sys.stderr.write(f"[!] {c} too large to expand ({net.num_addresses} hosts); "
                             f"pass individual IPs or use --naabu.\n")

    if not targets:
        sys.exit("[x] Nothing to probe.")

    # 3) optional fast port scan, then HTTP probe
    if args.naabu:
        hostports = naabu_scan(sorted(targets), args.ports, args.top_ports, args.disc_timeout)
        if hostports:
            targets = hostports

    records = run_httpx(targets, args)

    # 4) PHP fingerprinting + enrichment
    rows = enrich(records, args)
    if args.php_only:
        rows = [r for r in rows if r["php"] == "yes"]

    # 5) output
    prefix = args.out or f"asm_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    use_color = _use_color(sys.stdout, force_off=args.no_color)
    print_table(rows, use_color=use_color)
    print()
    php_count = sum(1 for r in rows if r["php"] == "yes")
    count_str = str(php_count)
    if php_count and _use_color(sys.stderr, force_off=args.no_color):
        count_str = f"{ANSI['bold']}{ANSI['red']}{php_count}{ANSI['reset']}"
    sys.stderr.write(f"[*] {len(rows)} live hosts, {count_str} flagged as PHP.\n")
    write_outputs(rows, prefix)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[x] Interrupted.")
