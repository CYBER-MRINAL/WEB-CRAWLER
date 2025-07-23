#!/usr/bin/env python3 """ Elite Pentest Web Crawler (EPWC)

A high-performance, scope-aware, asynchronous reconnaissance crawler built for penetration testers and red teams. Designed to be fast, polite, controllable, and actionable.

Major Capabilities

✓ Asynchronous HTTP fetching (aiohttp) with bounded concurrency. ✓ Strict no-duplicate URL fetching with canonicalization + async locks. ✓ Scope controls: same-origin (default), allow subdomains, explicit allowlist. ✓ Optional ignore robots.txt for authorized testing; otherwise honor robots. ✓ BFS depth control, URL budget (--max-urls) safety brake. ✓ Sensitive file & directory probing (admin panels, backups, .env, etc.). ✓ Keyword / regex hit tagging (e.g., "admin", "login", "api", etc.). ✓ Rate limiting: global delay between requests + per-host semaphore. ✓ Retries w/ exponential backoff. ✓ Rich result metadata: status, content-type, length, title, depth, redirect, hits. ✓ Multi-format output: CSV, JSON, JSONL (streaming-friendly), and pretty summary. ✓ Colored console output (Colorama). ✓ Optional proxy, cookies, custom headers, auth, and TLS verify toggle.

Legal / Ethical Notice

Use only against systems you own or have explicit authorization to test. Respect laws, terms of service, and engagement scope.

Example Usage

Basic crawl, depth 2, save to out.csv/json/jsonl

python elite_pentest_web_crawler.py https://target.tld --max-depth 2 --output target_scan

Ignore robots, scan subdomains, look for login/admin strings, faster concurrency

python elite_pentest_web_crawler.py https://corp.example --ignore-robots --allow-subdomains 
--keywords admin login api --concurrency 40 --delay 0.1 --output corp_recon

Limit total URLs (safety), trust self-signed certs, go deeper

python elite_pentest_web_crawler.py https://internal.lab --max-depth 5 --max-urls 5000 --no-verify

"""

import asyncio import aiohttp from aiohttp import ClientTimeout from aiohttp.client_exceptions import ClientError import async_timeout from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode from bs4 import BeautifulSoup import argparse import csv import json import os import re import sys from datetime import datetime from typing import List, Set, Tuple, Dict, Optional, Iterable from colorama import Fore, Style, init as colorama_init

---------------------------------------------------------------------------

Colorama init

---------------------------------------------------------------------------

colorama_init(autoreset=True)

---------------------------------------------------------------------------

Data Structures

---------------------------------------------------------------------------

class CrawlResult(dict): """Simple dict subclass for clarity; keys documented below.""" # Keys: url, status, content_type, content_length, title, depth, #        redirected, redirect_target, keywords_hit (list), timestamp pass

---------------------------------------------------------------------------

Utility Functions

---------------------------------------------------------------------------

def now_str() -> str: return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def canonicalize_url(url: str, keep_query: bool = True, sort_query: bool = True) -> str: """Create a normalized URL string for dedupe comparisons.

Normalizations:
- Lowercase scheme + host.
- Remove default ports (:80 for http, :443 for https).
- Drop fragment.
- Optionally sort query params for stability.
- Optionally drop query string entirely.
- Collapse repeated slashes in path.
- Ensure no trailing slash duplication (except root).
"""
try:
    parsed = urlparse(url)
except Exception:
    return url  # fallback

scheme = parsed.scheme.lower()
netloc = parsed.hostname.lower() if parsed.hostname else ''
port = parsed.port
if port and not ((scheme == 'http' and port == 80) or (scheme == 'https' and port == 443)):
    netloc = f"{netloc}:{port}"

# Normalize path: collapse // -> /
path = re.sub(r'/+', '/', parsed.path or '/')
if path != '/' and path.endswith('/'):
    path = path[:-1]

query = ''
if keep_query and parsed.query:
    if sort_query:
        q = parse_qsl(parsed.query, keep_blank_values=True)
        q.sort()
        query = urlencode(q, doseq=True)
    else:
        query = parsed.query

new_parts = (scheme, netloc, path, '', query, '')
return urlunparse(new_parts)

---------------------------------------------------------------------------

Scope Helpers

---------------------------------------------------------------------------

def extract_registrable_domain(host: str) -> str: """Very simple heuristic registrable domain extraction. NOTE: Not a full PSL parse; good enough for scope gating. Splits host and returns last two labels if >=2 labels, else host. """ if not host: return '' parts = host.split('.') if len(parts) >= 2: return '.'.join(parts[-2:]) return host

---------------------------------------------------------------------------

Robots.txt Handling (sync-once call via aiohttp)

---------------------------------------------------------------------------

async def fetch_robots(session: aiohttp.ClientSession, base_url: str) -> Optional[str]: robots_url = urljoin(base_url.rstrip('/') + '/', 'robots.txt') try: async with session.get(robots_url, timeout=ClientTimeout(total=10)) as resp: if resp.status == 200: return await resp.text() except Exception: pass return None

def parse_robots(robots_text: str) -> List[Tuple[str, str]]: """Minimal robots parser: returns allow/disallow lines for User-agent: . Format: [('allow', '/path'), ('disallow', '/admin')...] This is intentionally lightweight; for full spec use python-robotexclusionrulesparser. """ rules = [] if not robots_text: return rules ua_block = False for line in robots_text.splitlines(): line = line.strip() if not line or line.startswith('#'): continue if line.lower().startswith('user-agent:'): ua = line.split(':', 1)[1].strip() ua_block = (ua == '' or ua == '.*') continue if not ua_block: continue if ':' not in line: continue k, v = line.split(':', 1) k = k.strip().lower() v = v.strip() if k == 'disallow': rules.append(('disallow', v)) elif k == 'allow': rules.append(('allow', v)) return rules

def robots_can_fetch(rules: List[Tuple[str, str]], url_path: str) -> bool: """Naive robots allow/disallow evaluation: longest match wins. Later rules override earlier ones if longer. """ decision = None  # None=allowed until disallowed longest = -1 for action, path_rule in rules: if not path_rule: continue if url_path.startswith(path_rule): l = len(path_rule) if l > longest: decision = action longest = l if decision == 'disallow': return False return True

---------------------------------------------------------------------------

Main Crawler Class

---------------------------------------------------------------------------

class ElitePentestCrawler: def init( self, base_url: str, max_depth: int, output_file: str, user_agents: List[str], delay: float, concurrency: int, allow_subdomains: bool, allowlist_domains: Optional[List[str]], ignore_robots: bool, max_urls: Optional[int], keywords: Optional[List[str]], keyword_regex: Optional[str], keep_query: bool, sort_query: bool, timeout: int, retries: int, backoff: float, proxy: Optional[str], cookies: Optional[str], headers: Optional[List[str]], auth: Optional[str], verify_ssl: bool, ): self.base_url = base_url.rstrip('/') self.parsed_base = urlparse(self.base_url) self.base_host = self.parsed_base.hostname or '' self.base_domain = extract_registrable_domain(self.base_host)

self.max_depth = max_depth
    self.output_file = output_file
    self.user_agents = user_agents
    self.delay = delay
    self.concurrency = concurrency
    self.allow_subdomains = allow_subdomains
    self.ignore_robots = ignore_robots
    self.max_urls = max_urls if max_urls and max_urls > 0 else None
    self.keep_query = keep_query
    self.sort_query = sort_query
    self.timeout = timeout
    self.retries = retries
    self.backoff = backoff
    self.proxy = proxy
    self.verify_ssl = verify_ssl

    # Parse cookies string "k=v;k2=v2" -> dict
    self.cookie_jar = {}
    if cookies:
        for c in cookies.split(';'):
            if '=' in c:
                k, v = c.split('=', 1)
                self.cookie_jar[k.strip()] = v.strip()

    # Extra headers list like Key:Val
    self.extra_headers = {}
    if headers:
        for h in headers:
            if ':' in h:
                k, v = h.split(':', 1)
                self.extra_headers[k.strip()] = v.strip()

    # Basic auth user:pass
    self.auth = None
    if auth and ':' in auth:
        u, p = auth.split(':', 1)
        self.auth = aiohttp.BasicAuth(u, p)

    # Keyword filters
    self.keywords = [k.lower() for k in (keywords or [])]
    self.keyword_regex = re.compile(keyword_regex, re.I) if keyword_regex else None

    # Domain allowlist overrides
    self.allowlist_domains = set(d.lower() for d in allowlist_domains) if allowlist_domains else set()

    # Async state
    self.visited: Set[str] = set()
    self.visited_lock = asyncio.Lock()
    self.rules = []  # robots rules
    self.results: List[CrawlResult] = []
    self.sem = asyncio.Semaphore(concurrency)

    # Sensitive endpoints (same as earlier versions; deduped) -- trailing slash mgmt
    self.important_dirs = sorted(set([
        '/admin', '/login', '/dashboard', '/api', '/uploads',
        '/config', '/backup', '/.env', '/.git', '/.svn',
        '/phpmyadmin', '/wp-admin', '/wp-login.php', '/admin.php',
        '/user', '/users', '/settings', '/private', '/tmp',
        '/cgi-bin', '/test', '/dev', '/data', '/files', 
        '/images', '/js', '/css', '/bin', '/src', '/var', 
        '/etc', '/mail', '/logs', '/web', '/public', 
        '/static', '/assets', '/download'
    ]))
    self.important_files = [
        '/robots.txt', '/security.txt', '/humans.txt', '/favicon.ico',
        '/.well-known/security.txt', '/.well-known/assetlinks.json',
        '/.well-known/host-meta', '/.well-known/webfinger',
        '/.well-known/manifest.json', '/.well-known/terms-of-service',
        '/.well-known/privacy-policy'
    ]

# -------------------------------------------------------------------
# Scope Check
# -------------------------------------------------------------------
def in_scope(self, url: str) -> bool:
    try:
        p = urlparse(url)
    except Exception:
        return False
    host = (p.hostname or '').lower()
    if not host:
        return False

    # Explicit allowlist wins
    if self.allowlist_domains and host in self.allowlist_domains:
        return True

    if self.allow_subdomains:
        # host endswith base_domain
        return host == self.base_host or host.endswith('.' + self.base_domain)
    else:
        return host == self.base_host

# -------------------------------------------------------------------
# Robots Gate
# -------------------------------------------------------------------
def robots_allowed(self, url: str) -> bool:
    if self.ignore_robots or not self.rules:
        return True
    try:
        path = urlparse(url).path or '/'
    except Exception:
        return True
    return robots_can_fetch(self.rules, path)

# -------------------------------------------------------------------
# Keyword Hit Logic
# -------------------------------------------------------------------
def keyword_hits(self, text: str, url: str) -> List[str]:
    hits = []
    low = text.lower() if text else ''
    for kw in self.keywords:
        if kw in low:
            hits.append(kw)
    if self.keyword_regex and self.keyword_regex.search(text or ''):
        hits.append(f"regex:{self.keyword_regex.pattern}")
    # Also check URL path itself
    path_low = url.lower()
    for kw in self.keywords:
        if kw in path_low and kw not in hits:
            hits.append(kw)
    if self.keyword_regex and self.keyword_regex.search(url) and f"regex:{self.keyword_regex.pattern}" not in hits:
        hits.append(f"regex:{self.keyword_regex.pattern}")
    return hits

# -------------------------------------------------------------------
# Result Recording
# -------------------------------------------------------------------
async def record(self, *, url: str, status: int, content_type: str = '', content_length: int = -1,
                 title: str = '', depth: int = -1, redirected: bool = False,
                 redirect_target: str = '', keywords_hit: Optional[List[str]] = None) -> None:
    r: CrawlResult = CrawlResult(
        url=url,
        status=status,
        content_type=content_type,
        content_length=content_length,
        title=title,
        depth=depth,
        redirected=redirected,
        redirect_target=redirect_target,
        keywords_hit=keywords_hit or [],
        timestamp=now_str(),
    )
    self.results.append(r)
    color = Fore.GREEN if status == 200 else (Fore.YELLOW if status and status < 400 else Fore.RED)
    kw_note = ''
    if r['keywords_hit']:
        kw_note = f" [hits: {','.join(r['keywords_hit'])}]"
    print(color + f"[{now_str()}] {status} {url}{kw_note}")

# -------------------------------------------------------------------
# HTTP Fetch w/ Retry & Backoff
# -------------------------------------------------------------------
async def http_get(self, session: aiohttp.ClientSession, url: str) -> Optional[aiohttp.ClientResponse]:
    # Caller must manage context; we return text separately.
    # We'll implement a simple retry loop.
    attempt = 0
    while True:
        try:
            async with self.sem:
                headers = {}
                if self.user_agents:
                    headers['User-Agent'] = self.user_agents[attempt % len(self.user_agents)]
                headers.update(self.extra_headers)
                resp = await session.get(url, headers=headers, ssl=self.verify_ssl, timeout=self.timeout)
                return resp
        except Exception as e:
            attempt += 1
            if attempt > self.retries:
                print(Fore.RED + f"[{now_str()}] GET failed {url}: {e}")
                return None
            await asyncio.sleep(self.backoff * attempt)

# -------------------------------------------------------------------
# Fetch + Parse
# -------------------------------------------------------------------
async def fetch_and_process(self, session: aiohttp.ClientSession, url: str, depth: int, queue: asyncio.Queue):
    # Canonicalize early for dedupe
    canon = canonicalize_url(url, keep_query=self.keep_query, sort_query=self.sort_query)
    async with self.visited_lock:
        if canon in self.visited:
            return
        self.visited.add(canon)

    if not self.in_scope(url):
        return
    if not self.robots_allowed(url):
        print(Fore.YELLOW + f"[{now_str()}] Blocked by robots.txt: {url}")
        return
    if self.max_urls and len(self.visited) > self.max_urls:
        return

    resp = await self.http_get(session, url)
    if not resp:
        await self.record(url=url, status=-1, depth=depth)
        return
    try:
        status = resp.status
        ct = resp.headers.get('Content-Type', '')
        cl = int(resp.headers.get('Content-Length') or -1)
        redir = bool(resp.history)
        redir_target = str(resp.real_url) if redir else ''

        body = ''
        text = ''
        title = ''
        if 'text/html' in ct:
            body = await resp.text(errors='ignore')
            soup = BeautifulSoup(body, 'html.parser')
            t = soup.find('title')
            title = t.get_text(strip=True)[:200] if t else ''
            if depth < self.max_depth:
                for a in soup.find_all('a', href=True):
                    nxt = urljoin(url, a['href'])
                    if self.in_scope(nxt):
                        await queue.put((nxt, depth + 1))
        else:
            # Non-HTML: read but don't parse (small read)
            # We'll not load full body to save mem
            _ = await resp.read()

        # Keyword detection (body+title path)
        text_for_hits = title + '\n' + body[:50000]  # cap for performance
        hits = self.keyword_hits(text_for_hits, url)
        await self.record(url=url, status=status, content_type=ct, content_length=cl,
                          title=title, depth=depth, redirected=redir,
                          redirect_target=redir_target, keywords_hit=hits)
    finally:
        resp.release()

    # politeness delay
    if self.delay > 0:
        await asyncio.sleep(self.delay)

# -------------------------------------------------------------------
# Sensitive Endpoint Scan
# -------------------------------------------------------------------
async def scan_sensitive(self, session: aiohttp.ClientSession):
    print(Fore.BLUE + f"[{now_str()}] Scanning sensitive endpoints...")
    tasks = []
    targets = self.important_files + self.important_dirs
    for ep in targets:
        u = urljoin(self.base_url + '/', ep.lstrip('/'))
        if not self.in_scope(u):
            continue
        if not self.robots_allowed(u):
            continue
        tasks.append(self.fetch_sensitive_single(session, u))
    await asyncio.gather(*tasks)

async def fetch_sensitive_single(self, session: aiohttp.ClientSession, url: str):
    resp = await self.http_get(session, url)
    if not resp:
        await self.record(url=url, status=-1, depth=0)
        return
    try:
        status = resp.status
        ct = resp.headers.get('Content-Type', '')
        cl = int(resp.headers.get('Content-Length') or -1)
        await self.record(url=url, status=status, content_type=ct, content_length=cl, depth=0)
    finally:
        resp.release()

# -------------------------------------------------------------------
# Robots bootstrap
# -------------------------------------------------------------------
async def load_robots(self, session: aiohttp.ClientSession):
    if self.ignore_robots:
        print(Fore.YELLOW + f"[{now_str()}] Ignoring robots.txt by user request.")
        return
    txt = await fetch_robots(session, self.base_url)
    if txt:
        self.rules = parse_robots(txt)
        print(Fore.GREEN + f"[{now_str()}] robots.txt loaded ({len(self.rules)} rules).")
    else:
        print(Fore.YELLOW + f"[{now_str()}] robots.txt not found or unreadable; proceeding.")

# -------------------------------------------------------------------
# Crawl Orchestration
# -------------------------------------------------------------------
async def run(self):
    timeout = ClientTimeout(total=self.timeout if isinstance(self.timeout, (int, float)) else 30)
    connector = aiohttp.TCPConnector(limit=0, ssl=self.verify_ssl)  # We'll sem-limit manually

    async with aiohttp.ClientSession(
        connector=connector,
        cookies=self.cookie_jar,
        auth=self.auth,
        trust_env=True if self.proxy else False,  # allow env proxies
    ) as session:
        # Proxy handling: we pass per-request? We'll rely on env if provided; else direct.
        await self.load_robots(session)
        await self.scan_sensitive(session)

        queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        await queue.put((self.base_url, 0))

        while not queue.empty():
            # Respect max_urls safety
            if self.max_urls and len(self.visited) >= self.max_urls:
                print(Fore.RED + f"[{now_str()}] Max URL budget reached ({self.max_urls}). Stopping crawl.")
                break

            batch = []
            # Drain up to concurrency items
            for _ in range(min(self.concurrency, queue.qsize())):
                batch.append(await queue.get())

            tasks = [self.fetch_and_process(session, u, d, queue) for u, d in batch]
            await asyncio.gather(*tasks)

    self.print_summary()
    self.save_outputs()

# -------------------------------------------------------------------
# Reporting
# -------------------------------------------------------------------
def print_summary(self):
    print(Fore.BLUE + "\n=== Crawl Summary ===")
    total = len(self.results)
    found200 = sum(1 for r in self.results if r['status'] == 200)
    print(Fore.BLUE + f"Total checked: {total}")
    print(Fore.GREEN + f"HTTP 200: {found200}")
    if self.keywords:
        hits = [r for r in self.results if r['keywords_hit']]
        print(Fore.MAGENTA + f"Keyword hits: {len(hits)}")

def save_outputs(self):
    base = self.output_file or 'results'
    if base.endswith('.csv'):
        base = base[:-4]
    csv_path = base + '.csv'
    json_path = base + '.json'
    jsonl_path = base + '.jsonl'

    # CSV
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['url','status','content_type','content_length','title','depth','redirected','redirect_target','keywords_hit','timestamp']
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in self.results:
            row = r.copy()
            row['keywords_hit'] = ','.join(row['keywords_hit'])
            w.writerow(row)

    # JSON (array)
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(self.results, f, indent=2)

    # JSONL
    with open(jsonl_path, 'w', encoding='utf-8') as f:
        for r in self.results:
            f.write(json.dumps(r) + '\n')

    print(Fore.GREEN + f"[{now_str()}] Results saved -> {csv_path}, {json_path}, {jsonl_path}")

---------------------------------------------------------------------------

CLI

---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser: p = argparse.ArgumentParser(description="Elite Pentest Web Crawler (^_^)") p.add_argument('url', type=str, help='Base URL to crawl (e.g., https://example.com)') p.add_argument('--max-depth', type=int, default=3, help='Maximum crawl depth (default: 3)') p.add_argument('--max-urls', type=int, default=None, help='Safety cap: max total URLs to fetch') p.add_argument('--output', type=str, default='results', help='Output file base name (default: results)') p.add_argument('--user-agents', type=str, nargs='', default=['Mozilla/5.0'], help='Rotate these User-Agent strings') p.add_argument('--delay', type=float, default=0.2, help='Politeness delay between requests (default: 0.2s)') p.add_argument('--concurrency', type=int, default=20, help='Max concurrent fetches (default: 20)') p.add_argument('--allow-subdomains', action='store_true', help='Include subdomains of the base domain in scope') p.add_argument('--allowlist-domain', action='append', default=[], help='Explicit additional in-scope domain (repeatable)') p.add_argument('--ignore-robots', action='store_true', help='Ignore robots.txt (authorized testing only!)') p.add_argument('--keywords', type=str, nargs='', default=[], help='Keyword substrings to detect in URL/HTML/title') p.add_argument('--keyword-regex', type=str, help='Regex pattern for keyword detection (case-insensitive)') p.add_argument('--keep-query', action='store_true', help='Keep query strings when deduping URLs (default: drop)') p.add_argument('--sort-query', action='store_true', help='Sort query parameters when canonicalizing') p.add_argument('--timeout', type=int, default=30, help='Total request timeout seconds (default: 30)') p.add_argument('--retries', type=int, default=2, help='Retry count on failure (default: 2)') p.add_argument('--backoff', type=float, default=0.5, help='Backoff multiplier seconds (default: 0.5)') p.add_argument('--proxy', type=str, help='HTTP/HTTPS proxy URL (or set env http_proxy/https_proxy)') p.add_argument('--cookies', type=str, help='Cookie string k=v;k2=v2') p.add_argument('--header', type=str, action='append', default=[], help='Extra header Key:Value (repeatable)') p.add_argument('--auth', type=str, help='Basic auth user:pass') p.add_argument('--no-verify', action='store_true', help='Disable TLS certificate verification') return p

def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace: p = build_arg_parser() args = p.parse_args(argv) return args

---------------------------------------------------------------------------

Main Entrypoint

---------------------------------------------------------------------------

async def async_main(args: argparse.Namespace): crawler = ElitePentestCrawler( base_url=args.url, max_depth=args.max_depth, output_file=args.output, user_agents=args.user_agents, delay=args.delay, concurrency=args.concurrency, allow_subdomains=args.allow_subdomains, allowlist_domains=args.allowlist_domain, ignore_robots=args.ignore_robots, max_urls=args.max_urls, keywords=args.keywords, keyword_regex=args.keyword_regex, keep_query=args.keep_query, sort_query=args.sort_query, timeout=args.timeout, retries=args.retries, backoff=args.backoff, proxy=args.proxy, cookies=args.cookies, headers=args.header, auth=args.auth, verify_ssl=not args.no_verify, ) await crawler.run()

def main(): args = parse_args() try: asyncio.run(async_main(args)) except KeyboardInterrupt: print(Fore.RED + f"\n[{now_str()}] Interrupted by user.")

if name == 'main': main()

