#!/usr/bin/env python3
import asyncio
import aiohttp
from aiohttp import ClientTimeout
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import argparse
import json
import csv
from datetime import datetime
from colorama import Fore, init
import re

init(autoreset=True)

class EliteCrawler:
    def __init__(self, base_url, max_depth, output_file, user_agents, delay,
                 concurrency, keywords, ignore_robots, domain_scope, url_budget):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.output_file = output_file
        self.user_agents = user_agents
        self.delay = delay
        self.concurrency = concurrency
        self.keywords = [k.lower() for k in keywords] if keywords else []
        self.ignore_robots = ignore_robots
        self.domain_scope = domain_scope  # 'same', 'subdomains', 'all'
        self.url_budget = url_budget

        self.visited = set()
        self.results = []
        self.visited_lock = asyncio.Lock()
        self.total_visited = 0
        self.session = None

        # Pre-parse netloc for scope checking
        parsed = urlparse(self.base_url)
        self.base_netloc = parsed.netloc
        self.base_domain = '.'.join(self.base_netloc.split('.')[-2:])

        self.important_dirs = [
            '/admin', '/login', '/dashboard', '/api', '/uploads',
            '/config', '/backup', '/.env', '/.git', '/.svn',
            '/phpmyadmin', '/wp-admin', '/wp-login.php', '/admin.php',
            '/user', '/users', '/settings', '/private', '/tmp',
            '/cgi-bin', '/test', '/dev', '/data', '/files',
        ]
        self.important_files = [
            '/robots.txt', '/security.txt', '/humans.txt', '/favicon.ico',
            '/.well-known/security.txt', '/.well-known/assetlinks.json',
            '/.well-known/host-meta', '/.well-known/webfinger',
        ]

    def current_time(self):
        return Fore.RED + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + Fore.RESET

    def in_scope(self, url):
        parsed = urlparse(url)
        if self.domain_scope == 'all':
            return True
        elif self.domain_scope == 'same':
            return parsed.netloc == self.base_netloc
        elif self.domain_scope == 'subdomains':
            return parsed.netloc.endswith(self.base_domain)
        return False

    async def record_result(self, url, status, title='', keyword_hit=False):
        entry = {'url': url, 'status': status, 'title': title, 'hit': keyword_hit}
        self.results.append(entry)
        color = Fore.GREEN if status == 200 else Fore.YELLOW
        if keyword_hit:
            color = Fore.MAGENTA
        print(f"[{self.current_time()}]> {color}{url} ({status}) {'[MATCH]' if keyword_hit else ''}")

    async def fetch(self, url):
        try:
            headers = {'User-Agent': self.user_agents[0]}
            async with self.session.get(url, headers=headers, timeout=ClientTimeout(total=10)) as resp:
                content_type = resp.headers.get('Content-Type', '')
                text = await resp.text(errors='ignore') if 'text/html' in content_type else ''
                return resp.status, text
        except Exception:
            return None, None

    async def crawl_url(self, url, depth, queue):
        async with self.visited_lock:
            if url in self.visited or self.total_visited >= self.url_budget:
                return
            self.visited.add(url)
            self.total_visited += 1

        status, html = await self.fetch(url)
        if status is None:
            return

        title = ''
        keyword_hit = False
        if html:
            soup = BeautifulSoup(html, 'html.parser')
            title_tag = soup.find('title')
            title = title_tag.text.strip() if title_tag else ''
            if any(k in url.lower() for k in self.keywords) or \
               any(k in title.lower() for k in self.keywords) or \
               any(re.search(k, html, re.I) for k in self.keywords):
                keyword_hit = True

            if depth < self.max_depth:
                for link in soup.find_all('a', href=True):
                    next_url = urljoin(url, link['href'])
                    if next_url.startswith(self.base_url) and self.in_scope(next_url):
                        await queue.put((next_url, depth + 1))

        await self.record_result(url, status, title, keyword_hit)
        await asyncio.sleep(self.delay)

    async def scan_sensitive_endpoints(self):
        targets = [urljoin(self.base_url, p) for p in self.important_dirs + self.important_files]
        tasks = [self.fetch_and_record(url) for url in targets if self.in_scope(url)]
        await asyncio.gather(*tasks)

    async def fetch_and_record(self, url):
        status, _ = await self.fetch(url)
        if status is not None:
            await self.record_result(url, status)

    async def run(self):
        conn = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=conn) as self.session:
            queue = asyncio.Queue()
            await queue.put((self.base_url, 0))
            await self.scan_sensitive_endpoints()

            while not queue.empty() and self.total_visited < self.url_budget:
                tasks = []
                for _ in range(min(queue.qsize(), self.concurrency)):
                    url, depth = await queue.get()
                    tasks.append(self.crawl_url(url, depth, queue))
                await asyncio.gather(*tasks)

        self.print_summary()
        self.save_results()

    def print_summary(self):
        print(Fore.BLUE + "\nSummary:")
        for r in self.results:
            line = f"{r['url']} ({r['status']})"
            if r['hit']:
                line += " [MATCH]"
            print(line)

    def save_results(self):
        csv_path = self.output_file + '.csv'
        json_path = self.output_file + '.json'

        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'status', 'title', 'hit'])
            writer.writeheader()
            writer.writerows(self.results)

        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2)

        print(Fore.GREEN + f"\nResults saved to {csv_path} and {json_path}")


def main():
    parser = argparse.ArgumentParser(description="Elite Async Pentester Web Crawler")
    parser.add_argument('url', help="Base URL to start crawling")
    parser.add_argument('--max-depth', type=int, default=3)
    parser.add_argument('--output', default='results')
    parser.add_argument('--user-agents', nargs='*', default=['Mozilla/5.0'])
    parser.add_argument('--delay', type=float, default=0.5)
    parser.add_argument('--concurrency', type=int, default=15)
    parser.add_argument('--keywords', nargs='*', help="Keyword or regex triggers (e.g. admin login)")
    parser.add_argument('--ignore-robots', action='store_true')
    parser.add_argument('--domain-scope', choices=['same', 'subdomains', 'all'], default='same')
    parser.add_argument('--url-budget', type=int, default=1000)
    args = parser.parse_args()

    crawler = EliteCrawler(
        base_url=args.url,
        max_depth=args.max_depth,
        output_file=args.output,
        user_agents=args.user_agents,
        delay=args.delay,
        concurrency=args.concurrency,
        keywords=args.keywords,
        ignore_robots=args.ignore_robots,
        domain_scope=args.domain_scope,
        url_budget=args.url_budget
    )

    try:
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Stopped by user")


if __name__ == "__main__":
    main()

