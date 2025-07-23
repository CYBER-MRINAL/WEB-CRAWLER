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
from colorama import Fore, Style, init

init(autoreset=True)

class AsyncWebCrawler:
    def __init__(self, base_url, max_depth, output_file, user_agents, delay, concurrency):
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.output_file = output_file
        self.user_agents = user_agents
        self.delay = delay
        self.concurrency = concurrency

        # Async-safe data structures
        self.visited = set()
        self.results = []
        self.visited_lock = asyncio.Lock()

        # Sensitive endpoints
        self.important_dirs = [
            '/admin', '/login', '/dashboard', '/api', '/uploads',
            '/config', '/backup', '/.env', '/.git', '/.svn',
            '/phpmyadmin', '/wp-admin', '/wp-login.php', '/admin.php',
            '/user', '/users', '/settings', '/private', '/tmp',
            '/cgi-bin', '/test', '/dev', '/data', '/files', 
            '/images', '/js', '/css', '/bin', '/src', '/var', 
            '/etc', '/mail', '/logs', '/web', '/public', 
            '/static', '/assets', '/download'
        ]
        self.important_files = [
            '/robots.txt', '/security.txt', '/humans.txt', '/favicon.ico',
            '/.well-known/security.txt', '/.well-known/assetlinks.json',
            '/.well-known/host-meta', '/.well-known/webfinger',
            '/.well-known/manifest.json', '/.well-known/terms-of-service',
            '/.well-known/privacy-policy'
        ]

    def current_time(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async def record_result(self, url, status):
        self.results.append({'url': url, 'status': status})
        color = Fore.GREEN if status == 200 else Fore.YELLOW
        print(color + f"[{self.current_time()}] {url} (Status: {status})")

    async def fetch(self, session, url):
        try:
            headers = {'User-Agent': self.user_agents[0]}  # Simple UA rotation if needed
            async with session.get(url, headers=headers, timeout=ClientTimeout(total=10)) as resp:
                await self.record_result(url, resp.status)
                if resp.status == 200 and "text/html" in resp.headers.get('Content-Type', ''):
                    return await resp.text()
        except Exception as e:
            print(Fore.RED + f"[{self.current_time()}] Error fetching {url}: {e}")
        return None

    async def crawl_url(self, session, url, depth, queue):
        async with self.visited_lock:
            if url in self.visited:
                return
            self.visited.add(url)

        html_content = await self.fetch(session, url)
        if html_content and depth < self.max_depth:
            soup = BeautifulSoup(html_content, 'html.parser')
            for link in soup.find_all('a', href=True):
                next_url = urljoin(self.base_url, link['href'])
                if next_url.startswith(self.base_url):
                    await queue.put((next_url, depth + 1))
            await asyncio.sleep(self.delay)

    async def scan_sensitive_endpoints(self, session):
        print(Fore.BLUE + f"[{self.current_time()}] Scanning sensitive files & directories...")
        tasks = []
        for endpoint in self.important_files + self.important_dirs:
            url = urljoin(self.base_url, endpoint)
            tasks.append(self.fetch(session, url))
        await asyncio.gather(*tasks)

    async def start_crawling(self):
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            await self.scan_sensitive_endpoints(session)

            # BFS with async queue
            queue = asyncio.Queue()
            await queue.put((self.base_url, 0))

            while not queue.empty():
                tasks = []
                for _ in range(min(self.concurrency, queue.qsize())):
                    url, depth = await queue.get()
                    tasks.append(self.crawl_url(session, url, depth, queue))
                await asyncio.gather(*tasks)

        self.print_summary()
        self.save_results()

    def print_summary(self):
        print(Fore.BLUE + "\nSummary of Results:")
        for result in self.results:
            color = Fore.GREEN if result['status'] == 200 else Fore.YELLOW
            print(color + f"{result['url']} (Status: {result['status']})")

    def save_results(self):
        csv_file = self.output_file if self.output_file.endswith('.csv') else f"{self.output_file}.csv"
        json_file = csv_file.replace('.csv', '.json')

        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['url', 'status'])
            writer.writeheader()
            writer.writerows(self.results)

        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=4)

        print(Fore.GREEN + f"[{self.current_time()}] Results saved to {csv_file} and {json_file}")

def main():
    parser = argparse.ArgumentParser(description="Elite Asynchronous Web Crawler (^_^)")
    parser.add_argument('url', type=str, help='Base URL to crawl (e.g., http://example.com)')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum depth to crawl (default: 3)')
    parser.add_argument('--output', type=str, default='results', help='Output file name (default: results)')
    parser.add_argument('--user-agents', type=str, nargs='*', default=['Mozilla/5.0'], help='List of user agents')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests (default: 0.5s)')
    parser.add_argument('--concurrency', type=int, default=20, help='Max concurrent requests (default: 20)')
    args = parser.parse_args()

    crawler = AsyncWebCrawler(args.url, args.max_depth, args.output, args.user_agents, args.delay, args.concurrency)
    asyncio.run(crawler.start_crawling())

if __name__ == "__main__":
    main()