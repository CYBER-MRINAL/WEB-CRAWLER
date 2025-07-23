#!/usr/bin/env python3
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from urllib import robotparser
import argparse
from colorama import Fore, Style, init
from datetime import datetime
import threading
import time
import json
import csv

# Initialize Colorama
init(autoreset=True)

class WebCrawler:
    def __init__(self, base_url, max_depth, output_file, user_agents, delay):
        self.base_url = base_url
        self.max_depth = max_depth
        self.output_file = output_file
        self.visited = set()
        self.results = []
        self.lock = threading.Lock()
        self.delay = delay
        self.user_agents = user_agents
        self.current_depth = 0
        self.important_dirs = [
            '/admin', '/login', '/dashboard', '/api', '/uploads',
            '/config', '/backup', '/.env', '/.git', '/.svn',
            '/phpmyadmin', '/wp-admin', '/wp-login.php', '/admin.php',
            '/user', '/users', '/settings', '/private', '/tmp',
            '/cgi-bin', '/test', '/dev', '/data', '/files', 
            '/images', '/js', '/css', '/uploads', '/bin', 
            '/src', '/var', '/etc', '/mail', '/logs', 
            '/web', '/public', '/static', '/assets', '/download'
        ]
        self.important_files = [
            '/robots.txt', '/security.txt', '/humans.txt', '/favicon.ico',
            '/.well-known/security.txt', '/.well-known/assetlinks.json',
            '/.well-known/host-meta', '/.well-known/webfinger',
            '/.well-known/manifest.json', '/.well-known/terms-of-service',
            '/.well-known/privacy-policy'
        ]
        self.rp = robotparser.RobotFileParser()
        self.rp.set_url(urljoin(base_url, 'robots.txt'))

    def current_time(self):
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def is_allowed(self, url):
        return self.rp.can_fetch('*', url)

    def check_robots_txt(self):
        try:
            response = requests.get(self.rp.url, headers={'User-Agent': 'Mozilla/5.0'})
            response.raise_for_status()
            self.rp.parse(response.text.splitlines())
            return True
        except requests.RequestException as e:
            print(Fore.RED + f"[{self.current_time()}] Failed to read robots.txt: {e}")
            return False

    def check_important_files(self):
        for file in self.important_files:
            file_url = urljoin(self.base_url, file)
            if self.is_allowed(file_url):
                try:
                    file_response = requests.get(file_url, headers={'User-Agent': 'Mozilla/5.0'})
                    self.record_result(file_url, file_response.status_code)
                except requests.RequestException as e:
                    print(Fore.RED + f"[{self.current_time()}] Error fetching {file_url}: {e}")

    def record_result(self, url, status):
        with self.lock:
            self.results.append({'url': url, 'status': status})
            if status == 200:
                print(Fore.GREEN + f"[{self.current_time()}] Found: {url} (Status: {status})")
            else:
                print(Fore.YELLOW + f"[{self.current_time()}] Not Found: {url} (Status: {status})")

    def crawl(self, url, depth):
        if url in self.visited or depth > self.max_depth:
            return
        if not self.is_allowed(url):
            print(Fore.YELLOW + f"[{self.current_time()}] Blocked by robots.txt: {url}")
            return

        print(Fore.CYAN + f"[{self.current_time()}] Crawling: {url}")
        self.visited.add(url)

        try:
            headers = {'User-Agent': self.user_agents[depth % len(self.user_agents)]}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            print(Fore.RED + f"[{self.current_time()}] Error fetching {url}: {e}")
            return

        # Check for important files
        self.check_important_files()

        # Check for important directories
        for directory in self.important_dirs:
            dir_url = urljoin(self.base_url, directory)
            if self.is_allowed(dir_url):
                try:
                    dir_response = requests.get(dir_url, headers={'User-Agent': 'Mozilla/5.0'})
                    self.record_result(dir_url, dir_response.status_code)
                except requests.RequestException as e:
                    print(Fore.RED + f"[{self.current_time()}] Error fetching {dir_url}: {e}")

        # Parse the page and find links
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            next_url = urljoin(self.base_url, link['href'])
            if next_url.startswith(self.base_url):
                # Start a new thread for each link to crawl concurrently
                threading.Thread(target=self.crawl, args=(next_url, depth + 1)).start()
                time.sleep(self.delay)  # Respect the delay between requests

    def start_crawling(self):
        if self.check_robots_txt():
            try:
                self.crawl(self.base_url, self.current_depth)
            except KeyboardInterrupt:
                print(Fore.RED + f"\n[{self.current_time()}] Crawling stopped by user.")
            finally:
                self.print_summary()
                self.save_results()

    def print_summary(self):
        print(Fore.BLUE + "\nSummary of Results:")
        for result in self.results:
            if result['status'] == 200:
                print(Fore.GREEN + f"[{self.current_time()}] Found: {result['url']} (Status: {result['status']})")
            else:
                print(Fore.YELLOW + f"[{self.current_time()}] Checked: {result['url']} (Status: {result['status']})")

    def save_results(self):
        if self.output_file:
            with open(self.output_file, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=['url', 'status'])
                writer.writeheader()
                writer.writerows(self.results)
            print(Fore.BLUE + f"[{self.current_time()}] Results saved to {self.output_file}")

def main():
    parser = argparse.ArgumentParser(description="WEB-CRAWLER IN CLI MODE (^_^)")
    parser.add_argument('url', type=str, help='Base URL to crawl (e.g., http://example.com)')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum depth to crawl (default: 3)')
    parser.add_argument('--output', type=str, help='Output file to save results (CSV format)')
    parser.add_argument('--user-agents', type=str, nargs='*', default=['Mozilla/5.0'], help='List of user agents to rotate (default: Mozilla/5.0)')
    parser.add_argument('--delay', type=float, default=1.0, help='Delay between requests in seconds (default: 1.0)')
    args = parser.parse_args()

    crawler = WebCrawler(args.url, args.max_depth, args.output, args.user_agents, args.delay)
    crawler.start_crawling()

if __name__ == "__main__":
    main()

