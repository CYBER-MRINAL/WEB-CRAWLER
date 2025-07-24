# 🌐 WEB-CRAWLER

An elite, asynchronous, high-performance web crawler built with Python — tailored for penetration testers, bug bounty hunters, and advanced recon workflows. It intelligently discovers hidden files, directories, keywords, and misconfigurations across large websites with speed and stealth.

<p align="center">
  <img src="https://img.shields.io/badge/Built%20With-Python%203.8%2B-blue?style=flat-square" />
  <img src="https://img.shields.io/github/license/cyber-mrinal/web-crawler?style=flat-square" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" />
</p>

---

## ⚙️ Features

- ✅ Asynchronous & concurrent crawling (built with asyncio & aiohttp)
- 🧠 Smart scope control (same domain, subdomains, or full)
- 🔍 Keyword/Regex match on URLs, titles, and HTML
- 📁 Scans sensitive paths & files (e.g. /.env, /admin, /.git)
- 📜 Optional robots.txt ignoring (for authorized scans)
- 🔁 User-agent rotation, delays, retries & URL deduplication
- 📄 Exports results in CSV + JSON (with status, title, match info)
- 🧪 Designed for offensive security use in CI or CLI pipelines
- ☠️ Graceful Ctrl+C stop (saves partial data)

---

## 🚀 Quick Start

1. Clone the repository:

```bash
git clone https://github.com/CYBER-MRINAL/WEB-CRAWLER.git
cd WEB-CRAWLER
````

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the crawler:

```bash
python3 elite_crawler.py https://example.com \
  --max-depth 3 \
  --output scan_results \
  --keywords admin login password \
  --concurrency 20 \
  --delay 0.3 \
  --url-budget 1000
```

---

## 📌 Command-Line Options

| Argument        | Description                                             |
| --------------- | ------------------------------------------------------- |
| url             | Target base URL to crawl                                |
| --max-depth     | How deep to follow links (default: 3)                   |
| --output        | Output file prefix (e.g., results → results.csv, .json) |
| --keywords      | Keywords or regex to trigger alerts (e.g., admin login) |
| --user-agents   | Custom user-agent list                                  |
| --concurrency   | Number of concurrent requests (default: 15)             |
| --delay         | Delay between requests (seconds)                        |
| --url-budget    | Stop after N total URLs crawled                         |
| --domain-scope  | Scope control: same, subdomains, or all                 |
| --ignore-robots | Ignore robots.txt (for authorized targets only)         |

---

<img width="1748" height="989" alt="image" src="https://github.com/user-attachments/assets/c1b0b5ba-b93e-4e67-8586-a0e1b28f9752" />

--- 

## 🎯 Example Use Cases

* ✅ Recon and discovery in bug bounty programs
* 🔍 Internal web asset scanning for exposed secrets
* 🛡️ Red teaming infrastructure enumeration
* 🧪 CI-integrated automated recon scans

---

## 🛠 Tech Stack

* 🐍 Python 3.8+
* ⚙️ aiohttp / asyncio – fast, async HTTP client
* 🧠 BeautifulSoup – HTML parsing
* 🎨 Colorama – CLI colors
* 🧰 argparse – CLI argument parsing

---

## 💡 Tips

* Set User-Agent strings that match your engagement type.
* Rotate proxies for stealth crawling.
* Use --url-budget to avoid infinite loops.
* Use --keywords with regex like 'api\_key|password|token' to find secrets.
* Always scan ethically and with permission.

---

## 📦 Output Format

* results.csv → Contains: url, status, title, hit
* results.json → Full structured output for integration

Example:

```json
[
  {
    "url": "https://example.com/admin",
    "status": 200,
    "title": "Admin Panel",
    "hit": true
  }
]
```

---

## 🧑‍💻 Developer Setup

Install manually without setup script:

```bash
pip install aiohttp beautifulsoup4 colorama
```

Make executable:

```bash
chmod +x elite_crawler.py
./elite_crawler.py https://example.com --max-depth 2 --output scan
```

---

## 🧯 Troubleshooting

| Problem           | Fix                                                                 |
| ----------------- | ------------------------------------------------------------------- |
| ImportError       | Re-run pip install requirements.txt                                 |
| Permission denied | chmod +x elite\_crawler.py                                          |
| Blocked URLs      | Check robots.txt or use --ignore-robots (for authorized scans only) |
| SSL errors        | Add --insecure flag (planned) or verify target cert                 |
| Nothing crawled   | Check base URL syntax and depth / scope limits                      |

---

## 🤝 Community & Support

For discussions, help, or suggestions:

🔗 Telegram Group → [Cyber Mrinal Group](https://t.me/cybermrinalgroup/3)

📬 GitHub Issues → Submit feature requests or bugs

---

## 🛡️ Legal & Ethics Notice

This tool is provided for legal penetration testing, bug bounty research, and authorized reconnaissance.

⚠️ Do not scan any target without explicit permission.

Author is not responsible for misuse of this tool.

---

## 📄 License

MIT License — feel free to modify, reuse, and contribute.

---

Made with 🐍 by [CYBER-MRINAL](https://github.com/CYBER-MRINAL)

