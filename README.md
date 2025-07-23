# 🌐 Web Crawler

A simple and efficient web crawler written in **Python**. This tool allows you to crawl websites, check for important files and directories, and save the results in a CSV format. It respects the `robots.txt` file and can be customized with different user agents and request delays.

## 🛠️ Technologies Used

- **Programming Language**: [Python](https://www.python.org/)
- **Libraries**:
  - [Requests](https://docs.python-requests.org/en/latest/): For making HTTP requests.
  - [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/): For parsing HTML and XML documents.
  - [Colorama](https://pypi.org/project/colorama/): For colored terminal text.
  - [argparse](https://docs.python.org/3/library/argparse.html): For parsing command-line arguments.
  - [robotparser](https://docs.python.org/3/library/urllib.robotparser.html): For checking `robots.txt` rules.

## 🚀 Features

- **Crawl Websites**: Explore websites up to a specified depth.
- **Check Important Files**: Identify critical files and directories.
- **Respect `robots.txt`**: Adhere to web crawling rules.
- **User Agent Rotation**: Customize user agents for requests.
- **CSV Output**: Save results in a structured CSV format.

## 📦 Installation

Follow these steps to install the web crawler:

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/CYBER-MRINAL/WEB-CRAWLER.git
   cd web-crawler
   ```

2. **Run the Installer**:

   Make the setup script executable and run it:

   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

   This will install all necessary dependencies and set up the web crawler as a system command.

## 🛠️ Usage

After installation, you can run the web crawler from the command line:

```bash
web-crawler <url> --max-depth <depth> --output <output_file> --user-agents <user_agents> --delay <delay>
```

### 📋 Example

To crawl `http://example.com` with a maximum depth of `2` and save results to `results.csv`:

```bash
web-crawler http://example.com --max-depth 2 --output results.csv
```

## 🛠️ Troubleshooting

- **Missing Dependencies**: If you encounter errors related to missing libraries, ensure that you have installed all required packages. You can run the installer script again to check for any missing dependencies.
  
- **Permission Denied**: If you receive a permission error when running the crawler, ensure that you have the necessary permissions to access the target URL and that the script is executable.

- **Blocked by `robots.txt`**: If the crawler is blocked from accessing certain URLs, check the `robots.txt` file of the target website to see if your user agent is allowed to crawl those pages.

- **Connection Errors**: If you experience connection issues, verify your internet connection and ensure that the target website is online.

## 🤝 Support

For any issues or questions regarding the tool, feel free to join our Telegram group: [Cyber Mrinal Group](https://t.me/cybermrinalgroup/3). We’re here to help!

## 📄 License

This project is licensed under the MIT License.

---

For questions or feedback, reach out on GitHub: [CYBER-MRINAL](https://github.com/CYBER-MRINAL).
