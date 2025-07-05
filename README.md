# ShadowMap Web : Advanced Reconnaissance Tool


## ✨ Features

* **HTTP/HTTPS Header Analysis:** Detailed examination of server responses, including content types, caching, and custom headers.
* **Security Header Checks:** Identifies missing or misconfigured security headers like Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, and X-Frame-Options.
* **WAF/CDN Detection:** Automatically detects Web Application Firewalls (WAFs) and Content Delivery Networks (CDNs) like Cloudflare.
* **IP & Direct Connection Testing:** Resolves the target IP and attempts direct connections for potential WAF bypass strategies.
* **Intelligent Nmap Suggestions:** Provides Nmap scanning recommendations based on WAF detection and direct IP connectivity.
* **`robots.txt` Deep Analysis:** Fetches, parses, and tests `Disallow` directives in `robots.txt` for accessible sensitive paths.
* **Sensitive File & Directory Scanning:** Scans for common sensitive files (e.g., `.git/HEAD`, `backup.zip`, `sitemap.xml`) and directories (e.g., `/admin`, `/login`).
* **Page Content Analysis:** Extracts snippets of `README.md` content and identifies potential injection points in forms.
* **Subdomain Enumeration:** Discovers subdomains related to the target domain.
* **Customizable Scans:** Supports custom wordlists for sensitive path and subdomain enumeration, along with adjustable timeouts and delays.
* **User-Friendly Output:** Utilizes `colorama` for clear, color-coded output, making results easy to read and understand.
* **Optimized for Stealth & Speed:** Designed to minimize noise and rapidly gather information, enhancing evasion against common detection mechanisms

## 🚀 Installation (Termux/Linux)

To get ShadowMap up and running on your Termux (Android) or Linux environment, follow these steps:

1.  **Install Python and Git:**
    ```bash
    pkg update && pkg upgrade -y
    pkg install python git -y
    ```

2.  **Clone the Repository:**
    Use `git clone` to download the tool to your device:
    ```bash
    git clone https://github.com/BlackPearl42/ShadowMap-Scanner.git 
    ```

3.  **Navigate to the Tool's Directory:**
    ```bash
    cd ShadowMap-Scanner
    ```

4.  **Install Required Python Libraries:**
    ShadowMap depends on a few Python packages. Install them using `pip`:
    ```bash
    pip install -r requirements.txt

### Installation on Kali Linux

1.  **Update and Upgrade System Packages:**
    ```bash                                                               sudo apt update && sudo apt upgrade -y
    sudo apt update && sudo apt upgrade -y
    ```
2.  **Install Python3 and Git:**
    Kali Linux usually comes with Python3, but it's good to ensure it's up-to-date along with Git.
    ```bash
    sudo apt install python3 python3-pip git -y
    ```
3.  **Clone the Repository:**
    ```bash
    git clone https://github.com/BlackPearl42/ShadowMap-Scanner.git
    ```
4.  **Navigate to the Tool's Directory:**
    ```bash
    cd ShadowMap-Scanner
    ```
5.  **Install Required Python Libraries:**
    ```bash
    pip install -r requirements.txt
    ```    ```

## 💡 Usage

Run ShadowMap from your terminal. Use the `-h` flag for help:

```bash
python ShadowMap_Scan_web1.py -h

Basic Scan:

python ShadowMap_Scan_web1.py -u [https://example.com](https://example.com)

Comprehensive Scan (Recommended):

python ShadowMap_Scan_web1.py -u [https://example.com](https://example.com) --timeout 15 --no-redirect --insecure --delay 1.5 --deep
Custom Wordlist for Sensitive Paths:


Custom Wordlist for Sensitive Paths:

python ShadowMap_Scan_web1.py -u [https://example.com](https://example.com) --wordlist my_custom_paths.txt

Subdomain Enumeration:

python ShadowMap_Scan_web1.py -u [https://example.com](https://example.com) --subdomains --subdomain-wordlist my_subdomains.txt

Ignoring SSL Errors (for self-signed certs or internal sites):


python ShadowMap_Scan_web1.py -u [https://internal-target.com](https://internal-target.com) --insecure


💖 Support My first The Project

If you find ShadowMap useful and would like to support its continued development, any contributions are greatly appreciated!

Bitcoin (BTC) Wallet Address:

bc1q3k9pkq8qxzzqq3axxew0r7g9wswr9madcrypt25

Thank you for your support!```

## By the way this whole thing made by Android/Termux hehe because i dont have pc or laptop but it took from me almost 10h 🫠 but i enjoy solve every problem 

