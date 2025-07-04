#!/usr/bin/env python3
import requests, re, sys, argparse, os, json, time, urllib3, socket
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from requests.exceptions import ConnectionError, Timeout, RequestException # Add these imports
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36'
DEFAULT_WORDLIST = ['robots.txt', '.git/HEAD', 'backup.zip', 'index.php', 'admin/', 'login/', 'README.md', 'sitemap.xml']
DEFAULT_SUBDOMAIN_LIST = ['dev', 'admin', 'test', 'staging', 'beta', 'mail', 'portal', 'vpn', 'api', 'blog']
os.system('clear')
try:
    with open('cve_db.json', 'r') as f:
        CVE_DB = json.load(f)
except:
    CVE_DB = {}

def banner():
    art = r"""
⠀⠀⠀⠀⣠⣶⣶⣶⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣶⣶⣶⣄⠀⠀⠀⠀
⠀⠀⠀⢰⣿⠋⠀⠀⠉⢻⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⠋⠀⠀⠈⣿⣇⣀⠀⠀
⢀⣴⣿⠿⠿⠀⠀⠀⠀⢠⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣇⠀⠀⠀⠀⠛⠛⢿⣷⡄
⢸⣿⠁⠀⠀⠀⠀⠀⠀⢻⣿⣆⠀⠀⠀⠀⠀⠀⢀⣀⣤⣶⣶⣿⣿⣿⣿⣿⡿⠿⠿⠿⣿⣿⣿⣿⣿⣷⣶⣤⣄⡀⠀⠀⠀⠀⠀⢀⣴⣿⠟⠀⠀⠀⠀⠀⠀⠀⣻⣷
⠘⣿⣧⡀⠀⢀⣀⠀⠀⠀⠙⢿⣷⣄⠀⢀⣴⣾⣿⣿⡿⠟⠋⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠿⣿⣿⣷⣦⣀⠀⣠⣿⡟⠁⠀⠀⠀⣠⣀⠀⠀⣠⣿⡏
⠀⠈⠻⢿⡿⠿⢿⣷⣄⠀⠀⠀⠙⣿⣷⣿⣿⠟⠋⠀⠀⣀⣠⣤⣶⣶⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⣤⣀⠀⠀⠉⠻⢿⣿⣿⣿⠋⠀⠀⠀⣠⣾⡿⠿⢿⣿⠿⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠙⢿⣷⣄⣠⣾⣿⡿⠋⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⡀⠀⠙⠿⣿⣿⣦⣠⣾⡿⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⡿⠋⠀⢀⣴⣿⣿⣿⣿⣿⡿⠟⠛⠉⠉⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠿⣿⣿⣿⣿⣿⣦⡀⠀⠘⢿⣿⣿⣏⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣿⠟⠀⠀⣴⣿⣿⣿⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣦⡀⠀⠙⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⠋⠀⢠⣾⣿⣿⣿⣿⠋⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⣿⣄⠀⠈⢿⣿⣷⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣼⣿⣿⠃⠀⣠⣿⣿⣿⣿⣿⣃⣀⣀⣤⣤⣤⣤⣤⠤⠶⠶⠶⠶⠶⠶⠶⠶⠶⠶⠤⣤⣤⣤⣤⣤⣈⣿⣿⣿⣿⣿⣆⠀⠈⢿⣿⣷⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⣿⣿⠇⠀⢠⣿⣿⣿⣿⡿⠛⠉⠉⠉⠀⠀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣀⠀⠀⠉⠉⢻⣿⣿⣿⣿⣆⠀⠈⢿⣿⣧⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣿⡏⠀⢠⣿⣿⣿⣿⣿⠷⠶⠞⠛⠛⠛⠋⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠾⠿⠿⣿⣿⣿⣆⡀⠘⣿⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⡷⠾⠛⠋⠉⠁⠀⢀⣠⣤⣶⡶⠶⠾⠟⠛⠛⠛⠛⠛⠛⠉⠉⠙⠛⠛⠛⠛⡛⠛⠛⠛⠛⡻⠿⠷⠶⢶⣬⠀⠀⠀⠉⠉⠛⠻⠿⣿⣧⠀⠈⠁⠀
⠀⠀⠀⠀⢸⣿⣥⣤⣤⣀⣀⣀⣀⣰⣿⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⣀⣤⣤⣤⣤⠴⢶⣾⣿⠀⠀⠀⠀
⠀⠀⠀⠀⣼⣿⡇⠀⢹⣿⣿⣿⣿⣿⣿⠀⠀⠀⠄⣤⣴⣾⣿⣿⣿⣶⣄⠀⠀⠀⠀⠀⠀⣠⣶⣿⣿⣿⣿⣷⣦⡀⠀⠀⠀⣸⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⣿⣿⡇⠀⢸⣿⣿⣿⣿⣿⣿⡄⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣷⠀⠀⠀⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⠀⠈⣿⣿⣿⣿⣿⣿⣧⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⢰⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣿⡀⠀⢿⣿⣿⣿⣿⣿⣿⣆⠀⢹⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⢠⣿⣿⣿⣿⣿⣿⣿⠁⠀⣾⣿⡿⠀⠀⠀⠀
⠀⠀⠀⠀⠈⣿⣿⡇⠀⠘⣿⣿⣿⣿⣿⣿⣿⣦⠀⠙⢿⣿⣿⣿⣿⣿⠟⠁⠀⣀⣀⡀⠀⠙⠿⣿⣿⣿⣿⡿⠟⠁⣠⣿⣿⣿⣿⣿⣿⣿⡏⠀⢠⣿⣿⠇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢹⣿⣿⡀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠉⠉⠁⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⠀⠈⠉⠀⠀⢀⣼⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⣾⣿⡟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⣿⣿⣷⡀⠀⠻⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣀⠀⠀⠀⠀⠀⠈⠻⠿⠋⠀⠀⠀⠀⠀⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⣸⣿⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⢿⣿⣷⡀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣤⣤⣀⣀⣀⣀⣀⣀⣤⣤⡶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⣼⣿⡿⠁⠀⠀⠀⠀⠀⠀
⠁⠀⠀⠀⠀⠀⠈⠈⢿⣿⣿⣄⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⣸⡏⠉⢻⡟⠛⢻⡋⠉⣿⣀⣸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⢀⣾⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣿⣷⡀⠀⠈⠻⣿⣿⣿⣿⣿⣿⡇⠈⣿⠛⠓⣿⠷⠶⢾⡷⠚⢻⡏⠁⣿⣿⣿⣿⣿⣿⠟⠋⠀⢀⣴⣿⣿⠿⣿⣦⣀⠀⠀⠀⠀⠀⠀
⠀⣠⣶⣿⣷⣶⣴⣿⠟⠁⠈⠻⣿⣿⣶⣄⠀⠀⠙⠻⢿⣿⣿⡷⣴⣯⣀⣀⣿⠀⠀⢘⣇⣄⣄⣿⡴⣿⣿⣿⠿⠋⠁⠀⣀⣶⣿⣿⡿⠁⠀⠈⠻⣿⣶⡿⢿⣶⣄⠀
⢰⣿⠋⠁⠀⠈⠛⠁⠀⠀⢀⣴⣿⠟⢿⣿⣿⣶⣄⡀⠀⠈⠛⢿⡀⠀⠉⠉⠉⠛⠛⠋⠉⠉⠁⠀⢠⡿⠉⠀⠀⣀⣴⣾⣿⣿⠟⠻⣿⣦⡀⠀⠀⠈⠁⠀⠀⠙⣿⡆
⢸⣿⠀⠀⠀⠀⠀⠀⠀⣴⣿⠟⠁⠀⠄⠈⠛⢿⣿⣿⣷⣦⣤⣀⣻⣦⣄⡀⠀⠀⠀⠀⠀⢀⣠⣴⣏⣠⣴⣶⣿⣿⡿⠟⠋⠀⠀⠀⠈⢻⣿⠇⠀⠀⠀⠀⠀⠀⣽⡿
⠈⢿⣷⣦⣤⡆⠀⠀⠀⢸⣿⠀⠀⠀⠀⠐⠀⠀⠈⠙⠛⠿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣿⣿⣿⣿⣿⣿⠿⠟⠋⠁⠀⠀⠀⠀⠀⠀⢠⣿⡏⠀⠀⠀⠀⣶⣶⣾⠿⠃
⠀⠀⠈⠙⣿⣇⠀⠀⣀⣾⣿⠃⠀⠀⠀⠀⠀⠈⠀⠀⡀⠀⠀⠈⠉⠉⠛⠛⠛⠛⠛⠛⠛⠛⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠁⠈⢿⣿⣄⠀⠀⣠⣿⡏⠀⠀⠀
⠀⠀⠀⠀⠈⠻⠿⠿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠂⠀⠀⠀⠀⠠⠀⠀⠙⠻⠿⠿⠿⠋⠀⠀⠀⠀
"""
    print(Fore.MAGENTA + art)
    print(Fore.YELLOW + "[i] WELCOME | TO | ShadowMap-Scan\n")

def fetch_headers(url, ua, timeout, verify_ssl, follow_redirects):
    try:
        res = requests.get(url, headers={'User-Agent': ua}, timeout=timeout, verify=verify_ssl, allow_redirects=follow_redirects)
        res.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        return res
    except ConnectionError:
        print(f"{Fore.RED}[!] Connection error to {url}. Check URL or network connection.")
        return None
    except Timeout:
        print(f"{Fore.RED}[!] Request to {url} timed out after {timeout} seconds.")
        return None
    except RequestException as e:
        print(f"{Fore.RED}[!] Request failed for {url}: {e}")
        return None
    except Exception as e: # Catch any other unexpected errors
        print(f"{Fore.RED}[!] An unexpected error occurred while fetching {url}: {e}")
        return None

def check_security_headers(headers):
    checks = {
        'Content-Security-Policy': 'Prevents XSS & injection.',
        'Strict-Transport-Security': 'Enforces HTTPS.',
        'X-Content-Type-Options': 'Prevents MIME sniffing.',
        'X-Frame-Options': 'Prevents clickjacking.'
    }
    for hdr, impact in checks.items():
        if hdr not in headers:
            severity = 'Critical' if hdr in ['Content-Security-Policy', 'Strict-Transport-Security'] else 'High'
            print(Fore.RED + f"[MISSING] {hdr} ({severity}) - {impact}")
        else:
            print(Fore.GREEN + f"[+] {hdr} Present")
def scan_sensitive_paths(base_url, paths, ua, timeout, verify_ssl, delay, follow_redirects):
    print(Fore.CYAN + "\n[+] Sensitive Files & Directories:")
    for path in paths:
        full_url = urljoin(base_url, path)
        try:
            r = requests.get(full_url, headers={'User-Agent': ua}, timeout=timeout, verify=verify_ssl, allow_redirects=follow_redirects)
            status = r.status_code
            sev = Fore.BLUE + "[INFO]" # Default to INFO

            # Prioritize severity for common sensitive paths
            is_critical_path = any(p in path for p in ['.git', 'admin', 'login', 'backup', 'test'])

            if status == 200:
                if is_critical_path:
                    sev = Fore.RED + "[CRITICAL]"
                else:
                    sev = Fore.GREEN + "[OK]"
            elif status in [403, 401]:
                if is_critical_path:
                    sev = Fore.YELLOW + "[WARNING]" # Path exists but restricted
                else:
                    sev = Fore.BLUE + "[INFO]" # e.g. robots.txt 403
            # 404 remains INFO, other codes INFO

            print(f"{sev} {full_url} (Status: {status})")

            # Handle content display for specific files
            if status == 200:
                if 'robots.txt' in path:
                    print(Fore.WHITE + "--- robots.txt content snippet ---")
                    print(Fore.YELLOW + r.text[:500]) # Display up to 500 chars of content
                    print(Fore.WHITE + "----------------------------------")
                    disallows = re.findall(r'Disallow:\s*(\S+)', r.text, re.I)
                    allows = re.findall(r'Allow:\s*(\S+)', r.text, re.I)

                    if allows:
                        print(Fore.CYAN + "\n[+] Robots.txt Allow Directives:")
                        for a in allows:
                            print(f"    {Fore.GREEN}[Allow] {a}")
                    if disallows:
                        print(Fore.CYAN + "\n[+] Robots.txt Disallow Paths (Testing Accessibility):")
                        for d in disallows:
                            test_url = urljoin(base_url, d)
                            try:
                                deep_r = requests.get(test_url, headers={'User-Agent': ua}, timeout=timeout, verify=verify_ssl, allow_redirects=follow_redirects)
                                deep_status = deep_r.status_code
                                deep_flag = Fore.BLUE + "[INFO]"
                                if deep_status == 200:
                                    deep_flag = Fore.RED + "[CRITICAL]" # Accessible despite Disallow
                                elif deep_status in [403, 401]:
                                    deep_flag = Fore.YELLOW + "[WARNING]" # Exists, but restricted
                                print(f"    {deep_flag} {test_url} (Status: {deep_status})")
                            except ConnectionError:
                                print(f"    {Fore.RED}[ERROR] Connection error for {test_url}")
                            except Timeout:
                                print(f"    {Fore.RED}[ERROR] Timeout for {test_url}")
                            except RequestException as e:
                                print(f"    {Fore.RED}[ERROR] Request failed for {test_url}: {e}")
                            except Exception as e:
                                print(f"    {Fore.RED}[UNKNOWN ERROR] for {test_url}: {e}")
                            time.sleep(delay)

                elif 'README.md' in path or 'sitemap.xml' in path: # Add sitemap.xml content display
                    print(Fore.WHITE + f"--- {path.split('/')[-1]} content snippet ---")
                    print(Fore.YELLOW + r.text[:500]) # Display up to 500 chars of content
                    print(Fore.WHITE + "--------------------------------------")
            time.sleep(delay)
        except ConnectionError:
            print(f"{Fore.RED}[ERROR] Connection error for {full_url}")
        except Timeout:
            print(f"{Fore.RED}[ERROR] Timeout for {full_url}")
        except RequestException as e:
            print(f"{Fore.RED}[ERROR] Request failed for {full_url}: {e}")
        except Exception as e:
            print(f"{Fore.RED}[UNKNOWN ERROR] for {full_url}: {e}")
def detect_waf(headers):
    waf_signatures = {
        'cloudflare': 'Cloudflare',
        'akamai': 'Akamai',
        'incapsula': 'Imperva',
        'sucuri': 'Sucuri',
        'aws': 'AWS WAF'
    }
    for val in headers.values():
        for key, name in waf_signatures.items():
            if key in str(val).lower():
                print(Fore.CYAN + f"[+] WAF/CDN Detected: {name}")
                waf_bypass_tips(name)
                return

def waf_bypass_tips(name):
    print(Fore.YELLOW + f"[i] Potential bypass techniques for {name}:")
    print(Fore.YELLOW + "    - Try direct IP if known")
    print(Fore.YELLOW + "    - Try uncommon ports (8080, 8443)")
    print(Fore.YELLOW + "    - Check for exposed subdomains or legacy hosts")

def cve_match(server_header):
    if not server_header:
        return
    for tech, details in CVE_DB.items():
        pattern = details.get('pattern')
        if pattern and re.search(pattern, server_header, re.I):
            print(Fore.RED + f"[CVE ALERT] {tech} → {details.get('cve')}: {details.get('desc')}")

def guess_backend(headers, url):
    server = headers.get('Server', '').lower()
    if 'php' in server or '.php' in url:
        print(Fore.CYAN + "[+] Backend: PHP → MySQL")
    elif 'asp' in server or '.asp' in url:
        print(Fore.CYAN + "[+] Backend: ASP.NET → MSSQL")
    elif 'jsp' in server or '.jsp' in url:
        print(Fore.CYAN + "[+] Backend: JSP → Java")
    else:
        print(Fore.CYAN + "[+] Backend: Unknown")

def analyze_cookies(cookies):
    if not cookies:
        print(Fore.BLUE + "[i] No cookies found.")
        return
    print(Fore.CYAN + "\n[+] Cookies Found:")
    for cookie in cookies:
        print(Fore.YELLOW + f"  - Name: {cookie.name}")
        print(f"    Value: {cookie.value}")
        print(f"    Domain: {cookie.domain}")
        print(f"    Path: {cookie.path}")
        print(f"    Secure: {'Yes' if cookie.secure else 'No'}")
        print(f"    HttpOnly: {'Yes' if cookie.has_httponly() else 'No'}") # Correct method
        print(f"    SameSite: {cookie.samesite if cookie.samesite else 'None'}") # Correct attribute
        print(f"    Expires: {cookie.expires if cookie.expires else 'Session'}")

def extract_params_forms(url, html):
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a', href=True)
    forms = soup.find_all('form')

    print(Fore.YELLOW + "\n[+] Potential Injection Points:")

    for link in links:
        if '?' in link['href']:
            full_link = urljoin(url, link['href'])
            print(f"    - URL Param: {full_link}")
            print(Fore.RED + f"      sqlmap -u \"{full_link}\" --batch")

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = [i.get('name') for i in form.find_all('input') if i.get('name')]
        print(f"    - Form: {urljoin(url, action)} ({method}) Inputs: {', '.join(inputs)}")
        if method == 'GET':
            print(Fore.RED + f"      sqlmap -u \"{urljoin(url, action)}?param=1\" --batch")
        else:
            dummy_data = '&'.join([f"{inp}=test" for inp in inputs])
            print(Fore.RED + f"      sqlmap -u \"{urljoin(url, action)}\" --data=\"{dummy_data}\" --batch")

def enumerate_subdomains(target_url, wordlist, ua, timeout, verify_ssl, delay):
    print(Fore.CYAN + "\n[+] Subdomain Enumeration (Active Check):")
    parsed_url = urlparse(target_url)
    domain_parts = parsed_url.netloc.split('.')
    
    # More robust base domain extraction
    if len(domain_parts) > 2 and domain_parts[-2] in ['com', 'org', 'net', 'gov', 'edu', 'co'] and len(domain_parts[-1]) <= 3:
        # e.g., for sub.domain.com
        base_domain = '.'.join(domain_parts[-3:])
    elif len(domain_parts) > 1:
        # e.g., for domain.com or sub.domain.org
        base_domain = '.'.join(domain_parts[-2:])
    else:
        base_domain = parsed_url.netloc

    if not base_domain:
        print(Fore.RED + "[!] Could not determine base domain for subdomain enumeration.")
        return []

    found_subdomains = []
    for sub in wordlist:
        subdomain_full = f"{sub}.{base_domain}"
        
        # Try resolving DNS first to minimize HTTP requests to non-existent hosts
        try:
            socket.gethostbyname(subdomain_full) 
        except socket.gaierror:
            # DNS resolution failed, skip this subdomain
            continue 

        # Attempt to connect via HTTPS then HTTP
        found_active_host = False
        for scheme in ['https', 'http']:
            subdomain_url = f"{scheme}://{subdomain_full}"
            try:
                r = requests.head(subdomain_url, headers={'User-Agent': ua}, timeout=timeout, verify=verify_ssl, allow_redirects=True)
                if r.status_code in [200, 301, 302, 403]: # Consider these as "active web host"
                    final_url = r.url # Get the final URL after redirects
                    print(Fore.GREEN + f"    - Found: {final_url} (Status: {r.status_code})")
                    found_subdomains.append(final_url)
                    found_active_host = True
                    break # Stop trying schemes if one is found
            except (ConnectionError, Timeout, RequestException):
                pass # HTTP/HTTPS request failed for this subdomain/scheme
            except Exception as e: # Catch any other unexpected errors during HTTP check
                # print(f"    {Fore.RED}[ERROR] during HTTP check for {subdomain_url}: {e}") # Too verbose
                pass
        
        if not found_active_host:
             # If DNS resolved but no active web server on 80/443 for either http/https
             # print(Fore.BLUE + f"    - Found DNS for {subdomain_full} but no active web server.") # Too verbose
             pass

        time.sleep(delay)
    
    if not found_subdomains:
        print(Fore.BLUE + "[i] No active subdomains found (basic wordlist scan).")
    return found_subdomains


def main():
    parser = argparse.ArgumentParser(description='ShadowMap Web v5.0 Advanced Recon Edition')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('--wordlist', help='Custom wordlist for sensitive paths (default: common list)')
    parser.add_argument('--subdomain-wordlist', help='Custom wordlist for subdomain enumeration (default: common list)')
    parser.add_argument('--timeout', type=int, default=7, help='Request timeout in seconds')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL certificate verification (USE WITH CAUTION)')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds')
    parser.add_argument('--no-redirect', action='store_true', help='Do not follow HTTP redirects')
    parser.add_argument('--subdomains', action='store_true', help='Enable subdomain enumeration')
    args = parser.parse_args()

    url = args.url if args.url.startswith('http') else 'https://' + args.url
    verify_ssl = not args.insecure
    follow_redirects = not args.no_redirect
    
    # Load custom wordlists
    paths_wordlist = DEFAULT_WORDLIST
    if args.wordlist and os.path.isfile(args.wordlist):
        with open(args.wordlist, 'r') as f:
            paths_wordlist = [line.strip() for line in f if line.strip()]

    sub_wordlist = DEFAULT_SUBDOMAIN_LIST
    if args.subdomain_wordlist and os.path.isfile(args.subdomain_wordlist):
        with open(args.subdomain_wordlist, 'r') as f:
            sub_wordlist = [line.strip() for line in f if line.strip()]

    banner()
    
    # Initial request for headers and content
    print(f"\n{Fore.CYAN}[i] Analyzing {url} ...")
    res = fetch_headers(url, USER_AGENT, args.timeout, verify_ssl, follow_redirects)
    if not res:
        print(Fore.RED + "[!] Target unreachable or initial request failed. Aborting scan.")
        sys.exit(1)

    print(Fore.GREEN + "\n[+] HTTP Headers:") # Added newline for better spacing
    for k, v in res.headers.items():
        print(f" - {k}: {v}")

    # IP & DNS section
    print(Fore.CYAN + "\n[+] IP & DNS:")
    ip_address = None
    direct_res = None
    try:
        # Extract hostname correctly without port
        hostname = urlparse(url).netloc.split(':')[0]
        ip_address = socket.gethostbyname(hostname)
        print(f" - Resolved IP: {ip_address}")
        
        print(Fore.YELLOW + "    [i] Attempting direct IP connection (for WAF bypass hints)...")
        try:
            # Send Host header for the actual domain to avoid server rejection
            direct_res = requests.get(f"https://{ip_address}/", headers={'User-Agent': USER_AGENT, 'Host': hostname}, timeout=args.timeout, verify=verify_ssl, allow_redirects=follow_redirects)
            print(Fore.GREEN + f"    [+] Direct IP connection successful (Status: {direct_res.status_code})")
        except ConnectionError:
            print(Fore.BLUE + f"    [i] Direct IP connection failed (Connection Error). Common for WAF protected sites.")
        except Timeout:
            print(Fore.BLUE + f"    [i] Direct IP connection failed (Timeout).")
        except RequestException as e:
            print(Fore.BLUE + f"    [i] Direct IP connection failed ({e}). Common for WAF protected sites.")
        except Exception as e:
            print(Fore.RED + f"    [!] An unexpected error occurred during direct IP check: {e}")
    except socket.gaierror:
        print(Fore.RED + " - Could not resolve IP address for the target domain.")
    except Exception as e:
        print(Fore.RED + f" - An unexpected error occurred during IP/DNS resolution: {e}")
        print(Fore.CYAN + "\n[+] Nmap Suggestions:")
    if ip_address: # Check if ip_address was successfully resolved (i.e., not None)
        print(f" - Target IP for Nmap: {ip_address}")
        # THIS IS THE CRUCIAL LINE: if direct_res is None, the first part of the 'and' (direct_res) will be False, and the second part (direct_res.status_code) will NOT be evaluated, avoiding the error.
        if direct_res and direct_res.status_code in [200, 301, 302, 403]:
            print(Fore.GREEN + f"   [RECOMMENDATION] Use Nmap to scan the origin IP {ip_address} for open ports and services, potentially bypassing WAF/CDN.")
            print(Fore.YELLOW + f"     Example: nmap -p 1-65535 -sV -O {ip_address}")
            print(Fore.YELLOW + f"     Example: nmap -p 80,443,8080,8443 --script http-headers {ip_address}")

        else:
            print(Fore.BLUE + f"   [INFO] Direct IP connection did not yield a conclusive web server response. Nmap scans on {ip_address} might hit the WAF/CDN.")
            print(Fore.YELLOW + f"     Example: nmap -p 80,443 --script http-waf-detect {ip_address}") # Nmap WAF script
            print(Fore.YELLOW + "     Consider using Nmap with DNS brute-forcing scripts if WAF is active.")
    else:
        print(Fore.BLUE + " - IP address not resolved, Nmap might need domain name or manual IP.")



    detect_waf(res.headers)
    cve_match(res.headers.get('Server', '')) # Ensure CVE_DB is populated for this to work
    guess_backend(res.headers, url)
    analyze_cookies(res.cookies)

    print(Fore.CYAN + "\n[+] Security Headers Check:")
    check_security_headers(res.headers)

    scan_sensitive_paths(url, paths_wordlist, USER_AGENT, args.timeout, verify_ssl, args.delay, follow_redirects)

    print(Fore.CYAN + "\n[+] Page Content Analysis & Potential Injection Points:") # Renamed section for clarity
    extract_params_forms(url, res.text)
    
    if args.subdomains:
        enumerate_subdomains(url, sub_wordlist, USER_AGENT, args.timeout, verify_ssl, args.delay)
    
    print(Fore.GREEN + "\n[i] Recon Complete.")
    print(Fore.RED + """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠚⢁⢼⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠞⢁⣼⡯⠋⠀⠀⢀⣀⠀⠀⠀⠤⣤⣄⣀⡀⠀⣀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣎⣠⡾⢋⡝⣀⠔⠚⠉⠁⠀⠀⠉⠉⠉⠉⠉⠁⠀⠉⠙⠛⠶⢤⣀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠾⠛⡷⠊⢀⣼⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡴⠚⠁⣠⣾⣥⡶⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢦
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⡯⠖⣲⣯⣥⣾⡟⠀⠀⠀⠀⡤⠀⢠⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠞⢋⡡⠔⢊⣥⡿⠛⡉⡽⢁⣾⣆⢠⡇⠀⢸⣿⣿⣷⣶⣶⣶⣿⡆⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡠⠋⢹⡿⡅⢀⠴⢋⣼⢀⠎⣠⣧⣾⣿⣿⠉⠀⠀⣿⣿⣿⣿⣿⣯⡠⠾⠷⠶⣦⣤⣸⣏⡀⠈⣇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡠⠊⠀⡴⠋⢀⣽⣁⡴⠋⢈⠏⢠⣿⣿⣿⡿⠃⠀⠀⠀⠈⠹⠟⠋⠉⠁⠀⠀⠀⠀⠀⠹⣤⠙⣧⠀⠈⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡞⠀⣠⠞⠶⡾⠋⠁⢉⡤⠒⠁⠀⡸⢿⣤⠻⣿⣦⡀⠀⣴⣶⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⠏⠀⠀⠀⠀⠀⠀
⠀⠀⠀⡀⠀⡠⢿⣡⣶⣋⣠⠞⠡⡔⠊⠁⠀⠀⠀⣼⠇⠈⢲⣿⣿⡿⣿⣶⠏⠉⠀⠀⠀⠀⠀⣀⣴⣶⣾⢻⣿⣿⣿⣤⣀⠀⠀⠀⠀⠀
⠀⢠⠏⠉⠾⢄⣀⣿⡛⢪⡡⠤⠖⠃⠀⠀⠀⠀⠐⢿⠀⠀⠀⠘⠸⠟⠚⠉⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⠇⠸⠿⣻⣿⣿⣿⣿⡀⠀⠀⠀
⣠⢿⠀⠀⢀⣴⡏⠁⡹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠢⣤⣶⠀⠀⠀⠀⠀⡄⢠⠀⡀⠀⢸⣿⣿⡿⠉⠀⠀⢠⣿⣿⣿⠏⢹⠁⠀⠀⠀
⣡⠏⢀⡴⠋⡽⢂⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⢁⠀⣇⣸⣶⡷⢼⣴⢿⣤⣾⣿⣿⠁⠀⠀⢀⣽⣿⣿⡇⠀⠀⠀⠀⢀⣰
⢃⣴⠏⢀⡜⣠⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡾⡏⠹⢨⠅⠧⠰⠃⠈⠻⠿⠛⠁⠀⣠⠖⠉⣿⣿⡟⢳⣶⣾⠿⠟⠛⠁
⠟⠁⣠⣿⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡇⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡜⠁⢀⣴⣿⡿⠃⢀⡇⠀⠀⠀⠀⠀
⢔⣾⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣴⣿⡿⠿⠟⠛⣿⣯⠭⢄⣀⣀⠀⠀⠀
⡾⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⡇⠀⠀⢀⣠⣴⠶⠾⠿⣿⣿⡿⠁⠀⠀⣀⠠⢬⠥⢤⣀⣀⡠⠬⠟⠂⠀
⠕⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⠀⢠⣟⣣⣀⡴⠋⠉⠉⣽⠦⣄⡀⢀⣀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠉⠀⣸⡄⢀⣰⣾⠿⣤⡾⠋⠀⠤⠟⠂⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⣤⡜⠢⢤⣀⠈⠛⣻⠉⢩⣿⣿⣟⣀⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠴⣴⣖⣶⡚⠉⠻⠷⣤⠔⠂⣸⠮⠳⣄⠀⠈⠑⣶⣿⠗⠚⠛⣋⣠⡌⠉⠙⢿⠆⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⣾⣿⣿⣿⠛⢿⣦⡈⠁⠀⣾⡁⠀⠀⠈⠳⣤⣄⢸⣁⣀⡴⠚⠹⣶⢤⣄⡀⣀⣹⣤⠤⠤
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⢸⡉⠂⢸⣈⢣⣠⣀⠈⢻⣏⠉⠓⠲⠦⣄⡀⣏⠉⠀⣤⡀⣀⣨⠿⠛⠛⠛⠲⠤⢄""") 

if __name__ == '__main__':
    main()
