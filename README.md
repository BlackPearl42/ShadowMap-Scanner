# A powerful all-in-one web reconnaissance tool for penetration testers, bug bounty hunters, and security researchers. Detects security misconfigurations, missing headers, sensitive files, backend technologies, CVEs, potential injection points, and more.


# Installation Termux 👉 kali 👉 linux 👍


# Install Recommended

# pkg update && pkg upgrade
# pkg install python
# pkg install nmap
# pkg install tcpdump
# pkg install figlet
# pkg install ruby
# gem install lolcat
# pip install colorama scapy requests
# pip install beautifulsoup4
# pip install geoip2

# note if you have one of those then jump into next 

# pip install -r requirements.txt



# python ShadowMap_Scan_web1.py  -u https://targetsite.com -v

# you may see agent and my exmple python ShadowMap_Scan_web1.py -u target.com --agent "MyCustomAgent/1.0"

# 👆 This helps bypass basic WAFs and fingerprinting.

# python ShadowMap_Scan_web1.py -u target.com --timeout 15
 
# Aggressive Recon with Subdomain Enumeration

# python ShadowMap_Scan_web1.py -u https://target.com --subdomains

# Use Custom Wordlist for Sensitive Files 

# python ShadowMap_Scan_web1.py -u https://target.com --wordlist myfiles.txt

# Ignore SSL Errors (For Self-Signed / Internal Sites) 

# python ShadowMap_Scan_web1.py -u https://internal.target.com --insecure

# Faster Scanning (Lower Delay Between Requests)

# python ShadowMap_Scan_web1.py -u https://target.com --delay 0.1


 
# my suggest Command-Line python ShadowMap_Scan_web1.py -u https://target.com --insecure --delay 1.5 --deep --shodan YOUR_KEY
