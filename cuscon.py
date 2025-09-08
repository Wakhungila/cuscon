#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
import threading
import time
import json
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import string
from pathlib import Path
import re
from datetime import datetime
import yaml

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

class BugBountyRecon:
    def __init__(self):
        self.tools_to_install = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest',
            'amass': 'go install -v github.com/owasp-amass/amass/v4/...@master',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'httprobe': 'go install github.com/tomnomnom/httprobe@latest',
            'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
            'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
            'ffuf': 'go install github.com/ffuf/ffuf/v2@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
            'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
            'getjs': 'go install github.com/003random/getJS@latest',
            'linkfinder': 'pip3 install linkfinder',
            'trufflehog': 'go install github.com/trufflesecurity/trufflehog/v3@latest',
            'arjun': 'pip3 install arjun',
            'gitdumper': 'pip3 install git-dumper',
            'cloudenum': 'pip3 install cloudenum',
            'chaos': 'go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest'
        }
        
        self.wordlists = {
            'directories': [
                'admin', 'administrator', 'api', 'app', 'backup', 'config', 'dev', 'development',
                'test', 'testing', 'stage', 'staging', 'prod', 'production', 'demo', 'beta',
                'alpha', 'tmp', 'temp', 'old', 'new', 'v1', 'v2', 'v3', 'assets', 'static',
                'files', 'uploads', 'download', 'downloads', 'data', 'db', 'database',
                'sql', 'mysql', 'postgres', 'mongo', 'redis', 'cache', 'logs', 'log',
                'archive', 'archives', 'backup', 'backups', 'git', 'svn', 'cvs',
                'vendor', 'node_modules', 'wp-admin', 'wp-content', 'wp-includes',
                'phpmyadmin', 'adminer', 'jenkins', 'gitlab', 'github', 'bitbucket'
            ],
            'sensitive_files': [
                '.env', '.env.local', '.env.production', '.env.staging', '.env.development',
                'config.php', 'config.json', 'config.yaml', 'config.yml', 'settings.py',
                'settings.json', 'web.config', 'app.config', 'database.yml', 'secrets.json',
                '.git/config', '.gitignore', '.gitmodules', '.htaccess', '.htpasswd',
                'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml',
                'backup.sql', 'dump.sql', 'database.sql', 'db.sql', 'users.sql',
                'admin.php', 'login.php', 'dashboard.php', 'panel.php', 'cpanel.php',
                'phpinfo.php', 'info.php', 'test.php', 'debug.php', 'error.log',
                'access.log', 'error_log', 'access_log', 'server.log', 'application.log',
                'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
                'package.json', 'composer.json', 'requirements.txt', 'Gemfile',
                'yarn.lock', 'package-lock.json', 'composer.lock', 'Pipfile.lock'
            ]
        }
        
        self.js_secrets_patterns = {
            'api_keys': [
                r'(?i)(api[_-]?key|apikey|secret|token)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9_\-]{16,})',
                r'(?i)(access[_-]?token|accesstoken)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9_\-]{16,})',
                r'(?i)(auth[_-]?token|authtoken)["\'\s]*[:=]["\'\s]*([a-zA-Z0-9_\-]{16,})'
            ],
            'aws_keys': [
                r'AKIA[0-9A-Z]{16}',
                r'(?i)(aws[_-]?access[_-]?key[_-]?id)["\'\s]*[:=]["\'\s]*([A-Z0-9]{20})',
                r'(?i)(aws[_-]?secret[_-]?access[_-]?key)["\'\s]*[:=]["\'\s]*([A-Za-z0-9/+=]{40})'
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\\-_]{35}',
                r'(?i)(google[_-]?api[_-]?key)["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-]{39})'
            ],
            'slack_tokens': [
                r'xox[baprs]-([0-9a-zA-Z]{10,48})',
                r'(?i)(slack[_-]?token)["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-]{20,})'
            ],
            'github_tokens': [
                r'gh[pousr]_[A-Za-z0-9_]{36}',
                r'(?i)(github[_-]?token)["\'\s]*[:=]["\'\s]*([A-Za-z0-9_\-]{20,})'
            ],
            'discord_webhooks': [
                r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
            ],
            'private_keys': [
                r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
                r'-----BEGIN OPENSSH PRIVATE KEY-----'
            ]
        }

    def print_banner(self):
        banner = f"""
{Colors.CYAN}
██████╗ ██╗   ██╗ ██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝ ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║  ███╗██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
██╔══██╗██║   ██║██║   ██║██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
██████╔╝╚██████╔╝╚██████╔╝██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
{Colors.RESET}
{Colors.YELLOW}Advanced Bug Bounty Reconnaissance Tool v2.0{Colors.RESET}
{Colors.GREEN}Created for Professional Security Researchers{Colors.RESET}
{Colors.BLUE}Author: pin0ccs{Colors.RESET}
"""
        print(banner)

    def check_tools(self):
        print(f"\n{Colors.YELLOW}[+] Checking required tools...{Colors.RESET}")
        missing_tools = []
        
        for tool in self.tools_to_install.keys():
            if not self.is_tool_installed(tool):
                missing_tools.append(tool)
                print(f"{Colors.RED}[-] {tool} not found{Colors.RESET}")
            else:
                print(f"{Colors.GREEN}[+] {tool} found{Colors.RESET}")
        
        if missing_tools:
            print(f"\n{Colors.YELLOW}[!] Installing missing tools...{Colors.RESET}")
            self.install_tools(missing_tools)
        else:
            print(f"\n{Colors.GREEN}[+] All tools are installed!{Colors.RESET}")

    def is_tool_installed(self, tool):
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            return result.returncode == 0
        except:
            return False

    def install_tools(self, tools):
        for tool in tools:
            print(f"{Colors.YELLOW}[+] Installing {tool}...{Colors.RESET}")
            try:
                if tool in ['linkfinder', 'arjun', 'gitdumper', 'cloudenum']:
                    # Use pipx for better isolation on Kali
                    cmd = self.tools_to_install[tool].replace('pip3 install', 'pipx install')
                    if not self.is_tool_installed('pipx'):
                        subprocess.run(['sudo', 'apt', 'install', '-y', 'pipx'], check=True)
                        subprocess.run(['pipx', 'ensurepath'], check=True)
                else:
                    cmd = self.tools_to_install[tool]
                
                subprocess.run(cmd.split(), check=True)
                print(f"{Colors.GREEN}[+] {tool} installed successfully{Colors.RESET}")
            except subprocess.CalledProcessError:
                print(f"{Colors.RED}[-] Failed to install {tool}{Colors.RESET}")
                print(f"{Colors.YELLOW}[!] Please install {tool} manually{Colors.RESET}")

    def create_output_directory(self, domain):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"recon_{domain}_{timestamp}"
        os.makedirs(output_dir, exist_ok=True)
        return output_dir

    def subdomain_enumeration(self, domain, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting subdomain enumeration for {domain}...{Colors.RESET}")
        
        subdomains_file = os.path.join(output_dir, "subdomains.txt")
        all_subdomains = set()
        
        # Subfinder
        print(f"{Colors.YELLOW}[+] Running subfinder...{Colors.RESET}")
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], 
                                  capture_output=True, text=True, timeout=300)
            if result.stdout:
                subfinder_subs = set(result.stdout.strip().split('\n'))
                all_subdomains.update(subfinder_subs)
                print(f"{Colors.GREEN}[+] Subfinder found {len(subfinder_subs)} subdomains{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Subfinder error: {e}{Colors.RESET}")

        # Assetfinder
        print(f"{Colors.YELLOW}[+] Running assetfinder...{Colors.RESET}")
        try:
            result = subprocess.run(['assetfinder', '--subs-only', domain], 
                                  capture_output=True, text=True, timeout=300)
            if result.stdout:
                assetfinder_subs = set(result.stdout.strip().split('\n'))
                all_subdomains.update(assetfinder_subs)
                print(f"{Colors.GREEN}[+] Assetfinder found {len(assetfinder_subs)} subdomains{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Assetfinder error: {e}{Colors.RESET}")

        # Amass
        print(f"{Colors.YELLOW}[+] Running amass (passive)...{Colors.RESET}")
        try:
            result = subprocess.run(['amass', 'enum', '-passive', '-d', domain], 
                                  capture_output=True, text=True, timeout=600)
            if result.stdout:
                amass_subs = set(result.stdout.strip().split('\n'))
                all_subdomains.update(amass_subs)
                print(f"{Colors.GREEN}[+] Amass found {len(amass_subs)} subdomains{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Amass error: {e}{Colors.RESET}")

        # Clean and save subdomains
        clean_subdomains = set()
        for sub in all_subdomains:
            if sub and sub.strip() and '.' in sub:
                clean_subdomains.add(sub.strip().lower())

        with open(subdomains_file, 'w') as f:
            for sub in sorted(clean_subdomains):
                f.write(f"{sub}\n")

        print(f"{Colors.GREEN}[+] Total unique subdomains found: {len(clean_subdomains)}{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Subdomains saved to: {subdomains_file}{Colors.RESET}")
        
        return subdomains_file

    def probe_live_subdomains(self, subdomains_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Probing for live subdomains...{Colors.RESET}")
        
        live_subs_file = os.path.join(output_dir, "live_subdomains.txt")
        
        # Using httpx for better results
        print(f"{Colors.YELLOW}[+] Running httpx...{Colors.RESET}")
        try:
            cmd = ['httpx', '-l', subdomains_file, '-silent', '-status-code', 
                   '-title', '-tech-detect', '-follow-redirects', '-random-agent']
            
            with open(live_subs_file, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            # Count live subdomains
            with open(live_subs_file, 'r') as f:
                live_count = len(f.readlines())
            
            print(f"{Colors.GREEN}[+] Found {live_count} live subdomains{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Live subdomains saved to: {live_subs_file}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] httpx error: {e}{Colors.RESET}")
            
        return live_subs_file

    def web_app_enumeration(self, live_subs_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting web application enumeration...{Colors.RESET}")
        
        webapps_file = os.path.join(output_dir, "web_applications.txt")
        
        # Extract URLs from httpx output
        urls = []
        try:
            with open(live_subs_file, 'r') as f:
                for line in f:
                    if '[' in line and ']' in line:  # httpx format
                        url = line.split()[0]
                        if url.startswith('http'):
                            urls.append(url)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading live subdomains: {e}{Colors.RESET}")
            return webapps_file

        # Detailed web app analysis
        web_apps_data = []
        for url in urls[:50]:  # Limit to prevent overwhelming
            try:
                print(f"{Colors.YELLOW}[+] Analyzing {url}...{Colors.RESET}")
                
                # Basic HTTP analysis
                response = requests.get(url, timeout=10, allow_redirects=True)
                
                app_info = {
                    'url': url,
                    'status_code': response.status_code,
                    'title': self.extract_title(response.text),
                    'server': response.headers.get('Server', 'Unknown'),
                    'technologies': self.detect_technologies(response),
                    'interesting_headers': self.find_interesting_headers(response.headers),
                    'forms': self.find_forms(response.text),
                    'potential_vulns': self.quick_vuln_check(response)
                }
                
                web_apps_data.append(app_info)
                
            except Exception as e:
                print(f"{Colors.RED}[-] Error analyzing {url}: {e}{Colors.RESET}")

        # Save detailed web app information
        with open(webapps_file, 'w') as f:
            for app in web_apps_data:
                f.write(f"\n{'='*80}\n")
                f.write(f"URL: {app['url']}\n")
                f.write(f"Status: {app['status_code']}\n")
                f.write(f"Title: {app['title']}\n")
                f.write(f"Server: {app['server']}\n")
                f.write(f"Technologies: {', '.join(app['technologies'])}\n")
                f.write(f"Interesting Headers: {', '.join(app['interesting_headers'])}\n")
                f.write(f"Forms Found: {app['forms']}\n")
                f.write(f"Potential Issues: {', '.join(app['potential_vulns'])}\n")

        print(f"{Colors.GREEN}[+] Web application analysis saved to: {webapps_file}{Colors.RESET}")
        return webapps_file

    def extract_title(self, html):
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else "No title"

    def detect_technologies(self, response):
        technologies = []
        headers = response.headers
        content = response.text.lower()
        
        # Common technology detection
        if 'x-powered-by' in headers:
            technologies.append(f"Powered by: {headers['x-powered-by']}")
        
        if 'wordpress' in content or 'wp-content' in content:
            technologies.append("WordPress")
        
        if 'drupal' in content:
            technologies.append("Drupal")
        
        if 'joomla' in content:
            technologies.append("Joomla")
        
        if 'react' in content or 'reactjs' in content:
            technologies.append("React")
        
        if 'angular' in content or 'ng-' in content:
            technologies.append("Angular")
        
        if 'vue' in content or 'vuejs' in content:
            technologies.append("Vue.js")
        
        if 'bootstrap' in content:
            technologies.append("Bootstrap")
            
        return technologies

    def find_interesting_headers(self, headers):
        interesting = []
        security_headers = [
            'strict-transport-security', 'content-security-policy', 
            'x-frame-options', 'x-content-type-options', 'x-xss-protection'
        ]
        
        for header in security_headers:
            if header not in headers:
                interesting.append(f"Missing: {header}")
        
        if 'server' in headers:
            interesting.append(f"Server: {headers['server']}")
            
        return interesting

    def find_forms(self, html):
        form_count = len(re.findall(r'<form', html, re.IGNORECASE))
        return f"{form_count} forms found"

    def quick_vuln_check(self, response):
        issues = []
        content = response.text.lower()
        
        # Quick vulnerability indicators
        if 'sql syntax' in content or 'mysql_fetch' in content:
            issues.append("Potential SQL Injection")
        
        if 'notice:' in content or 'warning:' in content or 'fatal error:' in content:
            issues.append("PHP Errors Exposed")
        
        if response.headers.get('server', '').lower().startswith('apache/2.2'):
            issues.append("Outdated Apache Version")
            
        return issues

    def javascript_enumeration(self, live_subs_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting JavaScript enumeration...{Colors.RESET}")
        
        js_files_dir = os.path.join(output_dir, "javascript_files")
        os.makedirs(js_files_dir, exist_ok=True)
        
        # Extract URLs for JS enumeration
        urls = []
        try:
            with open(live_subs_file, 'r') as f:
                for line in f:
                    if '[' in line and ']' in line:
                        url = line.split()[0]
                        if url.startswith('http'):
                            urls.append(url)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading URLs: {e}{Colors.RESET}")
            return

        # Use getJS to find JavaScript files
        print(f"{Colors.YELLOW}[+] Running getJS...{Colors.RESET}")
        js_urls_file = os.path.join(js_files_dir, "js_urls.txt")
        
        all_js_urls = set()
        for url in urls[:20]:  # Limit to prevent overwhelming
            try:
                result = subprocess.run(['getJS', '--url', url, '--complete'], 
                                      capture_output=True, text=True, timeout=60)
                if result.stdout:
                    js_urls = result.stdout.strip().split('\n')
                    all_js_urls.update([js_url for js_url in js_urls if js_url.strip()])
            except Exception as e:
                print(f"{Colors.RED}[-] getJS error for {url}: {e}{Colors.RESET}")

        # Save JS URLs
        with open(js_urls_file, 'w') as f:
            for js_url in sorted(all_js_urls):
                f.write(f"{js_url}\n")

        print(f"{Colors.GREEN}[+] Found {len(all_js_urls)} JavaScript files{Colors.RESET}")

        # Analyze JavaScript files for secrets
        self.analyze_javascript_secrets(all_js_urls, js_files_dir)

    def analyze_javascript_secrets(self, js_urls, output_dir):
        print(f"{Colors.YELLOW}[+] Analyzing JavaScript files for secrets...{Colors.RESET}")
        
        secrets_file = os.path.join(output_dir, "js_secrets.txt")
        endpoints_file = os.path.join(output_dir, "js_endpoints.txt")
        
        found_secrets = []
        found_endpoints = []
        
        for js_url in list(js_urls)[:50]:  # Limit analysis
            try:
                print(f"{Colors.YELLOW}[+] Analyzing {js_url}...{Colors.RESET}")
                response = requests.get(js_url, timeout=10)
                js_content = response.text
                
                # Search for secrets
                for secret_type, patterns in self.js_secrets_patterns.items():
                    for pattern in patterns:
                        matches = re.findall(pattern, js_content, re.IGNORECASE)
                        for match in matches:
                            found_secrets.append({
                                'url': js_url,
                                'type': secret_type,
                                'match': match,
                                'context': self.get_context(js_content, match)
                            })

                # Search for endpoints
                endpoint_patterns = [
                    r'["\']/(api/[^"\']*)["\']',
                    r'["\']/(v\d+/[^"\']*)["\']',
                    r'["\']/(admin/[^"\']*)["\']',
                    r'["\']/(user/[^"\']*)["\']',
                    r'["\']/(auth/[^"\']*)["\']',
                    r'["\']/(login[^"\']*)["\']',
                    r'["\']/(register[^"\']*)["\']',
                    r'["\']/(dashboard[^"\']*)["\']'
                ]
                
                for pattern in endpoint_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for match in matches:
                        found_endpoints.append({
                            'url': js_url,
                            'endpoint': match,
                            'full_url': urljoin(js_url, match)
                        })

            except Exception as e:
                print(f"{Colors.RED}[-] Error analyzing {js_url}: {e}{Colors.RESET}")

        # Save secrets
        with open(secrets_file, 'w') as f:
            f.write("JavaScript Secrets Analysis\n")
            f.write("="*50 + "\n\n")
            for secret in found_secrets:
                f.write(f"URL: {secret['url']}\n")
                f.write(f"Type: {secret['type']}\n")
                f.write(f"Match: {secret['match']}\n")
                f.write(f"Context: {secret['context']}\n")
                f.write("-" * 40 + "\n")

        # Save endpoints
        with open(endpoints_file, 'w') as f:
            f.write("JavaScript Endpoints\n")
            f.write("="*30 + "\n\n")
            for endpoint in found_endpoints:
                f.write(f"Source: {endpoint['url']}\n")
                f.write(f"Endpoint: {endpoint['endpoint']}\n")
                f.write(f"Full URL: {endpoint['full_url']}\n")
                f.write("-" * 40 + "\n")

        print(f"{Colors.GREEN}[+] Found {len(found_secrets)} potential secrets{Colors.RESET}")
        print(f"{Colors.GREEN}[+] Found {len(found_endpoints)} endpoints{Colors.RESET}")

    def get_context(self, content, match, window=50):
        if isinstance(match, tuple):
            match = match[0] if match else ""
        
        try:
            index = content.find(str(match))
            if index != -1:
                start = max(0, index - window)
                end = min(len(content), index + len(str(match)) + window)
                return content[start:end].replace('\n', ' ').strip()
        except:
            pass
        return "Context not available"

    def cloud_asset_discovery(self, domain, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting cloud asset discovery...{Colors.RESET}")
        
        cloud_assets_file = os.path.join(output_dir, "cloud_assets.txt")
        
        # Common cloud storage patterns
        cloud_patterns = {
            'aws_s3': [
                f"{domain}.s3.amazonaws.com",
                f"{domain}-backup.s3.amazonaws.com",
                f"{domain}-dev.s3.amazonaws.com",
                f"{domain}-prod.s3.amazonaws.com",
                f"{domain}-staging.s3.amazonaws.com"
            ],
            'azure_blob': [
                f"{domain}.blob.core.windows.net",
                f"{domain}backup.blob.core.windows.net",
                f"{domain}dev.blob.core.windows.net"
            ],
            'gcp_storage': [
                f"{domain}.storage.googleapis.com",
                f"{domain}-backup.storage.googleapis.com"
            ]
        }
        
        found_assets = []
        
        for platform, urls in cloud_patterns.items():
            print(f"{Colors.YELLOW}[+] Checking {platform} assets...{Colors.RESET}")
            for url in urls:
                try:
                    response = requests.head(f"https://{url}", timeout=10)
                    if response.status_code in [200, 403, 301, 302]:
                        found_assets.append({
                            'platform': platform,
                            'url': url,
                            'status': response.status_code,
                            'accessible': response.status_code == 200
                        })
                        print(f"{Colors.GREEN}[+] Found: {url} (Status: {response.status_code}){Colors.RESET}")
                except:
                    pass

        # Save cloud assets
        with open(cloud_assets_file, 'w') as f:
            f.write("Cloud Asset Discovery Results\n")
            f.write("="*40 + "\n\n")
            for asset in found_assets:
                f.write(f"Platform: {asset['platform']}\n")
                f.write(f"URL: {asset['url']}\n")
                f.write(f"Status: {asset['status']}\n")
                f.write(f"Accessible: {asset['accessible']}\n")
                f.write("-" * 30 + "\n")

        print(f"{Colors.GREEN}[+] Cloud asset discovery completed{Colors.RESET}")

    def directory_fuzzing(self, live_subs_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting directory and file fuzzing...{Colors.RESET}")
        
        fuzzing_dir = os.path.join(output_dir, "fuzzing_results")
        os.makedirs(fuzzing_dir, exist_ok=True)
        
        # Extract base URLs
        urls = []
        try:
            with open(live_subs_file, 'r') as f:
                for line in f:
                    if '[' in line and ']' in line:
                        url = line.split()[0]
                        if url.startswith('http'):
                            urls.append(url)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading URLs: {e}{Colors.RESET}")
            return

        # Create wordlists
        dir_wordlist = os.path.join(fuzzing_dir, "directories.txt")
        files_wordlist = os.path.join(fuzzing_dir, "sensitive_files.txt")
        
        with open(dir_wordlist, 'w') as f:
            for directory in self.wordlists['directories']:
                f.write(f"{directory}\n")
        
        with open(files_wordlist, 'w') as f:
            for file in self.wordlists['sensitive_files']:
                f.write(f"{file}\n")

        # Fuzz directories and files for each URL
        for url in urls[:10]:  # Limit to prevent overwhelming
            print(f"{Colors.YELLOW}[+] Fuzzing {url}...{Colors.RESET}")
            
            # Directory fuzzing with ffuf
            dir_output = os.path.join(fuzzing_dir, f"dirs_{urlparse(url).netloc}.txt")
            try:
                cmd = [
                    'ffuf', '-w', dir_wordlist, '-u', f"{url}/FUZZ",
                    '-mc', '200,204,301,302,307,401,403,405',
                    '-fc', '404', '-t', '50', '-o', dir_output, '-of', 'csv'
                ]
                subprocess.run(cmd, capture_output=True, timeout=300)
            except Exception as e:
                print(f"{Colors.RED}[-] Directory fuzzing error for {url}: {e}{Colors.RESET}")

            # File fuzzing with ffuf
            files_output = os.path.join(fuzzing_dir, f"files_{urlparse(url).netloc}.txt")
            try:
                cmd = [
                    'ffuf', '-w', files_wordlist, '-u', f"{url}/FUZZ",
                    '-mc', '200,204,301,302,307,401,403,405',
                    '-fc', '404', '-t', '30', '-o', files_output, '-of', 'csv'
                ]
                subprocess.run(cmd, capture_output=True, timeout=300)
            except Exception as e:
                print(f"{Colors.RED}[-] File fuzzing error for {url}: {e}{Colors.RESET}")

        print(f"{Colors.GREEN}[+] Fuzzing completed. Results in: {fuzzing_dir}{Colors.RESET}")

    def parameter_discovery(self, live_subs_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting parameter discovery with Arjun...{Colors.RESET}")
        
        params_dir = os.path.join(output_dir, "parameters")
        os.makedirs(params_dir, exist_ok=True)
        
        # Extract URLs
        urls = []
        try:
            with open(live_subs_file, 'r') as f:
                for line in f:
                    if '[' in line and ']' in line:
                        url = line.split()[0]
                        if url.startswith('http'):
                            urls.append(url)
        except Exception as e:
            print(f"{Colors.RED}[-] Error reading URLs: {e}{Colors.RESET}")
            return

        # Run Arjun on each URL
        for url in urls[:15]:  # Limit to prevent overwhelming
            print(f"{Colors.YELLOW}[+] Parameter discovery on {url}...{Colors.RESET}")
            
            params_output = os.path.join(params_dir, f"params_{urlparse(url).netloc}.txt")
            try:
                cmd = ['arjun', '-u', url, '-oT', params_output, '--stable']
                subprocess.run(cmd, capture_output=True, timeout=180)
            except Exception as e:
                print(f"{Colors.RED}[-] Arjun error for {url}: {e}{Colors.RESET}")

        print(f"{Colors.GREEN}[+] Parameter discovery completed{Colors.RESET}")

    def github_secrets_discovery(self, domain, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting GitHub secrets discovery...{Colors.RESET}")
        
        github_dir = os.path.join(output_dir, "github_secrets")
        os.makedirs(github_dir, exist_ok=True)
        
        # Use TruffleHog for comprehensive secret scanning
        print(f"{Colors.YELLOW}[+] Running TruffleHog GitHub scan...{Colors.RESET}")
        
        github_output = os.path.join(github_dir, "github_secrets.json")
        try:
            cmd = [
                'trufflehog', 'github', '--org', domain.split('.')[0],
                '--json', '--no-update'
            ]
            
            with open(github_output, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, 
                                      timeout=600, text=True)
            
            print(f"{Colors.GREEN}[+] GitHub secrets scan completed{Colors.RESET}")
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] GitHub scan timed out{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] TruffleHog error: {e}{Colors.RESET}")

        # Additional GitHub dork searches
        self.github_dork_search(domain, github_dir)

    def github_dork_search(self, domain, output_dir):
        print(f"{Colors.YELLOW}[+] Performing GitHub dork searches...{Colors.RESET}")
        
        # Common GitHub dorks for the domain
        dorks = [
            f'"{domain}" password',
            f'"{domain}" api_key',
            f'"{domain}" secret',
            f'"{domain}" token',
            f'"{domain}" AWS_ACCESS_KEY_ID',
            f'"{domain}" config',
            f'"{domain}" database',
            f'"{domain}" .env',
            f'"{domain}" credentials',
            f'"{domain}" private',
            f'"{domain}" internal',
            f'site:{domain} password',
            f'site:{domain} secret',
            f'site:{domain} api',
            f'extension:json "{domain}"',
            f'extension:yaml "{domain}"',
            f'extension:yml "{domain}"',
            f'extension:conf "{domain}"',
            f'extension:cnf "{domain}"',
            f'extension:cfg "{domain}"',
            f'extension:env "{domain}"'
        ]
        
        dorks_file = os.path.join(output_dir, "github_dorks.txt")
        with open(dorks_file, 'w') as f:
            f.write("GitHub Dork Queries for Manual Investigation\n")
            f.write("="*50 + "\n\n")
            for i, dork in enumerate(dorks, 1):
                f.write(f"{i}. {dork}\n")
                f.write(f"   URL: https://github.com/search?q={dork.replace(' ', '+')}&type=code\n\n")

        print(f"{Colors.GREEN}[+] GitHub dorks saved to: {dorks_file}{Colors.RESET}")

    def wayback_enumeration(self, domain, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting Wayback Machine enumeration...{Colors.RESET}")
        
        wayback_dir = os.path.join(output_dir, "wayback_results")
        os.makedirs(wayback_dir, exist_ok=True)
        
        # Use waybackurls
        print(f"{Colors.YELLOW}[+] Running waybackurls...{Colors.RESET}")
        wayback_file = os.path.join(wayback_dir, "wayback_urls.txt")
        
        try:
            with open(wayback_file, 'w') as f:
                result = subprocess.run(['waybackurls', domain], stdout=f, 
                                      stderr=subprocess.PIPE, timeout=300)
            
            # Count URLs found
            with open(wayback_file, 'r') as f:
                url_count = len(f.readlines())
            
            print(f"{Colors.GREEN}[+] Found {url_count} URLs from Wayback Machine{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Waybackurls error: {e}{Colors.RESET}")

        # Use gau (Get All URLs)
        print(f"{Colors.YELLOW}[+] Running gau...{Colors.RESET}")
        gau_file = os.path.join(wayback_dir, "gau_urls.txt")
        
        try:
            with open(gau_file, 'w') as f:
                result = subprocess.run(['gau', domain], stdout=f, 
                                      stderr=subprocess.PIPE, timeout=300)
            
            # Count URLs found
            with open(gau_file, 'r') as f:
                url_count = len(f.readlines())
            
            print(f"{Colors.GREEN}[+] Found {url_count} URLs from gau{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] gau error: {e}{Colors.RESET}")

        # Analyze URLs for interesting patterns
        self.analyze_wayback_urls(wayback_dir)

    def analyze_wayback_urls(self, wayback_dir):
        print(f"{Colors.YELLOW}[+] Analyzing Wayback URLs for interesting patterns...{Colors.RESET}")
        
        interesting_file = os.path.join(wayback_dir, "interesting_urls.txt")
        
        # Patterns to look for
        interesting_patterns = {
            'admin_panels': [r'/admin', r'/administrator', r'/panel', r'/dashboard', r'/cpanel'],
            'api_endpoints': [r'/api/', r'/v\d+/', r'/rest/', r'/graphql'],
            'config_files': [r'\.env', r'\.config', r'\.yaml', r'\.yml', r'\.json'],
            'sensitive_dirs': [r'/backup', r'/dev', r'/test', r'/staging', r'/prod'],
            'file_uploads': [r'/upload', r'/files', r'/media', r'/assets'],
            'debug_info': [r'/debug', r'/trace', r'/error', r'/log'],
            'git_exposed': [r'\.git/', r'\.svn/', r'\.hg/'],
            'database': [r'/db/', r'/database/', r'/sql/', r'/mysql/']
        }
        
        all_urls = []
        
        # Collect all URLs
        for filename in ['wayback_urls.txt', 'gau_urls.txt']:
            filepath = os.path.join(wayback_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    all_urls.extend(f.readlines())
        
        interesting_finds = {}
        for category, patterns in interesting_patterns.items():
            interesting_finds[category] = []
            for url in all_urls:
                url = url.strip()
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        interesting_finds[category].append(url)
                        break
        
        # Save interesting URLs
        with open(interesting_file, 'w') as f:
            f.write("Interesting URLs from Wayback Analysis\n")
            f.write("="*50 + "\n\n")
            
            for category, urls in interesting_finds.items():
                if urls:
                    f.write(f"\n{category.upper().replace('_', ' ')}:\n")
                    f.write("-" * 30 + "\n")
                    for url in sorted(set(urls))[:20]:  # Limit to 20 per category
                        f.write(f"{url}\n")

        total_interesting = sum(len(urls) for urls in interesting_finds.values())
        print(f"{Colors.GREEN}[+] Found {total_interesting} interesting URLs{Colors.RESET}")

    def nuclei_scanning(self, live_subs_file, output_dir):
        print(f"\n{Colors.BLUE}[+] Starting Nuclei vulnerability scanning...{Colors.RESET}")
        
        nuclei_dir = os.path.join(output_dir, "nuclei_results")
        os.makedirs(nuclei_dir, exist_ok=True)
        
        # Update nuclei templates
        print(f"{Colors.YELLOW}[+] Updating Nuclei templates...{Colors.RESET}")
        try:
            subprocess.run(['nuclei', '-update-templates'], capture_output=True, timeout=120)
        except Exception as e:
            print(f"{Colors.RED}[-] Template update error: {e}{Colors.RESET}")
        
        # Run nuclei scan
        nuclei_output = os.path.join(nuclei_dir, "nuclei_results.txt")
        
        print(f"{Colors.YELLOW}[+] Running Nuclei scan...{Colors.RESET}")
        try:
            cmd = [
                'nuclei', '-l', live_subs_file, '-t', 'cves/',
                '-t', 'exposures/', '-t', 'misconfiguration/',
                '-t', 'vulnerabilities/', '-severity', 'medium,high,critical',
                '-o', nuclei_output, '-v'
            ]
            
            subprocess.run(cmd, capture_output=True, timeout=1800)  # 30 minutes timeout
            
            # Count findings
            if os.path.exists(nuclei_output):
                with open(nuclei_output, 'r') as f:
                    findings = len(f.readlines())
                print(f"{Colors.GREEN}[+] Nuclei found {findings} potential vulnerabilities{Colors.RESET}")
            
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] Nuclei scan timed out{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Nuclei error: {e}{Colors.RESET}")

    def generate_final_report(self, domain, output_dir):
        print(f"\n{Colors.BLUE}[+] Generating comprehensive report...{Colors.RESET}")
        
        report_file = os.path.join(output_dir, "FINAL_REPORT.md")
        
        with open(report_file, 'w') as f:
            f.write(f"# Bug Bounty Reconnaissance Report\n\n")
            f.write(f"**Target Domain:** {domain}\n")
            f.write(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Report Generated by:** Advanced Bug Bounty Recon Tool\n\n")
            
            f.write("## Executive Summary\n\n")
            f.write("This report contains the results of comprehensive reconnaissance performed on the target domain. ")
            f.write("The scanning process included subdomain enumeration, web application analysis, JavaScript analysis, ")
            f.write("parameter discovery, cloud asset discovery, and vulnerability scanning.\n\n")
            
            f.write("## Methodology\n\n")
            f.write("1. **Subdomain Enumeration** - Using Subfinder, Assetfinder, and Amass\n")
            f.write("2. **Live Host Detection** - Using httpx for comprehensive probing\n")
            f.write("3. **Web Application Analysis** - Technology detection and vulnerability assessment\n")
            f.write("4. **JavaScript Analysis** - Secret detection and endpoint discovery\n")
            f.write("5. **Directory/File Fuzzing** - Using ffuf with comprehensive wordlists\n")
            f.write("6. **Parameter Discovery** - Using Arjun for hidden parameter detection\n")
            f.write("7. **Cloud Asset Discovery** - Checking for exposed cloud storage\n")
            f.write("8. **Historical Data** - Wayback Machine enumeration\n")
            f.write("9. **Vulnerability Scanning** - Using Nuclei for known vulnerabilities\n")
            f.write("10. **GitHub Intelligence** - Secret detection and repository analysis\n\n")
            
            # Add file references
            f.write("## Generated Files\n\n")
            for root, dirs, files in os.walk(output_dir):
                for file in files:
                    if file != "FINAL_REPORT.md":
                        rel_path = os.path.relpath(os.path.join(root, file), output_dir)
                        f.write(f"- `{rel_path}`\n")
            
            f.write("\n## Key Areas for Manual Investigation\n\n")
            f.write("### High Priority\n")
            f.write("1. **JavaScript Files** - Review `javascript_files/js_secrets.txt` for exposed secrets\n")
            f.write("2. **Nuclei Results** - Check `nuclei_results/nuclei_results.txt` for vulnerabilities\n")
            f.write("3. **Cloud Assets** - Investigate any accessible cloud storage found\n")
            f.write("4. **Fuzzing Results** - Review discovered directories and files\n\n")
            
            f.write("### Medium Priority\n")
            f.write("1. **Parameter Discovery** - Test discovered parameters for injection vulnerabilities\n")
            f.write("2. **GitHub Intelligence** - Manual review of GitHub dorks\n")
            f.write("3. **Wayback URLs** - Test interesting historical endpoints\n")
            f.write("4. **Web Applications** - Manual testing of identified applications\n\n")
            
            f.write("## Security Recommendations\n\n")
            f.write("1. **Subdomain Management** - Ensure all discovered subdomains are intentional and secure\n")
            f.write("2. **JavaScript Security** - Review and remove any exposed secrets or sensitive information\n")
            f.write("3. **Cloud Security** - Verify proper access controls on cloud assets\n")
            f.write("4. **Web Application Security** - Address any identified vulnerabilities\n")
            f.write("5. **Information Disclosure** - Remove debug information and error messages\n\n")
            
            f.write("## Disclaimer\n\n")
            f.write("This reconnaissance was performed for legitimate security testing purposes. ")
            f.write("All findings should be verified manually before reporting. The tool output ")
            f.write("may contain false positives that require human verification.\n")

        print(f"{Colors.GREEN}[+] Comprehensive report generated: {report_file}{Colors.RESET}")

    def run_full_recon(self, target, is_file=False):
        """Main reconnaissance workflow"""
        try:
            if is_file:
                # If target is a file containing subdomains
                domain = "multiple_domains"
                output_dir = self.create_output_directory("subdomain_list")
                
                print(f"{Colors.GREEN}[+] Processing subdomain list from file: {target}{Colors.RESET}")
                
                # Skip subdomain enumeration, use provided file
                subdomains_file = target
                
                # Probe live subdomains
                live_subs_file = self.probe_live_subdomains(subdomains_file, output_dir)
                
            else:
                # Single domain target
                domain = target
                output_dir = self.create_output_directory(domain)
                
                print(f"{Colors.GREEN}[+] Starting full reconnaissance on: {domain}{Colors.RESET}")
                print(f"{Colors.GREEN}[+] Output directory: {output_dir}{Colors.RESET}")
                
                # 1. Subdomain Enumeration
                subdomains_file = self.subdomain_enumeration(domain, output_dir)
                
                # 2. Probe Live Subdomains
                live_subs_file = self.probe_live_subdomains(subdomains_file, output_dir)
            
            # Continue with common workflow
            # 3. Web Application Enumeration
            self.web_app_enumeration(live_subs_file, output_dir)
            
            # 4. JavaScript Enumeration
            self.javascript_enumeration(live_subs_file, output_dir)
            
            # 5. Directory and File Fuzzing
            self.directory_fuzzing(live_subs_file, output_dir)
            
            # 6. Parameter Discovery
            self.parameter_discovery(live_subs_file, output_dir)
            
            # 7. Cloud Asset Discovery (only for single domain)
            if not is_file:
                self.cloud_asset_discovery(domain, output_dir)
                
                # 8. GitHub Secrets Discovery
                self.github_secrets_discovery(domain, output_dir)
                
                # 9. Wayback Machine Enumeration
                self.wayback_enumeration(domain, output_dir)
            
            # 10. Nuclei Vulnerability Scanning
            self.nuclei_scanning(live_subs_file, output_dir)
            
            # 11. Generate Final Report
            self.generate_final_report(target, output_dir)
            
            print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] RECONNAISSANCE COMPLETED SUCCESSFULLY!{Colors.RESET}")
            print(f"{Colors.GREEN}[+] All results saved in: {output_dir}{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Review the FINAL_REPORT.md for summary and next steps{Colors.RESET}")
            print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}[-] Critical error: {e}{Colors.RESET}")


def main():
    recon = BugBountyRecon()
    recon.print_banner()
    
    parser = argparse.ArgumentParser(
        description="Advanced Bug Bounty Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py -d example.com                    # Single domain scan
  python3 recon.py -l subdomains.txt                 # Subdomain list scan
  python3 recon.py -d example.com --check-tools      # Check tools first
  python3 recon.py -d example.com --install-tools    # Install missing tools
        """
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Target domain (e.g., example.com)')
    group.add_argument('-l', '--list', help='File containing list of subdomains')
    
    parser.add_argument('--check-tools', action='store_true', 
                       help='Check if required tools are installed')
    parser.add_argument('--install-tools', action='store_true',
                       help='Install missing tools automatically')
    
    args = parser.parse_args()
    
    # Check and install tools if requested
    if args.check_tools or args.install_tools:
        recon.check_tools()
        if args.check_tools and not args.install_tools:
            return
    
# Validate target
    if args.domain:
        target = args.domain.lower().strip()
        is_file = False
        
        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]*\.([a-zA-Z]{2,})$', target):
            print(f"{Colors.RED}[-] Invalid domain format: {target}{Colors.RESET}")
            return
            
    elif args.list:
        target = args.list
        is_file = True
        
        # Check if file exists
        if not os.path.isfile(target):
            print(f"{Colors.RED}[-] File not found: {target}{Colors.RESET}")
            return
    
    # Run reconnaissance
    recon.run_full_recon(target, is_file)


if __name__ == "__main__":
    main()
