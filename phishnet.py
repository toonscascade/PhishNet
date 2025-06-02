import re
import json
import validators
import requests
from datetime import datetime
from fuzzywuzzy import fuzz
from rapidfuzz import fuzz as rfuzz
from colorama import init, Fore, Style
from typing import Dict, List, Tuple

# Initialize colorama
init()

def print_banner():
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║                                                                ║
║  {Fore.YELLOW}██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███╗   ██╗███████╗████████╗{Fore.CYAN}  ║
║  {Fore.YELLOW}██╔══██╗██║  ██║██║██╔════╝██║  ██║████╗  ██║██╔════╝╚══██╔══╝{Fore.CYAN}  ║
║  {Fore.YELLOW}██████╔╝███████║██║███████╗███████║██╔██╗ ██║█████╗     ██║   {Fore.CYAN}  ║
║  {Fore.YELLOW}██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║╚██╗██║██╔══╝     ██║   {Fore.CYAN}  ║
║  {Fore.YELLOW}██║     ██║  ██║██║███████║██║  ██║██║ ╚████║███████╗   ██║   {Fore.CYAN}  ║
║  {Fore.YELLOW}╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   {Fore.CYAN}  ║
║                                                                ║
║  {Fore.GREEN}URL Phishing Detection Tool{Fore.CYAN}                              ║
║  {Fore.WHITE}Version 1.0{Fore.CYAN}                                             ║
║  {Fore.MAGENTA}Made by ToonsCascade{Fore.CYAN}                                   ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def print_menu():
    menu = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}Available Options:{Fore.CYAN}                                    ║
║                                                                ║
║  {Fore.GREEN}1.{Fore.WHITE} Analyze a URL                                    {Fore.CYAN}║
║  {Fore.GREEN}2.{Fore.WHITE} View Analysis History                            {Fore.CYAN}║
║  {Fore.GREEN}3.{Fore.WHITE} Check for Typosquatting                          {Fore.CYAN}║
║  {Fore.GREEN}4.{Fore.WHITE} About PhishNet+                                  {Fore.CYAN}║
║  {Fore.GREEN}5.{Fore.WHITE} Exit                                            {Fore.CYAN}║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(menu)

def show_about():
    about = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════╗
║  {Fore.WHITE}About PhishNet+{Fore.CYAN}                                      ║
║                                                                ║
║  {Fore.GREEN}Features:{Fore.CYAN}                                            ║
║  • URL analysis for phishing indicators                        ║
║  • Risk scoring system (Low, Medium, High)                     ║
║  • Typosquatting detection                                     ║
║  • Analysis history logging                                    ║
║                                                                ║
║  {Fore.YELLOW}Created for educational purposes{Fore.CYAN}                      ║
║  {Fore.WHITE}Version 1.0{Fore.CYAN}                                          ║
║  {Fore.MAGENTA}Made by ToonsCascade{Fore.CYAN}                                ║
╚════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(about)

def view_history():
    try:
        with open('phishnet_logs.json', 'r') as f:
            logs = json.load(f)
        
        if not logs:
            print(f"\n{Fore.YELLOW}No analysis history found.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Analysis History:{Style.RESET_ALL}")
        print("="*50)
        for log in logs:
            print(f"\nURL: {log['url']}")
            print(f"Risk Level: {log['risk_level']}")
            print(f"Risk Score: {log['risk_score']}/100")
            print(f"Timestamp: {log['timestamp']}")
            print("-"*50)
    except FileNotFoundError:
        print(f"\n{Fore.YELLOW}No analysis history found.{Style.RESET_ALL}")

class PhishNetPlus:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'secure', 'account', 'bank', 'password',
            'confirm', 'update', 'signin', 'signup', 'payment', 'security'
        ]
        self.shortener_domains = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs',
            'ow.ly', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc'
        ]

    def analyze_url(self, url: str) -> Dict:
        """Analyze a URL for potential phishing indicators."""
        if not validators.url(url):
            return {
                'valid_url': False,
                'error': 'Invalid URL format'
            }

        risk_score = 0
        findings = []
        final_url = url

        # Check for redirects
        try:
            response = requests.head(url, allow_redirects=True, timeout=5)
            final_url = response.url
            if final_url != url:
                risk_score += 20
                findings.append(f'URL redirects to: {final_url}')
        except requests.RequestException:
            findings.append('Could not check for redirects')

        # Check for IP address instead of domain
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', final_url):
            risk_score += 30
            findings.append('URL contains IP address instead of domain name')

        # Check for suspicious keywords
        for keyword in self.suspicious_keywords:
            if keyword.lower() in final_url.lower():
                risk_score += 10
                findings.append(f'Contains suspicious keyword: {keyword}')

        # Check for URL shorteners
        for shortener in self.shortener_domains:
            if shortener in final_url:
                risk_score += 25
                findings.append(f'URL is shortened using {shortener}')

        # Check for excessive subdomains
        subdomain_count = final_url.count('.')
        if subdomain_count > 3:
            risk_score += 15
            findings.append(f'Excessive number of subdomains ({subdomain_count})')

        # Determine if suspicious
        is_suspicious = risk_score >= 25

        return {
            'valid_url': True,
            'original_url': url,
            'final_url': final_url,
            'is_suspicious': is_suspicious,
            'risk_score': risk_score,
            'findings': findings,
            'timestamp': datetime.now().isoformat()
        }

    def display_results(self, analysis: Dict) -> None:
        """Display analysis results in a user-friendly format."""
        if not analysis['valid_url']:
            print(f"{Fore.RED}Error: {analysis['error']}{Style.RESET_ALL}")
            return

        print("\n" + "="*50)
        print(f"{Fore.CYAN}PhishNet+ Analysis Results{Style.RESET_ALL}")
        print("="*50)
        
        print(f"\nOriginal URL: {analysis['original_url']}")
        if analysis['original_url'] != analysis['final_url']:
            print(f"Redirected to: {analysis['final_url']}")
        
        if analysis['is_suspicious']:
            print(f"\n{Fore.RED}SUSPICIOUS URL DETECTED!{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}URL appears to be safe{Style.RESET_ALL}")
        
        if analysis['findings']:
            print("\nFindings:")
            for finding in analysis['findings']:
                print(f"• {finding}")
        
        print("\n" + "="*50)

    def log_results(self, analysis: Dict, filename: str = 'phishnet_logs.json') -> None:
        """Log analysis results to a JSON file."""
        try:
            with open(filename, 'r') as f:
                logs = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            logs = []

        logs.append(analysis)

        with open(filename, 'w') as f:
            json.dump(logs, f, indent=4)

def main():
    phishnet = PhishNetPlus()
    
    while True:
        print_banner()
        print_menu()
        
        choice = input(f"\n{Fore.GREEN}Enter your choice (1-5): {Style.RESET_ALL}").strip()
        
        if choice == '1':
            while True:
                url = input(f"\n{Fore.CYAN}Enter URL to analyze: {Style.RESET_ALL}").strip()
                
                # Check if URL is valid
                if not validators.url(url):
                    print(f"\n{Fore.RED}Invalid URL format. Please enter a valid URL (e.g., https://example.com){Style.RESET_ALL}")
                    retry = input(f"{Fore.YELLOW}Would you like to try again? (y/n): {Style.RESET_ALL}").lower()
                    if retry != 'y':
                        break
                    continue
                
                analysis = phishnet.analyze_url(url)
                phishnet.display_results(analysis)
                
                log_choice = input(f"\n{Fore.YELLOW}Would you like to log these results? (y/n): {Style.RESET_ALL}").lower()
                if log_choice == 'y':
                    phishnet.log_results(analysis)
                    print(f"{Fore.GREEN}Results logged successfully!{Style.RESET_ALL}")
                break
                
        elif choice == '2':
            view_history()
            
        elif choice == '3':
            while True:
                url = input(f"\n{Fore.CYAN}Enter URL to check for typosquatting: {Style.RESET_ALL}").strip()
                
                # Check if URL is valid
                if not validators.url(url):
                    print(f"\n{Fore.RED}Invalid URL format. Please enter a valid URL (e.g., https://example.com){Style.RESET_ALL}")
                    retry = input(f"{Fore.YELLOW}Would you like to try again? (y/n): {Style.RESET_ALL}").lower()
                    if retry != 'y':
                        break
                    continue
                
                known_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 'apple.com']
                matches = phishnet.check_typosquatting(url, known_domains)
                
                if matches:
                    print(f"\n{Fore.YELLOW}Potential typosquatting detected:{Style.RESET_ALL}")
                    for domain, similarity in matches:
                        print(f"• Similar to {domain} (Similarity: {similarity}%)")
                else:
                    print(f"\n{Fore.GREEN}No potential typosquatting detected.{Style.RESET_ALL}")
                break
                
        elif choice == '4':
            show_about()
            
        elif choice == '5':
            print(f"\n{Fore.GREEN}Thank you for using PhishNet+! Goodbye!{Style.RESET_ALL}")
            break
            
        else:
            print(f"\n{Fore.RED}Invalid choice. Please try again.{Style.RESET_ALL}")
        
        input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 