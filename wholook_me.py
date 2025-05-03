import whois
import dns.resolver
import socket
from datetime import datetime
from pyfiglet import Figlet
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init()

def generate_banner():
    custom_font = "slant"  # Other options: "block", "script", "doom"
    f = Figlet(font=custom_font)
    banner = f.renderText("WhoLook me?")
    print(Fore.CYAN + banner)
    print(Fore.YELLOW + "WHOIS & DNS Recon Tool".center(70))
    print(Fore.GREEN + "By MD Farhan Uddin Jibon".center(70) + Style.RESET_ALL)
    print("\n")

def get_whois_info(domain):
    """Fetch WHOIS registration data"""
    try:
        print(Fore.MAGENTA + "\n[+] WHOIS Information:" + Style.RESET_ALL)
        w = whois.whois(domain)
        
        # Format dates properly
        def format_date(date):
            if isinstance(date, list):
                return date[0].strftime('%Y-%m-%d %H:%M:%S') if date else "N/A"
            return date.strftime('%Y-%m-%d %H:%M:%S') if date else "N/A"
        
        print(f"Domain: {Fore.BLUE}{w.domain_name}{Style.RESET_ALL}")
        print(f"Registrar: {w.registrar or 'N/A'}")
        print(f"Creation Date: {format_date(w.creation_date)}")
        print(f"Expiration Date: {format_date(w.expiration_date)}")
        print(f"Updated Date: {format_date(w.updated_date)}")
        print(f"Name Servers: {Fore.GREEN}{', '.join(w.name_servers) if w.name_servers else 'N/A'}{Style.RESET_ALL}")
        
    except Exception as e:
        print(Fore.RED + f"[!] WHOIS lookup failed: {e}" + Style.RESET_ALL)

def get_dns_records(domain):
    """Query common DNS records"""
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    print(Fore.MAGENTA + "\n[+] DNS Records:" + Style.RESET_ALL)
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record)
            print(f"\n{Fore.YELLOW}{record} Records:{Style.RESET_ALL}")
            for rdata in answers:
                output = rdata.to_text()
                # Special formatting for MX records
                if record == 'MX':
                    output = f"Priority {rdata.preference} → {rdata.exchange}"
                print(f"→ {Fore.GREEN}{output}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            continue
        except dns.resolver.Timeout:
            print(Fore.RED + f"[!] DNS {record} query timed out" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] DNS {record} lookup error: {e}" + Style.RESET_ALL)

def get_host_info(domain):
    """Comprehensive host information"""
    print(Fore.MAGENTA + "\n[+] Host Information:" + Style.RESET_ALL)
    
    try:
        # Get ALL IP addresses (IPv4 + IPv6)
        ips = set()
        for record_type in ['A', 'AAAA']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                ips.update(rdata.address for rdata in answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
        
        if not ips:
            print(Fore.RED + "[!] No IP addresses found" + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + "IP Addresses:" + Style.RESET_ALL)
            for ip in ips:
                print(f"→ {Fore.GREEN}{ip}{Style.RESET_ALL}")
                # Reverse DNS lookup
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                    print(f"  Reverse DNS: {Fore.CYAN}{hostname}{Style.RESET_ALL}")
                except (socket.herror, socket.timeout):
                    print("  Reverse DNS: Not available")
        
        # Check for CNAME
        try:
            cname = dns.resolver.resolve(domain, 'CNAME')
            print(Fore.YELLOW + f"\nCanonical Name (CNAME): {Fore.GREEN}{cname[0].target}{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass
            
    except dns.resolver.Timeout:
        print(Fore.RED + "[!] DNS query timed out" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[!] Host lookup error: {e}" + Style.RESET_ALL)

def main():
    generate_banner()
    
    domain = input(Fore.YELLOW + "[?] Enter domain (e.g., example.com): " + Style.RESET_ALL).strip()
    
    start_time = datetime.now()
    print(Fore.WHITE + f"\n[~] Scanning {domain} at {start_time}" + Style.RESET_ALL)
    
    get_host_info(domain)
    get_whois_info(domain)
    get_dns_records(domain)
    
    duration = datetime.now() - start_time
    print(Fore.CYAN + f"\n[+] Scan completed in {duration.total_seconds():.2f} seconds" + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user" + Style.RESET_ALL)