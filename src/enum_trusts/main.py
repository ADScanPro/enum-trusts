#!/usr/bin/env python3

import argparse
import subprocess
import re
from collections import defaultdict
import sys
import os.path

class TrustEnumerator:
    def __init__(self, domain, username, password, pdc, hashes=None):
        self.initial_domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.initial_pdc = pdc
        self.debug = False
        
        # Tracking structures
        self.seen_domains = set()
        self.domains_to_process = []
        self.trust_relationships = defaultdict(list)
        self.domain_controllers = {}
        
        # Save the initial DC
        self.domain_controllers[domain] = pdc
        # The initial PDC will be used as our DNS server
        self.dns = pdc

    def get_domain_trusts(self, domain):
        """Gets the trust relationships for a domain using netexec"""
        try:
            dc_ip = self.domain_controllers[domain]
            
            # Check if the specific netexec path exists
            netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
            nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
            
            # Build the command conditionally based on whether a hash or password is used
            command = [
                nxc_cmd, 'ldap', dc_ip,
                '-u', self.username,
            ]
            if self.hashes:
                command.extend(['-H', self.hashes])
            else:
                command.extend(['-p', self.password])
            command.extend(['-d', self.initial_domain, '--dc-list'])
            
            if self.debug:
                print(f"[DEBUG] Executing command: {' '.join(command)}")
            
            proc = subprocess.run(command, capture_output=True, text=True)
            
            if proc.returncode == 0:
                trusts = []
                for line in proc.stdout.splitlines():
                    if "->" in line:
                        trust_info = self.parse_trust_line(line)
                        if trust_info:
                            trusts.append(trust_info)
                            if self.debug:
                                print(f"[DEBUG] Found trust relationship: {trust_info}")
                return trusts
            else:
                if self.debug:
                    print(f"[DEBUG] Error in netexec: {proc.stderr}")
                return []
                
        except Exception as e:
            print(f"[-] Error obtaining trusts for {domain}: {str(e)}")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return []

    def get_domain_trusts_old(self, domain):
        """Gets the trust relationships for a domain using netexec"""
        try:
            dc_ip = self.domain_controllers[domain]

            # Check if the specific netexec path exists
            netexec_path = "/root/.adscan/tool_venvs/netexec/venv/bin/nxc"
            nxc_cmd = netexec_path if os.path.exists(netexec_path) else 'nxc'
            
            # Build the command conditionally based on whether a hash or password is used
            command = [
                nxc_cmd, 'ldap', dc_ip,
                '-u', self.username,
            ]
            if self.hashes:
                command.extend(['-H', self.hashes])
            else:
                command.extend(['-p', self.password])
            command.extend(['-d', self.initial_domain, '-M', 'enum_trusts'])
            
            if self.debug:
                print(f"[DEBUG] Executing command: {' '.join(command)}")
            
            proc = subprocess.run(command, capture_output=True, text=True)
            
            if proc.returncode == 0:
                trusts = []
                for line in proc.stdout.splitlines():
                    if "ENUM_TRUSTS" in line and "->" in line:
                        trust_info = self.parse_trust_line(line)
                        if trust_info:
                            trusts.append(trust_info)
                            if self.debug:
                                print(f"[DEBUG] Found trust relationship: {trust_info}")
                return trusts
            else:
                if self.debug:
                    print(f"[DEBUG] Error in netexec: {proc.stderr}")
                return []
                
        except Exception as e:
            print(f"[-] Error obtaining trusts for {domain}: {str(e)}")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return []

    def parse_trust_line(self, line):
        """Parses a netexec output line to extract trust information"""
        try:
            # Si no hay flecha, no es una línea de trust
            if '->' not in line:
                return None

            # Dividimos toda la línea por '->'
            parts = [p.strip() for p in line.split('->')]
            # Debemos tener al menos 2 '->' para tener partner, direction y type
            if len(parts) < 3:
                return None

            # 'parts[0]' contiene todo lo anterior a la primera flecha.
            # El dominio (partner) es la última palabra antes de esa flecha:
            left = parts[0]
            tokens = left.split()
            if not tokens:
                return None

            # La última palabra puede llevar ':' al final; la quitamos
            partner = tokens[-1].rstrip(':')

            # Dirección y tipo vienen en parts[1] y parts[2]
            direction = parts[1]
            trust_type = parts[2]

            return {
                'partner': partner,
                'direction': direction,
                'type': trust_type
            }

        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error parsing trust line: {line}")
                print(f"[DEBUG] Error: {str(e)}")
            return None

    def find_domain_controller(self, domain):
        """
        Finds the PDC of a domain using nslookup.
        Returns the IP of the PDC if found, otherwise None.
        """
        try:
            # Query SRV to find the PDC
            pdc_query = f"nslookup -type=srv _ldap._tcp.pdc._msdcs.{domain} {self.dns}"
            result = subprocess.run(pdc_query, shell=True, capture_output=True, text=True)
            
            # Look for the PDC hostname
            pdc_hostname_match = re.search(r"service = \d+ \d+ \d+ ([\w.-]+)", result.stdout)
            
            if pdc_hostname_match:
                # Get the hostname without the domain
                pdc_hostname = pdc_hostname_match.group(1).split('.')[0]
                
                # Resolve the IP of the PDC
                ip_query = f"nslookup {pdc_hostname}.{domain} {self.dns}"
                ip_result = subprocess.run(ip_query, shell=True, capture_output=True, text=True)
                
                # Extract the IP
                ip_matches = re.findall(r"Address:\s+([\d.]+)", ip_result.stdout)
                if ip_matches:
                    pdc_ip = ip_matches[-1]
                    if self.debug:
                        print(f"[DEBUG] PDC found for {domain}:")
                        print(f"[DEBUG] Hostname: {pdc_hostname}")
                        print(f"[DEBUG] IP: {pdc_ip}")
                    return pdc_ip
            
            return None
            
        except Exception as e:
            print(f"[-] Error searching for DC for {domain}: {str(e)}")
            return None

    def enumerate_trusts(self):
        """Main entry point for recursive trust enumeration"""
        print(f"\n[*] Starting trust enumeration from {self.initial_domain}")
        if self.hashes:
            print(f"[*] Using credentials (NTLM hash): {self.username}@{self.initial_domain}")
        else:
            print(f"[*] Using credentials: {self.username}@{self.initial_domain}")
        print(f"[*] Initial PDC: {self.initial_pdc}\n")
        
        self.domains_to_process.append(self.initial_domain)
        
        while self.domains_to_process:
            current_domain = self.domains_to_process.pop()
            
            if current_domain in self.seen_domains:
                continue
                
            print(f"[+] Processing domain: {current_domain}")
            self.seen_domains.add(current_domain)
            
            if current_domain not in self.domain_controllers:
                dc = self.find_domain_controller(current_domain)
                if not dc:
                    print(f"[-] Could not find a DC for {current_domain}")
                    continue
                self.domain_controllers[current_domain] = dc
                if self.debug:
                    print(f"[DEBUG] Found DC for {current_domain}: {dc}")
            
            trusts = self.get_domain_trusts(current_domain)
            
            if trusts:
                for trust in trusts:
                    try:
                        if 'partner' not in trust:
                            continue
                        self.trust_relationships[current_domain].append(trust)
                        target_domain = trust['partner']
                        if target_domain not in self.seen_domains:
                            self.domains_to_process.append(target_domain)
                    except KeyError as e:
                        if self.debug:
                            print(f"[DEBUG] Error processing trust: {str(e)}")
                        continue

    def print_results(self):
        """Prints a summary of all found trust relationships"""
        print("\n" + "="*60)
        print("SUMMARY OF FOUND TRUST RELATIONSHIPS")
        print("="*60)
        
        if not self.trust_relationships:
            print("\n[-] No trust relationships found.")
            print("\nDomains processed:", len(self.seen_domains))
            return
        
        for domain in self.trust_relationships:
            print(f"\nDomain: {domain}")
            print("-" * (len(domain) + 8))
            
            if not self.trust_relationships[domain]:
                print("  No trust relationships found")
                continue
                
            for trust in self.trust_relationships[domain]:
                print(f"  → Trusted Domain: {trust['partner']}")
                print(f"    Address: {trust.get('direction', 'Not specified')}")
                print(f"    Type: {trust.get('type', 'Not specified')}")
        
        print("\nDomains processed:", len(self.seen_domains))
        print("Domains with trust relationships:", len(self.trust_relationships))

def main():
    parser = argparse.ArgumentParser(
        description='Recursively enumerates Active Directory domain trust relationships.'
    )
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=False, help='Password')
    parser.add_argument('-H', '--hashes', required=False, help='NTLM hash for authentication')
    parser.add_argument('-d', '--domain', required=True, help='Initial domain name')
    parser.add_argument('-pdc', '--pdc', required=True, help='Primary Domain Controller IP')
    parser.add_argument('--debug', action='store_true', help='Enable debug messages')
    
    args = parser.parse_args()

    # Validation: either password or hash must be provided
    if not args.password and not args.hashes:
        parser.error("You must specify either the password (-p/--password) or the NTLM hash (-H/--hashes) for authentication.")

    enumerator = TrustEnumerator(args.domain, args.username, args.password, args.pdc, hashes=args.hashes)
    enumerator.debug = args.debug
    
    try:
        enumerator.enumerate_trusts()
        enumerator.print_results()
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by the user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        if args.debug:
            import traceback
            print(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()