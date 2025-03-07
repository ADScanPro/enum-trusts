#!/usr/bin/env python3

import argparse
import subprocess
import re
from collections import defaultdict
import sys

class TrustEnumerator:
    def __init__(self, domain, username, password, pdc, hashes=None):
        self.initial_domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.initial_pdc = pdc
        self.debug = False
        
        # Estructuras para seguimiento
        self.seen_domains = set()
        self.domains_to_process = []
        self.trust_relationships = defaultdict(list)
        self.domain_controllers = {}
        
        # Guardamos el DC inicial
        self.domain_controllers[domain] = pdc
        # El PDC inicial será nuestro servidor DNS
        self.dns = pdc

    def get_domain_trusts(self, domain):
        """Obtiene las relaciones de confianza para un dominio usando netexec"""
        try:
            dc_ip = self.domain_controllers[domain]
            
            # Construimos el comando de forma condicional según si se usa hash o contraseña
            command = [
                'nxc', 'ldap', dc_ip,
                '-u', self.username,
            ]
            if self.hashes:
                command.extend(['-H', self.hashes])
            else:
                command.extend(['-p', self.password])
            command.extend(['-d', self.initial_domain, '-M', 'enum_trusts'])
            
            if self.debug:
                print(f"[DEBUG] Ejecutando comando: {' '.join(command)}")
            
            proc = subprocess.run(command, capture_output=True, text=True)
            
            if proc.returncode == 0:
                trusts = []
                for line in proc.stdout.splitlines():
                    if "ENUM_TRUSTS" in line and "->" in line:
                        trust_info = self.parse_trust_line(line)
                        if trust_info:
                            trusts.append(trust_info)
                            if self.debug:
                                print(f"[DEBUG] Encontrada relación de confianza: {trust_info}")
                return trusts
            else:
                if self.debug:
                    print(f"[DEBUG] Error en netexec: {proc.stderr}")
                return []
                
        except Exception as e:
            print(f"[-] Error obteniendo confianzas para {domain}: {str(e)}")
            if self.debug:
                import traceback
                print(traceback.format_exc())
            return []

    def parse_trust_line(self, line):
        """Parsea una línea de salida de netexec para extraer información de confianza"""
        try:
            # Buscamos el patrón: dominio -> dirección -> tipo
            if ' -> ' not in line:
                return None
            
            # Extraer la parte después de ENUM_TRUSTS que contiene la información
            trust_info = line.split('ENUM_TRUSTS')[-1]
            trust_parts = [part.strip() for part in trust_info.split('->')]
            
            # Encontrar el dominio (buscamos algo que termine en .local)
            domain_match = re.search(r'(\S+\.local)', trust_parts[0])
            if not domain_match:
                return None
            
            partner = domain_match.group(1)
            direction = trust_parts[1].strip()
            trust_type = trust_parts[2].strip()
            
            return {
                'partner': partner,
                'direction': direction,
                'type': trust_type
            }
            
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error parseando línea de confianza: {line}")
                print(f"[DEBUG] Error: {str(e)}")
            return None

    def find_domain_controller(self, domain):
        """
        Encuentra el PDC de un dominio usando nslookup.
        Retorna la IP del PDC si se encuentra, None en caso contrario.
        """
        try:
            # Consulta SRV para encontrar el PDC
            pdc_query = f"nslookup -type=srv _ldap._tcp.pdc._msdcs.{domain} {self.dns}"
            result = subprocess.run(pdc_query, shell=True, capture_output=True, text=True)
            
            # Buscar el hostname del PDC
            pdc_hostname_match = re.search(r"service = \d+ \d+ \d+ ([\w.-]+)", result.stdout)
            
            if pdc_hostname_match:
                # Obtener el hostname sin el dominio
                pdc_hostname = pdc_hostname_match.group(1).split('.')[0]
                
                # Resolver la IP del PDC
                ip_query = f"nslookup {pdc_hostname}.{domain} {self.dns}"
                ip_result = subprocess.run(ip_query, shell=True, capture_output=True, text=True)
                
                # Extraer la IP
                ip_matches = re.findall(r"Address:\s+([\d.]+)", ip_result.stdout)
                if ip_matches:
                    pdc_ip = ip_matches[-1]
                    if self.debug:
                        print(f"[DEBUG] PDC encontrado para {domain}:")
                        print(f"[DEBUG] Hostname: {pdc_hostname}")
                        print(f"[DEBUG] IP: {pdc_ip}")
                    return pdc_ip
            
            return None
            
        except Exception as e:
            print(f"[-] Error buscando DC para {domain}: {str(e)}")
            return None

    def enumerate_trusts(self):
        """Punto de entrada principal para la enumeración recursiva de confianzas"""
        print(f"\n[*] Iniciando enumeración de confianzas desde {self.initial_domain}")
        if self.hashes:
            print(f"[*] Usando credenciales (hash NTLM): {self.username}@{self.initial_domain}")
        else:
            print(f"[*] Usando credenciales: {self.username}@{self.initial_domain}")
        print(f"[*] PDC inicial: {self.initial_pdc}\n")
        
        self.domains_to_process.append(self.initial_domain)
        
        while self.domains_to_process:
            current_domain = self.domains_to_process.pop()
            
            if current_domain in self.seen_domains:
                continue
                
            print(f"[+] Procesando dominio: {current_domain}")
            self.seen_domains.add(current_domain)
            
            if current_domain not in self.domain_controllers:
                dc = self.find_domain_controller(current_domain)
                if not dc:
                    print(f"[-] No se pudo encontrar un DC para {current_domain}")
                    continue
                self.domain_controllers[current_domain] = dc
                if self.debug:
                    print(f"[DEBUG] Encontrado DC para {current_domain}: {dc}")
            
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
                            print(f"[-] Error procesando confianza: {str(e)}")
                        continue

    def print_results(self):
        """Imprime un resumen de todas las relaciones de confianza encontradas"""
        print("\n" + "="*60)
        print("RESUMEN DE RELACIONES DE CONFIANZA ENCONTRADAS")
        print("="*60)
        
        if not self.trust_relationships:
            print("\n[-] No se encontraron relaciones de confianza.")
            print("\nDominios procesados:", len(self.seen_domains))
            return
        
        for domain in self.trust_relationships:
            print(f"\nDominio: {domain}")
            print("-" * (len(domain) + 8))
            
            if not self.trust_relationships[domain]:
                print("  No se encontraron relaciones de confianza")
                continue
                
            for trust in self.trust_relationships[domain]:
                print(f"  → Dominio de confianza: {trust['partner']}")
                print(f"    Dirección: {trust.get('direction', 'No especificada')}")
                print(f"    Tipo: {trust.get('type', 'No especificado')}")
        
        print("\nDominios procesados:", len(self.seen_domains))
        print("Dominios con relaciones de confianza:", len(self.trust_relationships))

def main():
    parser = argparse.ArgumentParser(
        description='Enumera recursivamente las relaciones de confianza de dominios Active Directory.'
    )
    parser.add_argument('-u', '--username', required=True, help='Nombre de usuario')
    parser.add_argument('-p', '--password', required=False, help='Contraseña')
    parser.add_argument('-H', '--hashes', required=False, help='Hash NTLM para la autenticación')
    parser.add_argument('-d', '--domain', required=True, help='Nombre del dominio inicial')
    parser.add_argument('-pdc', '--pdc', required=True, help='IP del controlador de dominio primario')
    parser.add_argument('--debug', action='store_true', help='Activa mensajes de depuración')
    
    args = parser.parse_args()

    # Validación: se requiere o la contraseña o el hash
    if not args.password and not args.hashes:
        parser.error("Debe especificar la contraseña (-p/--password) o el hash NTLM (-H/--hashes) para la autenticación.")

    enumerator = TrustEnumerator(args.domain, args.username, args.password, args.pdc, hashes=args.hashes)
    enumerator.debug = args.debug
    
    try:
        enumerator.enumerate_trusts()
        enumerator.print_results()
    except KeyboardInterrupt:
        print("\n[!] Enumeración interrumpida por el usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error: {str(e)}")
        if args.debug:
            import traceback
            print(traceback.format_exc())
        sys.exit(1)

if __name__ == '__main__':
    main()