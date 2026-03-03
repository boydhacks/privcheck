#!/usr/bin/env python3
"""
PrivCheck - Privileged Account Password Reuse Detector
Author: David Boyd (@Fir3d0g)
Description: Identifies privileged accounts that share password hashes with non-privileged accounts
             in NTDS.dit dumps, highlighting potential privilege escalation risks.
"""

import argparse
import sys
from collections import defaultdict


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def banner():
    """Display tool banner"""
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print(r"""
    ____       _     ________              __  
   / __ \_____(_)   / ____/ /_  ___  _____/ /__
  / /_/ / ___/ / | / / __/ __ \/ _ \/ ___/ //_/
 / ____/ /  / /| |/ / /_/ / / /  __/ /__/ ,<   
/_/   /_/  /_/ |___/\____/_/ /_/\___/\___/_/|_| 
                                                
    """)
    print("  PrivCheck - Privileged Account Password Reuse Detector")
    print("  Author: David Boyd (@Fir3d0g)")
    print("=" * 70)
    print(f"{Colors.RESET}\n")


def parse_ntds_line(line):
    """
    Parse a single line from NTDS.dit dump
    Expected format: DOMAIN\\username:RID:LMhash:NThash:::
    
    Returns: (domain, username, nt_hash) or None if invalid
    """
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    parts = line.split(':')
    if len(parts) < 4:
        return None
    
    # Extract domain\username
    account = parts[0]
    if '\\' in account:
        domain, username = account.split('\\', 1)
    else:
        domain = ''
        username = account
    
    # Extract NT hash (4th field, index 3)
    nt_hash = parts[3]
    
    # Skip empty hashes
    if not nt_hash or nt_hash == '31d6cfe0d16ae931b73c59d7e0c089c0':  # Empty NT hash
        return None
    
    return (domain, username, nt_hash)


def load_privileged_accounts(priv_file):
    """
    Load privileged account list from file
    Handles both 'username' and 'DOMAIN\\username' formats
    
    Returns: set of (domain, username) tuples (case-insensitive)
    """
    priv_accounts = set()
    
    try:
        with open(priv_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Handle DOMAIN\username format
                if '\\' in line:
                    domain, username = line.split('\\', 1)
                    priv_accounts.add((domain.lower(), username.lower()))
                else:
                    # Just username - will match any domain
                    priv_accounts.add(('', line.lower()))
    
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: Privileged accounts file not found: {priv_file}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading privileged accounts file: {e}{Colors.RESET}")
        sys.exit(1)
    
    return priv_accounts


def parse_ntds_dump(ntds_file, priv_accounts):
    """
    Parse NTDS.dit dump and identify hash matches
    
    Returns: (priv_hash_map, all_accounts_map)
        - priv_hash_map: {hash: [(domain, username), ...]} for privileged accounts
        - all_accounts_map: {hash: [(domain, username), ...]} for all accounts
    """
    priv_hash_map = defaultdict(list)
    all_accounts_map = defaultdict(list)
    
    try:
        with open(ntds_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_ntds_line(line)
                if not parsed:
                    continue
                
                domain, username, nt_hash = parsed
                account_tuple = (domain, username)
                
                # Add to all accounts map
                all_accounts_map[nt_hash].append(account_tuple)
                
                # Check if this is a privileged account
                is_privileged = False
                for priv_domain, priv_username in priv_accounts:
                    if priv_domain == '':  # Match any domain
                        if username.lower() == priv_username:
                            is_privileged = True
                            break
                    else:  # Match specific domain\username
                        if domain.lower() == priv_domain and username.lower() == priv_username:
                            is_privileged = True
                            break
                
                if is_privileged:
                    priv_hash_map[nt_hash].append(account_tuple)
    
    except FileNotFoundError:
        print(f"{Colors.RED}[!] Error: NTDS dump file not found: {ntds_file}{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}[!] Error reading NTDS dump file: {e}{Colors.RESET}")
        sys.exit(1)
    
    return priv_hash_map, all_accounts_map


def generate_report(priv_hash_map, all_accounts_map, output_file=None, full_hash=False):
    """
    Generate report showing privileged accounts with shared hashes
    Optionally write to output file if specified
    """
    import re
    
    # Collect output lines for file
    output_lines = []
    
    def output(text=""):
        """Print to console and collect for file output"""
        print(text)
        if output_file:
            # Strip ANSI color codes for file output
            clean_text = re.sub(r'\033\[[0-9;]+m', '', text)
            output_lines.append(clean_text)
    
    def format_hash(nt_hash):
        """Format hash based on full_hash flag"""
        return nt_hash if full_hash else f"...{nt_hash[-4:]}"
    
    output(f"{Colors.BOLD}[*] Analysis Results{Colors.RESET}\n")
    
    findings = []
    
    for nt_hash, priv_accounts in priv_hash_map.items():
        all_accounts = all_accounts_map[nt_hash]
        
        # Find non-privileged accounts with same hash
        non_priv_accounts = [acc for acc in all_accounts if acc not in priv_accounts]
        
        if non_priv_accounts:
            findings.append((priv_accounts, non_priv_accounts, nt_hash))
    
    if not findings:
        output(f"{Colors.GREEN}[+] No password reuse detected! All privileged accounts have unique passwords.{Colors.RESET}\n")
        if output_file:
            _write_output_file(output_file, output_lines)
        return
    
    # Summary
    output(f"{Colors.YELLOW}[!] PASSWORD REUSE DETECTED{Colors.RESET}")
    output(f"    Found {len(findings)} privileged account(s) sharing passwords with non-privileged accounts\n")
    
    # Detailed findings
    output(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    output(f"{Colors.BOLD}Detailed Findings:{Colors.RESET}\n")
    
    for idx, (priv_accounts, non_priv_accounts, nt_hash) in enumerate(findings, 1):
        output(f"  NT Hash: {format_hash(nt_hash)}")
        
        output(f"\n  {Colors.MAGENTA}Privileged Account(s):{Colors.RESET}")
        for domain, username in priv_accounts:
            if domain:
                output(f"    • {domain}\\{username}")
            else:
                output(f"    • {username}")
        
        output(f"\n  {Colors.RED}Shares password with ({len(non_priv_accounts)} account(s)):{Colors.RESET}")
        for domain, username in non_priv_accounts:
            if domain:
                output(f"    • {domain}\\{username}")
            else:
                output(f"    • {username}")
        
        output(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")
    
    # Report-ready grouped output
    output(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    output(f"{Colors.BOLD}Grouped Account List (Report Format):{Colors.RESET}\n")
    
    for idx, (priv_accounts, non_priv_accounts, nt_hash) in enumerate(findings, 1):
        output(f"Hash Group #{idx}:")
        output(f"NT Hash: {format_hash(nt_hash)}\n")
        
        # Combine all accounts (privileged first)
        all_accounts_in_group = []
        for domain, username in priv_accounts:
            if domain:
                all_accounts_in_group.append(f"{domain}\\{username} [PRIVILEGED]")
            else:
                all_accounts_in_group.append(f"{username} [PRIVILEGED]")
        
        for domain, username in non_priv_accounts:
            if domain:
                all_accounts_in_group.append(f"{domain}\\{username}")
            else:
                all_accounts_in_group.append(f"{username}")
        
        for account in all_accounts_in_group:
            output(f"  {account}")
        
        output()  # Blank line between groups
    
    # Final summary
    output(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    output(f"{Colors.BOLD}Summary:{Colors.RESET}")
    output(f"  Total privileged accounts analyzed: {len(priv_hash_map)}")
    output(f"  Privileged accounts with password reuse: {len(findings)}")
    output(f"  Unique hashes identified: {len(findings)}")
    output()
    
    # Write to file if specified
    if output_file:
        _write_output_file(output_file, output_lines)


def _write_output_file(filename, lines):
    """Write output lines to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        print(f"{Colors.GREEN}[+] Results saved to: {filename}{Colors.RESET}\n")
    except Exception as e:
        print(f"{Colors.RED}[!] Error writing output file: {e}{Colors.RESET}\n")


def main():
    parser = argparse.ArgumentParser(
        description='Identify privileged accounts sharing password hashes with non-privileged accounts',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage:
  python3 privcheck.py -n <ntds_dump> -p <privileged_accounts> [-o <output_file>] [-f]

Examples:
  python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt
  python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt -o results.txt
  python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt --full-hash
  python3 privcheck.py --ntds secretsdump_output.txt --priv-accounts domain_admins.txt --output report.txt -f

Privileged accounts file format (one per line):
  username
  DOMAIN\\username
        """
    )
    
    parser.add_argument('-n', '--ntds', required=True,
                        help='NTDS.dit dump file (secretsdump.py output format)')
    parser.add_argument('-p', '--priv-accounts', required=True,
                        help='File containing privileged account names (one per line)')
    parser.add_argument('-o', '--output', required=False,
                        help='Output file to save results (optional)')
    parser.add_argument('-f', '--full-hash', action='store_true',
                        help='Display full NT hashes instead of truncated (last 4 chars)')
    
    args = parser.parse_args()
    
    banner()
    
    # Load privileged accounts
    print(f"[*] Loading privileged accounts from: {args.priv_accounts}")
    priv_accounts = load_privileged_accounts(args.priv_accounts)
    print(f"[+] Loaded {len(priv_accounts)} privileged account(s)\n")
    
    # Parse NTDS dump
    print(f"[*] Parsing NTDS dump: {args.ntds}")
    priv_hash_map, all_accounts_map = parse_ntds_dump(args.ntds, priv_accounts)
    print(f"[+] Parsed {len(all_accounts_map)} unique hash(es)")
    print(f"[+] Found {len(priv_hash_map)} privileged account(s) with valid hashes\n")
    
    # Generate report
    generate_report(priv_hash_map, all_accounts_map, args.output, args.full_hash)


if __name__ == '__main__':
    main()