# PrivCheck

**Privileged Account Password Reuse Detector**

Identifies privileged Active Directory accounts sharing password hashes with non-privileged accounts in NTDS.dit dumps.

```
    ____       _     ________              __  
   / __ \_____(_)   / ____/ /_  ___  _____/ /__
  / /_/ / ___/ / | / / __/ __ \/ _ \/ ___/ //_/
 / ____/ /  / /| |/ / /_/ / / /  __/ /__/ ,<   
/_/   /_/  /_/ |___/\____/_/ /_/\___/\___/_/|_| 
```

## Overview

A common security misconfiguration in Active Directory environments occurs when privileged accounts (Domain Admins, Enterprise Admins, etc.) share passwords with standard user accounts. This creates an immediate privilege escalation path - if a low-privileged account is compromised, attackers gain administrative access without additional credential cracking or exploitation.

**PrivCheck** automates the detection of this critical vulnerability by:
1. Identifying privileged accounts from a provided list
2. Extracting their NT password hashes from NTDS.dit dumps
3. Finding all other accounts using the same hashes
4. Generating professional, report-ready output suitable for client deliverables

## Features

- ✅ **Flexible Input**: Accepts privileged account names in multiple formats (`username` or `DOMAIN\username`)
- ✅ **Comprehensive Analysis**: Processes complete NTDS.dit dumps from secretsdump.py or ntdsutil
- ✅ **Clean Output**: Color-coded terminal output with professional formatting
- ✅ **Report-Ready**: Grouped account lists perfect for copy/paste into penetration test reports
- ✅ **Hash Privacy**: Displays last 4 characters of hashes by default (full hash optional with `-f`)
- ✅ **File Export**: Optional text file output (strips colors for clean reports)
- ✅ **Zero Dependencies**: Pure Python 3 - no external libraries required

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/privcheck.git
cd privcheck

# Make executable
chmod +x privcheck.py

# Run
python3 privcheck.py -h
```

**Requirements:** Python 3.6+

No external dependencies required, uses only Python standard library.

## Usage

### Basic Usage

```bash
python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt
```

### Command-Line Options

```
-n, --ntds NTDS              NTDS.dit dump file (required)
-p, --priv-accounts FILE     Privileged accounts list (required)
-o, --output FILE            Save results to file (optional)
-f, --full-hash              Show full NT hashes instead of truncated (optional)
-h, --help                   Show help message
```

### Examples

```bash
# Basic analysis
python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt

# Save results to file
python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt -o results.txt

# Show full hashes for cross-referencing with cracking tools
python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt --full-hash

# Combined: full hashes + output file
python3 privcheck.py -n ntds_dump.txt -p privileged_accounts.txt -f -o full_report.txt
```

## Input File Formats

### NTDS Dump Format

Expected format from secretsdump.py (Impacket):

```
DOMAIN\username:RID:LMhash:NThash:::
CORP\Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
CORP\jsmith:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
```

### Privileged Accounts File

One account per line. Supports both formats:
- `username` - matches any domain
- `DOMAIN\username` - matches specific domain\username combination

```
# Comments are allowed
Administrator
CORP\domain_admin
CORP\backup_admin
svc_sqlserver
krbtgt
```

## Example Output

```
======================================================================
  PrivCheck - Privileged Account Password Reuse Detector
  Author: David Boyd (@Fir3d0g)
======================================================================

[*] Loading privileged accounts from: privileged_accounts.txt
[+] Loaded 5 privileged account(s)

[*] Parsing NTDS dump: ntds_dump.txt
[+] Parsed 150 unique hash(es)
[+] Found 5 privileged account(s) with valid hashes

[*] Analysis Results

[!] PASSWORD REUSE DETECTED
    Found 3 privileged account(s) sharing passwords with non-privileged accounts

======================================================================
Detailed Findings:

  NT Hash: ...586c

  Privileged Account(s):
    • CORP\Administrator

  Shares password with (1 account(s)):
    • CORP\jsmith

======================================================================

======================================================================
Grouped Account List (Report Format):

Hash Group #1:
NT Hash: ...586c

  CORP\Administrator [PRIVILEGED]
  CORP\jsmith

Hash Group #2:
NT Hash: ...1889

  CORP\domain_admin [PRIVILEGED]
  CORP\bjones
  CORP\helpdesk

======================================================================
Summary:
  Total privileged accounts analyzed: 5
  Privileged accounts with password reuse: 3
  Unique hashes identified: 3
```

```bash
# From a domain-joined machine with credentials
secretsdump.py DOMAIN/user:password@DC_IP -just-dc-ntlm

# Using NTLM hash (Pass-the-Hash)
secretsdump.py -hashes :NTHASH DOMAIN/user@DC_IP -just-dc-ntlm

# From extracted NTDS.dit and SYSTEM files
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

### Using ntdsutil (On Domain Controller)

```powershell
# Create IFM backup
ntdsutil "ac i ntds" "ifm" "create full c:\temp\dump" q q

# Then extract with secretsdump.py
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL > dump.txt
```

## Creating Privileged Account Lists

### From Active Directory

```bash
# Domain Admins
net group "Domain Admins" /domain > domain_admins.txt

# Enterprise Admins
net group "Enterprise Admins" /domain > enterprise_admins.txt

# Schema Admins
net group "Schema Admins" /domain > schema_admins.txt

# Custom privileged groups
net group "IT Admins" /domain > it_admins.txt
```

### PowerShell

```powershell
# Export Domain Admins
Get-ADGroupMember "Domain Admins" | Select -ExpandProperty SamAccountName | Out-File privileged.txt

# Multiple groups
$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
$groups | ForEach-Object { Get-ADGroupMember $_ } | 
    Select -ExpandProperty SamAccountName -Unique | 
    Out-File all_privileged.txt
```

### Manual Creation

Ideas of accounts to audit:
- Built-in Administrator account
- Service accounts with admin privileges
- Backup/recovery accounts
- Application pool identities with elevated rights
- Third-party admin accounts (AV, monitoring, etc.)

## Output Files

When using `-o` / `--output`, PrivCheck creates a clean text file with:
- All ANSI color codes stripped
- Same structure as terminal output
- Ready for direct inclusion in reports
- Plain text format for easy editing

Perfect for:
- Client deliverables
- Internal documentation
- Compliance reporting
- Knowledge base articles

## Tips & Best Practices

### Creating Comprehensive Privileged Account Lists

1. **Start Broad**: Include all built-in privileged groups
2. **Add Custom Groups**: Organization-specific admin groups
3. **Service Accounts**: Don't forget high-privilege service accounts
4. **Application Accounts**: Database admins, application pool accounts
5. **Validate**: Cross-reference with client's privileged access documentation

### Interpreting Results

- **No matches found**: Good! Privileged accounts have unique passwords
- **1-2 matches**: Common issue, easy to fix
- **3+ matches per privileged account**: Serious password policy problem
- **Many privileged accounts flagged**: Systemic password reuse issue

### Report Writing

The "Grouped Account List" section is specifically designed for copy/paste into reports:
- Shows all accounts sharing each hash
- Clearly marks `[PRIVILEGED]` accounts
- Clean formatting without colors
- Groups related issues together

## Troubleshooting

### "No privileged accounts found with valid hashes"
- Check that privileged account names match format in NTDS dump
- Verify accounts aren't disabled (empty NT hash: `31d6cfe0d16ae931b73c59d7e0c089c0`)
- Ensure case sensitivity isn't an issue (tool is case-insensitive)

### "Error reading NTDS dump file"
- Verify file is in correct format (secretsdump.py output)
- Check file encoding (should be UTF-8 or ASCII)
- Ensure file isn't corrupted

### Colors not displaying
- Ensure terminal supports ANSI colors
- Use `-o` output file for colorless text
- Try different terminal emulator

## License

This tool is provided for authorized security testing and assessment only.

## Author

**David Boyd (@Fir3d0g)**

Penetration Testing & Red Team Tools

## Changelog

### v1.0 (Current)
- Initial release
- NTDS.dit parsing and hash matching
- Flexible account name format support
- Color-coded terminal output
- Report-ready grouped output
- Optional file export
- Truncated hash display (last 4 chars)
- Full hash display option (`--full-hash`)

---
