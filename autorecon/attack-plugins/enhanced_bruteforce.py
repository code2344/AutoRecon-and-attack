from autorecon.plugins import AttackScan
import os

class EnhancedBruteForce(AttackScan):
    """Enhanced brute force attack plugin supporting multiple protocols and tools."""

    def __init__(self):
        super().__init__()
        self.name = "Enhanced Brute Force"
        self.tags = ['attack', 'bruteforce', 'credentials']
        self.attack_type = 'bruteforce'
        self.risk_level = 'medium'
        self.requires_confirmation = True

    def configure(self):
        self.add_choice_option('tool', choices=['hydra', 'medusa', 'ncrack', 'crowbar', 'patator'], default='hydra', help='Brute force tool to use. Default: %(default)s')
        self.add_option('username-list', help='Custom username wordlist file')
        self.add_option('password-list', help='Custom password wordlist file')
        self.add_option('single-username', help='Single username to test')
        self.add_option('single-password', help='Single password to test')
        self.add_option('threads', default='16', help='Number of parallel connections. Default: %(default)s')
        self.add_option('timeout', default='30', help='Connection timeout in seconds. Default: %(default)s')
        self.add_true_option('empty-passwords', help='Try empty passwords')
        self.add_true_option('username-as-password', help='Try username as password')
        self.add_true_option('reverse-username', help='Try reversed username as password')
        self.add_true_option('common-combos', help='Try common username/password combinations')
        self.add_option('delay', default='0', help='Delay between attempts in seconds. Default: %(default)s')
        self.add_true_option('verbose-output', help='Enable verbose output')
        self.add_true_option('continue-on-success', help='Continue after finding valid credentials')
        
        # Match common services that support brute forcing
        self.match_service_name(['^ssh'])
        self.match_service_name(['^ftp', '^ftp\\-data'])
        self.match_service_name(['^telnet'])
        self.match_service_name(['^smb', '^microsoft\\-ds', '^netbios'])
        self.match_service_name(['^rdp', '^ms\\-wbt\\-server', '^ms\\-term\\-serv'])
        self.match_service_name(['^http', '^https'])
        self.match_service_name(['^mysql'])
        self.match_service_name(['^postgresql', '^postgres'])
        self.match_service_name(['^mssql', '^ms\\-sql'])
        self.match_service_name(['^vnc'])
        self.match_service_name(['^pop3'])
        self.match_service_name(['^imap'])
        self.match_service_name(['^smtp'])

    def check(self):
        tool = self.get_option('tool')
        if not self._command_exists(tool):
            self.error(f'{tool} is not available. Please install {tool}.')
            return False
        return True

    def _command_exists(self, command):
        """Check if a command exists in the system PATH."""
        return os.system(f'which {command} > /dev/null 2>&1') == 0

    async def run(self, service):
        tool = self.get_option('tool')
        
        # Determine protocol and service type
        protocol_map = {
            'ssh': 'ssh',
            'ftp': 'ftp',
            'telnet': 'telnet',
            'smb': 'smb',
            'microsoft-ds': 'smb',
            'netbios': 'smb',
            'rdp': 'rdp',
            'ms-wbt-server': 'rdp',
            'ms-term-serv': 'rdp',
            'http': 'http-get',
            'https': 'https-get',
            'mysql': 'mysql',
            'postgresql': 'postgres',
            'postgres': 'postgres',
            'mssql': 'mssql',
            'ms-sql': 'mssql',
            'vnc': 'vnc',
            'pop3': 'pop3',
            'imap': 'imap',
            'smtp': 'smtp'
        }

        service_name = service.service.lower()
        target_protocol = protocol_map.get(service_name, service_name)

        self.info(f'Starting brute force attack on {service.target.address}:{service.port} ({target_protocol})')

        # Set up wordlists
        username_list = self._get_username_list()
        password_list = self._get_password_list()

        if not username_list or not password_list:
            self.warn('No valid wordlists found. Skipping brute force attack.')
            return

        # Execute brute force based on selected tool
        if tool == 'hydra':
            await self._run_hydra(service, target_protocol, username_list, password_list)
        elif tool == 'medusa':
            await self._run_medusa(service, target_protocol, username_list, password_list)
        elif tool == 'ncrack':
            await self._run_ncrack(service, target_protocol, username_list, password_list)
        elif tool == 'crowbar':
            await self._run_crowbar(service, target_protocol, username_list, password_list)
        elif tool == 'patator':
            await self._run_patator(service, target_protocol, username_list, password_list)

    def _get_username_list(self):
        """Get username wordlist."""
        if self.get_option('single_username'):
            # Create temporary file with single username
            username_file = '/tmp/single_username.txt'
            with open(username_file, 'w') as f:
                f.write(self.get_option('single_username') + '\n')
            return username_file
        
        if self.get_option('username_list') and os.path.exists(self.get_option('username_list')):
            return self.get_option('username_list')
        
        # Use global username wordlist
        global_list = self.get_global('username_wordlist', '/usr/share/seclists/Usernames/top-usernames-shortlist.txt')
        if os.path.exists(global_list):
            return global_list
        
        # Fallback to common usernames
        fallback_file = '/tmp/common_usernames.txt'
        with open(fallback_file, 'w') as f:
            common_users = ['admin', 'administrator', 'root', 'user', 'test', 'guest', 'oracle', 'postgres', 'mysql', 'ftp', 'www', 'web', 'tomcat', 'apache', 'nginx']
            f.write('\n'.join(common_users))
        return fallback_file

    def _get_password_list(self):
        """Get password wordlist."""
        if self.get_option('single_password'):
            # Create temporary file with single password
            password_file = '/tmp/single_password.txt'
            with open(password_file, 'w') as f:
                f.write(self.get_option('single_password') + '\n')
            return password_file
        
        if self.get_option('password_list') and os.path.exists(self.get_option('password_list')):
            return self.get_option('password_list')
        
        # Use global password wordlist
        global_list = self.get_global('password_wordlist', '/usr/share/seclists/Passwords/darkweb2017-top100.txt')
        if os.path.exists(global_list):
            return global_list
        
        # Fallback to common passwords
        fallback_file = '/tmp/common_passwords.txt'
        with open(fallback_file, 'w') as f:
            common_passwords = ['password', '123456', 'admin', 'root', 'pass', 'test', 'guest', 'password123', 'admin123', '']
            f.write('\n'.join(common_passwords))
        return fallback_file

    async def _run_hydra(self, service, protocol, username_list, password_list):
        """Execute Hydra brute force attack."""
        cmd_parts = [
            'hydra',
            f'-L "{username_list}"',
            f'-P "{password_list}"',
            f'-t {self.get_option("threads")}',
            f'-w {self.get_option("timeout")}',
            f'-s {service.port}'
        ]

        # Add options based on configuration
        if self.get_option('empty_passwords'):
            cmd_parts.append('-e n')
        if self.get_option('username_as_password'):
            cmd_parts.append('-e s')
        if self.get_option('reverse_username'):
            cmd_parts.append('-e r')
        if self.get_option('verbose_output'):
            cmd_parts.append('-V')
        if self.get_option('continue_on_success'):
            cmd_parts.append('-f')
        if int(self.get_option('delay')) > 0:
            cmd_parts.append(f'-W {self.get_option("delay")}')

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{protocol}_hydra_bruteforce.txt'
        cmd_parts.append(f'-o "{output_file}"')

        # Target and protocol
        cmd_parts.append(f'{service.target.address} {protocol}')

        cmd = ' '.join(cmd_parts)
        await service.execute(cmd)

    async def _run_medusa(self, service, protocol, username_list, password_list):
        """Execute Medusa brute force attack."""
        cmd_parts = [
            'medusa',
            f'-U "{username_list}"',
            f'-P "{password_list}"',
            f'-h {service.target.address}',
            f'-n {service.port}',
            f'-t {self.get_option("threads")}',
            f'-M {protocol}'
        ]

        # Add options
        if self.get_option('empty_passwords'):
            cmd_parts.append('-e n')
        if self.get_option('username_as_password'):
            cmd_parts.append('-e s')
        if self.get_option('verbose_output'):
            cmd_parts.append('-v 4')

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{protocol}_medusa_bruteforce.txt'
        cmd_parts.append(f'-O "{output_file}"')

        cmd = ' '.join(cmd_parts)
        await service.execute(cmd)

    async def _run_ncrack(self, service, protocol, username_list, password_list):
        """Execute Ncrack brute force attack."""
        protocol_map = {
            'ssh': 'ssh',
            'rdp': 'rdp',
            'ftp': 'ftp',
            'telnet': 'telnet',
            'http-get': 'http',
            'https-get': 'https'
        }

        ncrack_protocol = protocol_map.get(protocol, protocol)
        
        cmd_parts = [
            'ncrack',
            f'-U "{username_list}"',
            f'-P "{password_list}"',
            f'-T {self.get_option("threads")}',
            f'{ncrack_protocol}://{service.target.address}:{service.port}'
        ]

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{protocol}_ncrack_bruteforce.txt'
        cmd_parts.append(f'-o "{output_file}"')

        cmd = ' '.join(cmd_parts)
        await service.execute(cmd)

    async def _run_crowbar(self, service, protocol, username_list, password_list):
        """Execute Crowbar brute force attack (mainly for RDP/SSH)."""
        if protocol not in ['rdp', 'ssh']:
            self.warn(f'Crowbar does not support {protocol}. Skipping.')
            return

        cmd_parts = [
            'crowbar',
            f'-b {protocol}',
            f'-U "{username_list}"',
            f'-C "{password_list}"',
            f'-s {service.target.address}/{service.port}'
        ]

        if self.get_option('verbose_output'):
            cmd_parts.append('-v')

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{protocol}_crowbar_bruteforce.txt'
        
        cmd = ' '.join(cmd_parts) + f' 2>&1 | tee "{output_file}"'
        await service.execute(cmd)

    async def _run_patator(self, service, protocol, username_list, password_list):
        """Execute Patator brute force attack."""
        protocol_modules = {
            'ssh': 'ssh_login',
            'ftp': 'ftp_login',
            'telnet': 'telnet_login',
            'smtp': 'smtp_login',
            'pop3': 'pop_login',
            'imap': 'imap_login',
            'mysql': 'mysql_login',
            'postgres': 'pgsql_login',
            'mssql': 'mssql_login',
            'http-get': 'http_fuzz',
            'https-get': 'http_fuzz'
        }

        patator_module = protocol_modules.get(protocol)
        if not patator_module:
            self.warn(f'Patator does not support {protocol}. Skipping.')
            return

        cmd_parts = [
            'patator',
            patator_module,
            f'host={service.target.address}',
            f'port={service.port}',
            f'user=FILE0',
            f'password=FILE1',
            f'0="{username_list}"',
            f'1="{password_list}"',
            f'-t {self.get_option("threads")}'
        ]

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{protocol}_patator_bruteforce.txt'
        cmd_parts.append(f'-x ignore:mesg="Authentication failed" --csv="{output_file}"')

        cmd = ' '.join(cmd_parts)
        await service.execute(cmd)

    def manual(self, service, plugin_was_run):
        if not plugin_was_run:
            service.add_manual_command('Enhanced brute force attack commands:', [
                f'# Hydra brute force attacks',
                f'hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt -s {service.port} {service.target.address} {service.service}',
                f'hydra -l admin -P /usr/share/wordlists/rockyou.txt -s {service.port} {service.target.address} {service.service}',
                '',
                f'# Medusa brute force attacks',
                f'medusa -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt -h {service.target.address} -n {service.port} -M {service.service}',
                '',
                f'# Ncrack brute force attacks',
                f'ncrack -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/darkweb2017-top100.txt {service.service}://{service.target.address}:{service.port}',
                '',
                f'# Service-specific attacks',
                f'# SSH',
                f'ssh-audit {service.target.address} -p {service.port}',
                f'# FTP',
                f'ftp-anon-scan {service.target.address} {service.port}',
                f'# RDP',
                f'rdesktop {service.target.address}:{service.port}',
                f'# SMB',
                f'smbclient -L //{service.target.address} -p {service.port}',
                f'enum4linux -a {service.target.address}',
                '',
                f'# Password spraying',
                f'# Use common passwords against multiple accounts',
                f'hydra -L users.txt -p "Password123" -s {service.port} {service.target.address} {service.service}',
                f'hydra -L users.txt -p "password" -s {service.port} {service.target.address} {service.service}',
                '',
                f'# Custom wordlist generation',
                f'cewl http://{service.target.address} -w custom_wordlist.txt',
                f'john --wordlist=custom_wordlist.txt --rules --stdout > mutated_wordlist.txt'
            ])