from autorecon.plugins import AttackScan
import os

class SQLMapAttack(AttackScan):
    """SQLMap plugin for automated SQL injection testing."""

    def __init__(self):
        super().__init__()
        self.name = "SQLMap SQL Injection"
        self.tags = ['attack', 'web', 'injection', 'sql']
        self.attack_type = 'injection'
        self.risk_level = 'medium'
        self.requires_confirmation = True

    def configure(self):
        self.add_option('url', help='Target URL to test (optional, will auto-detect from HTTP services)')
        self.add_option('data', help='POST data to test')
        self.add_option('cookie', help='HTTP Cookie header value')
        self.add_option('user-agent', default='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', help='HTTP User-Agent header value. Default: %(default)s')
        self.add_option('level', default='1', help='Level of tests to perform (1-5). Default: %(default)s')
        self.add_option('risk', default='1', help='Risk of tests to perform (1-3). Default: %(default)s')
        self.add_option('threads', default='5', help='Max number of concurrent HTTP(s) requests. Default: %(default)s')
        self.add_true_option('batch', help='Never ask for user input, use the default behaviour')
        self.add_true_option('crawl', help='Crawl the website starting from the target URL')
        self.add_option('crawl-depth', default='2', help='Crawl depth from the target URL. Default: %(default)s')
        self.add_true_option('forms', help='Parse and test forms on target URL')
        self.add_true_option('dump', help='Dump DBMS database table entries')
        self.add_true_option('dump-all', help='Dump all DBMS databases tables entries')
        
        # Match HTTP services
        self.match_service_name(['^http', '^https'])

    def check(self):
        # Check if sqlmap is available
        if not self._command_exists('sqlmap'):
            self.error('sqlmap is not available. Please install sqlmap.')
            return False
        return True

    def _command_exists(self, command):
        """Check if a command exists in the system PATH."""
        return os.system(f'which {command} > /dev/null 2>&1') == 0

    async def run(self, service):
        target_url = self.get_option('url')
        
        # Auto-generate URL if not provided
        if not target_url:
            scheme = 'https' if service.secure else 'http'
            target_url = f'{scheme}://{service.target.address}:{service.port}/'

        self.info(f'Testing {target_url} for SQL injection vulnerabilities')

        # Base sqlmap command
        cmd_parts = [
            'sqlmap',
            f'-u "{target_url}"',
            f'--level={self.get_option("level")}',
            f'--risk={self.get_option("risk")}',
            f'--threads={self.get_option("threads")}',
            f'--user-agent="{self.get_option("user_agent")}"',
            '--random-agent',
            '--timeout=30',
            '--retries=3'
        ]

        # Add optional parameters
        if self.get_option('data'):
            cmd_parts.append(f'--data="{self.get_option("data")}"')
            
        if self.get_option('cookie'):
            cmd_parts.append(f'--cookie="{self.get_option("cookie")}"')

        if self.get_option('batch'):
            cmd_parts.append('--batch')

        if self.get_option('forms'):
            cmd_parts.append('--forms')

        if self.get_option('crawl'):
            cmd_parts.append('--crawl')
            cmd_parts.append(f'--crawl-depth={self.get_option("crawl_depth")}')

        # Output file
        output_file = f'{service.target.scandir}/{service.protocol}_{service.port}_{service.service}_sqlmap.txt'
        cmd_parts.append(f'--output-dir="{service.target.scandir}"')

        # First run: just detection
        detection_cmd = ' '.join(cmd_parts) + f' 2>&1 | tee "{output_file}"'
        await service.execute(detection_cmd)

        # If dump options are enabled, run additional commands
        if self.get_option('dump') or self.get_option('dump_all'):
            dump_cmd_parts = cmd_parts.copy()
            if self.get_option('dump_all'):
                dump_cmd_parts.append('--dump-all')
                dump_cmd_parts.append('--exclude-sysdbs')
            elif self.get_option('dump'):
                dump_cmd_parts.append('--dump')
            
            dump_output = f'{service.target.scandir}/{service.protocol}_{service.port}_{service.service}_sqlmap_dump.txt'
            dump_cmd = ' '.join(dump_cmd_parts) + f' 2>&1 | tee "{dump_output}"'
            await service.execute(dump_cmd)

    def manual(self, service, plugin_was_run):
        if not plugin_was_run:
            scheme = 'https' if service.secure else 'http'
            base_url = f'{scheme}://{service.target.address}:{service.port}'
            
            service.add_manual_command('SQLMap manual testing commands:', [
                f'# Basic SQL injection test',
                f'sqlmap -u "{base_url}/" --batch --level=3 --risk=2',
                '',
                f'# Test with forms',
                f'sqlmap -u "{base_url}/" --forms --batch',
                '',
                f'# Test with crawling',
                f'sqlmap -u "{base_url}/" --crawl=2 --batch',
                '',
                f'# Test specific parameter',
                f'sqlmap -u "{base_url}/page.php?id=1" --batch',
                '',
                f'# Test POST data',
                f'sqlmap -u "{base_url}/login.php" --data="username=admin&password=test" --batch',
                '',
                f'# Dump database if injection is found',
                f'sqlmap -u "{base_url}/" --dump-all --exclude-sysdbs --batch',
                '',
                f'# Get OS shell if possible',
                f'sqlmap -u "{base_url}/" --os-shell --batch'
            ])