from autorecon.plugins import AttackScan
import os
import json
import asyncio
try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
from urllib.parse import urljoin, urlparse

class WebCrawlerAttack(AttackScan):
    """Advanced web crawler and attack plugin for web application testing."""

    def __init__(self):
        super().__init__()
        self.name = "Web Crawler Attack"
        self.tags = ['attack', 'web', 'crawler', 'forms']
        self.attack_type = 'web'
        self.risk_level = 'medium'
        self.requires_confirmation = True

    def configure(self):
        self.add_option('max-depth', default='3', help='Maximum crawl depth. Default: %(default)s')
        self.add_option('max-pages', default='100', help='Maximum number of pages to crawl. Default: %(default)s')
        self.add_option('threads', default='10', help='Number of concurrent requests. Default: %(default)s')
        self.add_option('user-agent', default='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', help='User agent string. Default: %(default)s')
        self.add_option('timeout', default='10', help='Request timeout in seconds. Default: %(default)s')
        self.add_true_option('test-forms', help='Test discovered forms for vulnerabilities')
        self.add_true_option('brute-dirs', help='Perform directory brute-forcing on discovered paths')
        self.add_true_option('parameter-fuzzing', help='Fuzz discovered parameters')
        self.add_option('cookie', help='Cookie to use for authenticated crawling')
        self.add_option('login-url', help='Login URL for authentication')
        self.add_option('login-data', help='Login data in format "username=admin&password=test"')
        
        # Match HTTP services
        self.match_service_name(['^http', '^https'])

    def check(self):
        # Check if required tools are available
        tools = ['curl', 'gobuster', 'wfuzz']
        missing_tools = []
        
        for tool in tools:
            if not self._command_exists(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            self.warn(f'Some tools are missing: {", ".join(missing_tools)}. Some features may not work.')
        
        if not AIOHTTP_AVAILABLE:
            self.warn('aiohttp is not available. Advanced crawling features will be disabled.')
        
        return True

    def _command_exists(self, command):
        """Check if a command exists in the system PATH."""
        return os.system(f'which {command} > /dev/null 2>&1') == 0

    async def run(self, service):
        scheme = 'https' if service.secure else 'http'
        base_url = f'{scheme}://{service.target.address}:{service.port}'
        
        self.info(f'Starting web crawler attack on {base_url}')

        if not AIOHTTP_AVAILABLE:
            self.warn('aiohttp not available. Using basic curl-based enumeration instead.')
            await self._basic_web_enumeration(service, base_url)
            return

        # Initialize crawler
        crawler = WebCrawler(
            base_url=base_url,
            max_depth=int(self.get_option('max_depth')),
            max_pages=int(self.get_option('max_pages')),
            timeout=int(self.get_option('timeout')),
            user_agent=self.get_option('user_agent'),
            cookie=self.get_option('cookie')
        )

        # Perform authentication if login details provided
        if self.get_option('login_url') and self.get_option('login_data'):
            await crawler.authenticate(self.get_option('login_url'), self.get_option('login_data'))

        # Crawl the website
        crawl_results = await crawler.crawl()

        # Save crawl results
        results_file = os.path.join(service.target.scandir, f'{service.protocol}_{service.port}_web_crawl_results.json')
        with open(results_file, 'w') as f:
            json.dump(crawl_results, f, indent=2)

        self.info(f'Crawled {len(crawl_results["pages"])} pages, found {len(crawl_results["forms"])} forms')

        # Test forms if enabled
        if self.get_option('test_forms') and crawl_results['forms']:
            await self._test_forms(service, crawl_results['forms'], base_url)

        # Brute force directories if enabled
        if self.get_option('brute_dirs'):
            await self._brute_directories(service, base_url)

        # Parameter fuzzing if enabled
        if self.get_option('parameter_fuzzing') and crawl_results['parameters']:
            await self._fuzz_parameters(service, crawl_results['parameters'], base_url)

    async def _basic_web_enumeration(self, service, base_url):
        """Basic web enumeration using curl and other tools when aiohttp is not available."""
        self.info('Performing basic web enumeration')
        
        # Basic page retrieval
        await service.execute(f'curl -s -L "{base_url}" -o "{service.target.scandir}/{service.protocol}_{service.port}_index.html"')
        
        # Try common paths
        common_paths = ['/', '/robots.txt', '/sitemap.xml', '/admin', '/login', '/wp-admin', '/phpmyadmin']
        for path in common_paths:
            url = base_url + path
            await service.execute(f'curl -s -I "{url}" | head -1 >> "{service.target.scandir}/{service.protocol}_{service.port}_common_paths.txt"')
        
        # Directory brute-forcing if enabled
        if self.get_option('brute_dirs'):
            await self._brute_directories(service, base_url)

    async def _test_forms(self, service, forms, base_url):
        """Test discovered forms for vulnerabilities."""
        self.info(f'Testing {len(forms)} discovered forms')
        
        for form in forms:
            form_url = urljoin(base_url, form['action'])
            
            # Test for SQL injection
            if 'text' in [input_type['type'] for input_type in form['inputs']]:
                sqli_cmd = f"sqlmap -u '{form_url}' --data='{form['sample_data']}' --batch --level=1 --risk=1 --timeout=30"
                await service.execute(f"{sqli_cmd} 2>&1 | tee '{service.target.scandir}/{service.protocol}_{service.port}_form_sqli_{form['id']}.txt'")

            # Test for XSS
            xss_payload = "<script>alert('XSS')</script>"
            xss_data = form['sample_data'].replace('test', xss_payload)
            xss_cmd = f"curl -X POST -d '{xss_data}' '{form_url}' -o '{service.target.scandir}/{service.protocol}_{service.port}_form_xss_{form['id']}.html'"
            await service.execute(xss_cmd)

    async def _brute_directories(self, service, base_url):
        """Perform directory brute-forcing."""
        self.info('Performing directory brute-forcing')
        
        wordlist = '/usr/share/wordlists/dirb/common.txt'
        if os.path.exists(wordlist):
            cmd = f"gobuster dir -u '{base_url}' -w '{wordlist}' -o '{service.target.scandir}/{service.protocol}_{service.port}_gobuster_dirs.txt'"
            await service.execute(cmd)

    async def _fuzz_parameters(self, service, parameters, base_url):
        """Fuzz discovered parameters."""
        self.info(f'Fuzzing {len(parameters)} discovered parameters')
        
        for param in parameters:
            if self._command_exists('wfuzz'):
                cmd = f"wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/SQL.txt --hc 404 '{param['url']}?{param['name']}=FUZZ' -o '{service.target.scandir}/{service.protocol}_{service.port}_param_fuzz_{param['name']}.txt'"
                await service.execute(cmd)

    def manual(self, service, plugin_was_run):
        if not plugin_was_run:
            scheme = 'https' if service.secure else 'http'
            base_url = f'{scheme}://{service.target.address}:{service.port}'
            
            service.add_manual_command('Manual web application testing:', [
                f'# Spider and crawl the application',
                f'spider {base_url}',
                f'hakrawler -url {base_url}',
                f'gospider -s {base_url}',
                '',
                f'# Directory and file discovery',
                f'gobuster dir -u {base_url} -w /usr/share/wordlists/dirb/common.txt',
                f'feroxbuster -u {base_url}',
                f'dirsearch -u {base_url}',
                '',
                f'# Parameter discovery and fuzzing',
                f'paramspider -d {service.target.address}',
                f'arjun -u {base_url}',
                f'wfuzz -c -z file,/usr/share/wfuzz/wordlist/Injections/All_attack.txt --hc 404 {base_url}/FUZZ',
                '',
                f'# Vulnerability scanning',
                f'nikto -h {base_url}',
                f'nuclei -u {base_url}',
                f'sqlmap -u {base_url} --crawl=2 --batch',
                '',
                f'# Form testing',
                f'# Use Burp Suite or OWASP ZAP for comprehensive form testing',
                f'# Manual testing for XSS, CSRF, SQL injection',
                '',
                f'# Authentication testing',
                f'hydra -l admin -P /usr/share/wordlists/rockyou.txt {service.target.address} http-post-form "/login:username=^USER^&password=^PASS^:F=failed"'
            ])


if AIOHTTP_AVAILABLE:
    class WebCrawler:
        """Web crawler implementation."""
        
        def __init__(self, base_url, max_depth=3, max_pages=100, timeout=10, user_agent=None, cookie=None):
            self.base_url = base_url
            self.max_depth = max_depth
            self.max_pages = max_pages
            self.timeout = timeout
            self.user_agent = user_agent
            self.cookie = cookie
            self.visited_urls = set()
            self.found_forms = []
            self.found_parameters = []
            self.session = None

        async def authenticate(self, login_url, login_data):
            """Perform authentication to get session cookies."""
            try:
                headers = {'User-Agent': self.user_agent} if self.user_agent else {}
                
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                    # Parse login data
                    data = {}
                    for pair in login_data.split('&'):
                        key, value = pair.split('=', 1)
                        data[key] = value
                    
                    async with session.post(login_url, data=data, headers=headers) as response:
                        if response.status == 200:
                            # Extract cookies for future requests
                            cookies = {}
                            for cookie in response.cookies:
                                cookies[cookie.key] = cookie.value
                            self.cookie = '; '.join([f'{k}={v}' for k, v in cookies.items()])
                            
            except Exception as e:
                print(f"Authentication failed: {e}")

        async def crawl(self):
            """Perform the crawling operation."""
            to_crawl = [(self.base_url, 0)]  # (url, depth)
            pages_crawled = 0
            
            headers = {}
            if self.user_agent:
                headers['User-Agent'] = self.user_agent
            if self.cookie:
                headers['Cookie'] = self.cookie

            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                headers=headers
            ) as session:
                
                while to_crawl and pages_crawled < self.max_pages:
                    url, depth = to_crawl.pop(0)
                    
                    if url in self.visited_urls or depth > self.max_depth:
                        continue
                    
                    try:
                        async with session.get(url) as response:
                            if response.status == 200:
                                content = await response.text()
                                self.visited_urls.add(url)
                                pages_crawled += 1
                                
                                # Extract links, forms, and parameters
                                new_urls = self._extract_links(content, url)
                                forms = self._extract_forms(content, url)
                                parameters = self._extract_parameters(content, url)
                                
                                self.found_forms.extend(forms)
                                self.found_parameters.extend(parameters)
                                
                                # Add new URLs to crawl queue
                                for new_url in new_urls:
                                    if new_url not in self.visited_urls:
                                        to_crawl.append((new_url, depth + 1))
                    
                    except Exception as e:
                        print(f"Error crawling {url}: {e}")

            return {
                'pages': list(self.visited_urls),
                'forms': self.found_forms,
                'parameters': self.found_parameters
            }

        def _extract_links(self, content, base_url):
            """Extract links from HTML content."""
            import re
            links = []
            
            # Simple regex to find href attributes
            href_pattern = r'href=["\'](.*?)["\']'
            matches = re.findall(href_pattern, content, re.IGNORECASE)
            
            for match in matches:
                absolute_url = urljoin(base_url, match)
                if urlparse(absolute_url).netloc == urlparse(self.base_url).netloc:
                    links.append(absolute_url)
            
            return links

        def _extract_forms(self, content, base_url):
            """Extract forms from HTML content."""
            import re
            forms = []
            
            # Simple form extraction (basic implementation)
            form_pattern = r'<form[^>]*action=["\'](.*?)["\'][^>]*>(.*?)</form>'
            matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)
            
            for i, (action, form_content) in enumerate(matches):
                # Extract input fields
                input_pattern = r'<input[^>]*name=["\'](.*?)["\'][^>]*type=["\'](.*?)["\'][^>]*>'
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                
                form_data = {
                    'id': f'form_{i}',
                    'action': action,
                    'inputs': [{'name': name, 'type': input_type} for name, input_type in inputs],
                    'sample_data': '&'.join([f'{name}=test' for name, _ in inputs])
                }
                forms.append(form_data)
            
            return forms

        def _extract_parameters(self, content, base_url):
            """Extract parameters from URLs and forms."""
            import re
            parameters = []
            
            # Extract parameters from URLs
            param_pattern = r'[?&]([a-zA-Z0-9_]+)='
            matches = re.findall(param_pattern, content)
            
            for param in set(matches):
                parameters.append({
                    'name': param,
                    'url': base_url,
                    'source': 'url'
                })
            
            return parameters
else:
    class WebCrawler:
        """Dummy WebCrawler class when aiohttp is not available."""
        def __init__(self, *args, **kwargs):
            pass
        
        async def authenticate(self, *args, **kwargs):
            pass
        
        async def crawl(self):
            return {'pages': [], 'forms': [], 'parameters': []}