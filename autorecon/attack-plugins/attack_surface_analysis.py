from autorecon.plugins import AttackScan
import os
import json
import re

class AttackSurfaceAnalysis(AttackScan):
    """Attack surface analysis plugin that analyzes discovered services and suggests attack vectors."""

    def __init__(self):
        super().__init__()
        self.name = "Attack Surface Analysis"
        self.tags = ['attack', 'analysis', 'surface']
        self.attack_type = 'analysis'
        self.risk_level = 'low'
        self.requires_confirmation = False
        self.run_once_boolean = True  # Run once per target

    def configure(self):
        self.add_true_option('detailed-analysis', help='Perform detailed vulnerability analysis')
        self.add_true_option('suggest-exploits', help='Suggest specific exploits for discovered services')
        self.add_true_option('prioritize-risks', help='Prioritize attack vectors by risk level')
        self.add_option('attack-scenarios', help='Comma-separated list of attack scenarios to analyze (web, network, lateral, privilege)')
        
        # This plugin analyzes all discovered services
        self.match_service_name('.*')

    def check(self):
        return True

    async def run(self, service):
        # This plugin runs once per target, not per service
        target = service.target
        
        self.info(f'Analyzing attack surface for {target.address}')

        # Create analysis directory
        analysis_dir = os.path.join(target.scandir, 'attack_surface_analysis')
        os.makedirs(analysis_dir, exist_ok=True)

        # Gather all discovered services for this target
        discovered_services = self._gather_discovered_services(target)
        
        # Perform attack surface analysis
        analysis_results = {
            'target': target.address,
            'total_services': len(discovered_services),
            'services': discovered_services,
            'attack_vectors': [],
            'risk_assessment': {},
            'recommended_actions': [],
            'attack_scenarios': {}
        }

        # Analyze each service
        for svc_info in discovered_services:
            attack_vectors = self._analyze_service_attack_vectors(svc_info)
            analysis_results['attack_vectors'].extend(attack_vectors)

        # Perform risk assessment
        analysis_results['risk_assessment'] = self._perform_risk_assessment(discovered_services)
        
        # Generate attack scenarios
        if self.get_option('attack_scenarios'):
            scenarios = self.get_option('attack_scenarios').split(',')
            for scenario in scenarios:
                scenario = scenario.strip()
                analysis_results['attack_scenarios'][scenario] = self._generate_attack_scenario(scenario, discovered_services)

        # Generate recommendations
        analysis_results['recommended_actions'] = self._generate_recommendations(analysis_results)

        # Save analysis results
        results_file = os.path.join(analysis_dir, 'attack_surface_analysis.json')
        with open(results_file, 'w') as f:
            json.dump(analysis_results, f, indent=2)

        # Generate human-readable report
        await self._generate_report(target, analysis_results, analysis_dir)

        self.info(f'Attack surface analysis completed. Found {len(analysis_results["attack_vectors"])} potential attack vectors.')

    def _gather_discovered_services(self, target):
        """Gather all discovered services from scan results."""
        services = []
        
        # This is a simplified version - in a real implementation, 
        # you would parse the actual scan results from the target's scandir
        
        # For now, we'll create a basic structure based on common services
        # In reality, this would parse nmap results, service detection output, etc.
        
        try:
            # Try to find scan results files
            scan_files = []
            if os.path.exists(target.scandir):
                for root, dirs, files in os.walk(target.scandir):
                    for file in files:
                        if file.endswith('.txt') or file.endswith('.xml'):
                            scan_files.append(os.path.join(root, file))
            
            # Parse service information from scan files
            for scan_file in scan_files:
                try:
                    with open(scan_file, 'r') as f:
                        content = f.read()
                        services.extend(self._parse_services_from_content(content))
                except:
                    continue
        except:
            pass

        return services

    def _parse_services_from_content(self, content):
        """Parse service information from scan file content."""
        services = []
        
        # Parse nmap-style output
        nmap_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
        matches = re.findall(nmap_pattern, content, re.IGNORECASE)
        
        for match in matches:
            port, protocol, service = match
            services.append({
                'port': int(port),
                'protocol': protocol.lower(),
                'service': service.lower(),
                'state': 'open'
            })

        return services

    def _analyze_service_attack_vectors(self, service):
        """Analyze attack vectors for a specific service."""
        attack_vectors = []
        port = service['port']
        protocol = service['protocol']
        service_name = service['service']

        # Service-specific attack vectors
        service_attacks = {
            'http': [
                {'vector': 'Web Application Attacks', 'risk': 'medium', 'description': 'SQL injection, XSS, CSRF, directory traversal'},
                {'vector': 'Directory Enumeration', 'risk': 'low', 'description': 'Enumerate web directories and files'},
                {'vector': 'Default Credentials', 'risk': 'high', 'description': 'Try default admin credentials'}
            ],
            'https': [
                {'vector': 'SSL/TLS Vulnerabilities', 'risk': 'medium', 'description': 'Check for SSL/TLS misconfigurations'},
                {'vector': 'Certificate Issues', 'risk': 'low', 'description': 'Analyze SSL certificate validity'},
                {'vector': 'Web Application Attacks', 'risk': 'medium', 'description': 'SQL injection, XSS, CSRF, directory traversal'}
            ],
            'ssh': [
                {'vector': 'Brute Force Attack', 'risk': 'medium', 'description': 'Attempt to brute force SSH credentials'},
                {'vector': 'SSH Key Enumeration', 'risk': 'low', 'description': 'Look for exposed SSH keys'},
                {'vector': 'Version Exploits', 'risk': 'high', 'description': 'Check for SSH version-specific vulnerabilities'}
            ],
            'ftp': [
                {'vector': 'Anonymous Login', 'risk': 'medium', 'description': 'Check for anonymous FTP access'},
                {'vector': 'Brute Force Attack', 'risk': 'medium', 'description': 'Attempt to brute force FTP credentials'},
                {'vector': 'Directory Traversal', 'risk': 'high', 'description': 'Test for FTP directory traversal vulnerabilities'}
            ],
            'smb': [
                {'vector': 'SMB Vulnerabilities', 'risk': 'high', 'description': 'Test for EternalBlue and other SMB exploits'},
                {'vector': 'Null Session', 'risk': 'medium', 'description': 'Attempt null session enumeration'},
                {'vector': 'Share Enumeration', 'risk': 'medium', 'description': 'Enumerate accessible SMB shares'}
            ],
            'microsoft-ds': [
                {'vector': 'SMB Vulnerabilities', 'risk': 'high', 'description': 'Test for EternalBlue and other SMB exploits'},
                {'vector': 'Active Directory Attacks', 'risk': 'high', 'description': 'Kerberoasting, ASREPRoasting, DCSync'},
                {'vector': 'Share Enumeration', 'risk': 'medium', 'description': 'Enumerate accessible SMB shares'}
            ],
            'mysql': [
                {'vector': 'Database Brute Force', 'risk': 'medium', 'description': 'Attempt to brute force MySQL credentials'},
                {'vector': 'SQL Injection', 'risk': 'high', 'description': 'Test for SQL injection vulnerabilities'},
                {'vector': 'Privilege Escalation', 'risk': 'high', 'description': 'MySQL UDF and privilege escalation'}
            ],
            'rdp': [
                {'vector': 'BlueKeep Vulnerability', 'risk': 'critical', 'description': 'Test for CVE-2019-0708 BlueKeep'},
                {'vector': 'RDP Brute Force', 'risk': 'medium', 'description': 'Attempt to brute force RDP credentials'},
                {'vector': 'Man-in-the-Middle', 'risk': 'medium', 'description': 'RDP certificate attacks'}
            ]
        }

        # Add service-specific vectors
        if service_name in service_attacks:
            for attack in service_attacks[service_name]:
                attack_vector = attack.copy()
                attack_vector.update({
                    'port': port,
                    'protocol': protocol,
                    'service': service_name
                })
                attack_vectors.append(attack_vector)

        # Add port-specific vectors
        if port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900]:
            attack_vectors.append({
                'vector': 'Service Fingerprinting',
                'risk': 'low',
                'description': f'Fingerprint {service_name} service version and configuration',
                'port': port,
                'protocol': protocol,
                'service': service_name
            })

        return attack_vectors

    def _perform_risk_assessment(self, services):
        """Perform overall risk assessment based on discovered services."""
        risk_assessment = {
            'overall_risk': 'low',
            'high_risk_services': [],
            'medium_risk_services': [],
            'low_risk_services': [],
            'exposed_services_count': len(services),
            'risk_factors': []
        }

        # Define high-risk services
        high_risk_services = ['smb', 'microsoft-ds', 'rdp', 'ftp', 'telnet', 'mysql', 'mssql', 'postgresql']
        medium_risk_services = ['ssh', 'http', 'https', 'pop3', 'imap', 'smtp']

        # Categorize services by risk
        for service in services:
            service_name = service['service']
            if service_name in high_risk_services:
                risk_assessment['high_risk_services'].append(service)
            elif service_name in medium_risk_services:
                risk_assessment['medium_risk_services'].append(service)
            else:
                risk_assessment['low_risk_services'].append(service)

        # Determine overall risk
        if risk_assessment['high_risk_services']:
            risk_assessment['overall_risk'] = 'high'
        elif risk_assessment['medium_risk_services']:
            risk_assessment['overall_risk'] = 'medium'

        # Add risk factors
        if len(services) > 10:
            risk_assessment['risk_factors'].append('Large attack surface (many open ports)')
        
        if any(s['service'] in ['smb', 'microsoft-ds'] for s in services):
            risk_assessment['risk_factors'].append('SMB services exposed (potential for lateral movement)')
            
        if any(s['service'] == 'rdp' for s in services):
            risk_assessment['risk_factors'].append('RDP exposed (high-value target)')
            
        if any(s['service'] in ['mysql', 'mssql', 'postgresql'] for s in services):
            risk_assessment['risk_factors'].append('Database services exposed')

        return risk_assessment

    def _generate_attack_scenario(self, scenario_type, services):
        """Generate attack scenario based on discovered services."""
        scenarios = {
            'web': self._web_attack_scenario(services),
            'network': self._network_attack_scenario(services),
            'lateral': self._lateral_movement_scenario(services),
            'privilege': self._privilege_escalation_scenario(services)
        }
        
        return scenarios.get(scenario_type, {'description': 'No scenario available for this type'})

    def _web_attack_scenario(self, services):
        """Generate web-based attack scenario."""
        web_services = [s for s in services if s['service'] in ['http', 'https']]
        
        if not web_services:
            return {'description': 'No web services detected'}
        
        return {
            'description': 'Web Application Attack Chain',
            'steps': [
                '1. Directory and file enumeration using tools like gobuster/dirbuster',
                '2. Identify web application technology stack',
                '3. Test for common web vulnerabilities (OWASP Top 10)',
                '4. SQL injection testing using sqlmap',
                '5. Cross-site scripting (XSS) testing',
                '6. Authentication bypass attempts',
                '7. File upload vulnerability testing',
                '8. Server-side request forgery (SSRF) testing'
            ],
            'tools': ['gobuster', 'sqlmap', 'burp suite', 'nikto', 'wpscan'],
            'target_services': web_services
        }

    def _network_attack_scenario(self, services):
        """Generate network-based attack scenario."""
        return {
            'description': 'Network Penetration Testing Chain',
            'steps': [
                '1. Service version identification and fingerprinting',
                '2. Vulnerability scanning for known CVEs',
                '3. Brute force attacks on authentication services',
                '4. Exploit known service vulnerabilities',
                '5. Network pivoting and lateral movement',
                '6. Privilege escalation attempts'
            ],
            'tools': ['nmap', 'searchsploit', 'hydra', 'metasploit'],
            'target_services': services
        }

    def _lateral_movement_scenario(self, services):
        """Generate lateral movement scenario."""
        smb_services = [s for s in services if s['service'] in ['smb', 'microsoft-ds']]
        
        return {
            'description': 'Lateral Movement Attack Chain',
            'steps': [
                '1. Initial foothold through vulnerable service',
                '2. Credential harvesting (passwords, hashes, tickets)',
                '3. SMB share enumeration and exploitation',
                '4. Pass-the-hash attacks',
                '5. Kerberos attacks (Golden/Silver tickets)',
                '6. Domain enumeration and privilege escalation'
            ],
            'tools': ['mimikatz', 'crackmapexec', 'impacket', 'bloodhound'],
            'target_services': smb_services
        }

    def _privilege_escalation_scenario(self, services):
        """Generate privilege escalation scenario."""
        return {
            'description': 'Privilege Escalation Chain',
            'steps': [
                '1. Local enumeration of system configuration',
                '2. Identify misconfigured services and permissions',
                '3. Search for SUID/SGID binaries',
                '4. Kernel exploit identification',
                '5. Service exploitation for privilege escalation',
                '6. Persistence mechanism installation'
            ],
            'tools': ['linpeas', 'winpeas', 'linux-exploit-suggester', 'powerup'],
            'target_services': services
        }

    def _generate_recommendations(self, analysis_results):
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        risk_level = analysis_results['risk_assessment']['overall_risk']
        high_risk_services = analysis_results['risk_assessment']['high_risk_services']
        
        # General recommendations
        recommendations.append('Implement network segmentation to limit attack surface')
        recommendations.append('Deploy intrusion detection and prevention systems')
        recommendations.append('Regular vulnerability assessments and penetration testing')
        
        # Service-specific recommendations
        if high_risk_services:
            recommendations.append('Priority: Secure or disable high-risk services immediately')
            
        if any(s['service'] == 'rdp' for s in high_risk_services):
            recommendations.append('RDP: Enable Network Level Authentication and use VPN access')
            
        if any(s['service'] in ['smb', 'microsoft-ds'] for s in high_risk_services):
            recommendations.append('SMB: Disable SMBv1, enable SMB signing, restrict access')
            
        # Risk-based recommendations
        if risk_level == 'high':
            recommendations.append('URGENT: Immediate security review required')
            recommendations.append('Consider temporarily disabling non-essential services')
        elif risk_level == 'medium':
            recommendations.append('Implement additional security controls within 30 days')
        
        return recommendations

    async def _generate_report(self, target, analysis_results, output_dir):
        """Generate human-readable attack surface analysis report."""
        report_file = os.path.join(output_dir, 'attack_surface_report.txt')
        
        with open(report_file, 'w') as f:
            f.write(f'Attack Surface Analysis Report\n')
            f.write(f'Target: {target.address}\n')
            f.write(f'Generated: {target.autorecon.start_time if hasattr(target.autorecon, "start_time") else "Unknown"}\n')
            f.write('=' * 80 + '\n\n')
            
            # Executive Summary
            f.write('EXECUTIVE SUMMARY\n')
            f.write('-' * 40 + '\n')
            f.write(f'Overall Risk Level: {analysis_results["risk_assessment"]["overall_risk"].upper()}\n')
            f.write(f'Total Services Discovered: {analysis_results["total_services"]}\n')
            f.write(f'High-Risk Services: {len(analysis_results["risk_assessment"]["high_risk_services"])}\n')
            f.write(f'Total Attack Vectors Identified: {len(analysis_results["attack_vectors"])}\n\n')
            
            # Risk Assessment
            f.write('RISK ASSESSMENT\n')
            f.write('-' * 40 + '\n')
            risk_assessment = analysis_results['risk_assessment']
            
            if risk_assessment['high_risk_services']:
                f.write('High-Risk Services:\n')
                for service in risk_assessment['high_risk_services']:
                    f.write(f'  - {service["service"]} on port {service["port"]}/{service["protocol"]}\n')
                f.write('\n')
            
            if risk_assessment['risk_factors']:
                f.write('Risk Factors:\n')
                for factor in risk_assessment['risk_factors']:
                    f.write(f'  - {factor}\n')
                f.write('\n')
            
            # Attack Vectors
            f.write('IDENTIFIED ATTACK VECTORS\n')
            f.write('-' * 40 + '\n')
            for vector in analysis_results['attack_vectors']:
                f.write(f'Service: {vector["service"]} (Port {vector["port"]}/{vector["protocol"]})\n')
                f.write(f'Attack Vector: {vector["vector"]}\n')
                f.write(f'Risk Level: {vector["risk"].upper()}\n')
                f.write(f'Description: {vector["description"]}\n')
                f.write('-' * 20 + '\n')
            
            # Recommendations
            f.write('\nRECOMMENDATIONS\n')
            f.write('-' * 40 + '\n')
            for i, recommendation in enumerate(analysis_results['recommended_actions'], 1):
                f.write(f'{i}. {recommendation}\n')

    def manual(self, service, plugin_was_run):
        if not plugin_was_run:
            service.add_manual_command('Manual attack surface analysis:', [
                '# Network enumeration and discovery',
                'nmap -sS -sV -O -A ' + service.target.address,
                'nmap --script vuln ' + service.target.address,
                '',
                '# Service-specific enumeration',
                'nmap --script safe ' + service.target.address,
                'nmap --script discovery ' + service.target.address,
                '',
                '# Attack surface analysis tools',
                'amass enum -d <domain>',
                'sublist3r -d <domain>',
                'gobuster dns -d <domain> -w /usr/share/wordlists/subdomains.txt',
                '',
                '# Vulnerability assessment',
                'nuclei -u http://' + service.target.address,
                'nikto -h ' + service.target.address,
                'dirb http://' + service.target.address,
                '',
                '# Manual analysis considerations:',
                '# 1. Identify all exposed services and versions',
                '# 2. Research known vulnerabilities for each service',
                '# 3. Assess network segmentation and access controls',
                '# 4. Evaluate authentication mechanisms',
                '# 5. Consider business impact of potential attacks',
                '# 6. Prioritize remediation based on risk assessment'
            ])