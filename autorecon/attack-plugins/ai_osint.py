#!/usr/bin/python3

import asyncio
import os
import json
import requests
import re
from datetime import datetime
from autorecon.plugins import ServiceScan
from autorecon.ai_service import get_ai_assistant

class AIOSINTPlugin(ServiceScan):
    """AI-powered OSINT (Open Source Intelligence) gathering plugin."""

    def __init__(self):
        super().__init__()
        self.name = "AI-Powered OSINT Collector"
        self.description = "Uses AI to gather open source intelligence on targets including people, organizations, and domains"
        self.type = "osint"
        self.tags = ['ai', 'osint', 'recon', 'social-engineering']
        self.priority = 1
        self.run_once_boolean = True
        
        # Plugin options
        self.add_option('target-name', help='Name of person/organization to investigate')
        self.add_option('target-location', help='Location information for the target')
        self.add_option('company', help='Company/organization associated with target')
        self.add_option('role', help='Role/position of the target')
        self.add_option('email-domain', help='Email domain to investigate')
        self.add_option('social-media', default='all', help='Social media platforms to search (linkedin,facebook,twitter,instagram,all)')
        self.add_option('search-depth', default='medium', help='Search depth (basic,medium,deep)')
        self.add_option('output-format', default='json', help='Output format (json,text,html)')
        self.add_true_option('interactive', help='Enable interactive mode for AI assistance')
        self.add_true_option('generate-profile', help='Generate comprehensive target profile')
        self.add_option('ollama-model', default='llama3.1', help='Ollama model to use for AI analysis')

    async def run(self, target):
        """Execute AI-powered OSINT collection."""
        try:
            self.info("Starting AI-powered OSINT collection...")
            
            # Get AI assistant
            ai_assistant = get_ai_assistant(model=self.get_option('ollama-model'))
            
            # Gather target information
            target_info = self._gather_target_info(target)
            
            # Generate OSINT strategy
            strategy = await ai_assistant.generate_osint_strategy(
                target_info.get('name', str(target)),
                target_info.get('location')
            )
            
            # Execute OSINT collection
            results = await self._execute_osint_collection(target_info, strategy, ai_assistant)
            
            # Generate comprehensive profile if requested
            if self.get_option('generate-profile'):
                profile = await self._generate_target_profile(target_info, results, ai_assistant)
                results['target_profile'] = profile
            
            # Save results
            await self._save_results(target, results)
            
            # Interactive mode
            if self.get_option('interactive'):
                await self._interactive_mode(target_info, results, ai_assistant)
            
            self.info("OSINT collection completed successfully")
            
        except Exception as e:
            self.error(f"OSINT collection failed: {e}")

    def _gather_target_info(self, target) -> dict:
        """Gather initial target information from options."""
        target_info = {
            'target': str(target),
            'name': self.get_option('target-name'),
            'location': self.get_option('target-location'),
            'company': self.get_option('company'),
            'role': self.get_option('role'),
            'email_domain': self.get_option('email-domain'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Remove None values
        return {k: v for k, v in target_info.items() if v is not None}

    async def _execute_osint_collection(self, target_info: dict, strategy: dict, ai_assistant) -> dict:
        """Execute the OSINT collection strategy."""
        results = {
            'strategy': strategy,
            'search_results': {},
            'social_media': {},
            'technical_footprint': {},
            'public_records': {},
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'search_depth': self.get_option('search-depth'),
                'platforms': self.get_option('social-media')
            }
        }
        
        # Execute search queries from AI strategy
        if 'search_queries' in strategy:
            for query in strategy['search_queries'][:5]:  # Limit to 5 queries
                self.info(f"Executing search query: {query}")
                search_results = await self._execute_search_query(query)
                results['search_results'][query] = search_results
        
        # Social media investigation
        await self._investigate_social_media(target_info, results)
        
        # Domain and email investigation
        if target_info.get('email_domain'):
            await self._investigate_domain(target_info['email_domain'], results)
        
        # Professional networks
        await self._investigate_professional_networks(target_info, results)
        
        return results

    async def _execute_search_query(self, query: str) -> dict:
        """Execute a search query and return results."""
        try:
            # This is a placeholder for actual search implementation
            # In a real implementation, you would use search APIs or web scraping
            self.info(f"Simulating search for: {query}")
            
            return {
                'query': query,
                'timestamp': datetime.now().isoformat(),
                'results': f"Simulated search results for: {query}",
                'status': 'completed'
            }
        except Exception as e:
            self.warn(f"Search query failed: {e}")
            return {'query': query, 'error': str(e), 'status': 'failed'}

    async def _investigate_social_media(self, target_info: dict, results: dict):
        """Investigate social media presence."""
        platforms = self.get_option('social-media').split(',') if self.get_option('social-media') != 'all' else [
            'linkedin', 'facebook', 'twitter', 'instagram', 'github'
        ]
        
        for platform in platforms:
            self.info(f"Investigating {platform} presence...")
            results['social_media'][platform] = await self._check_platform(target_info, platform)

    async def _check_platform(self, target_info: dict, platform: str) -> dict:
        """Check for presence on a specific platform."""
        # This is a placeholder for actual social media investigation
        # In real implementation, you would use appropriate APIs or techniques
        
        name = target_info.get('name', '')
        if not name:
            return {'status': 'skipped', 'reason': 'No target name provided'}
        
        return {
            'platform': platform,
            'search_terms': [name, f"{name} {target_info.get('company', '')}", 
                           f"{name} {target_info.get('location', '')}"],
            'timestamp': datetime.now().isoformat(),
            'status': 'investigated',
            'notes': f"Manual investigation required for {platform}"
        }

    async def _investigate_domain(self, domain: str, results: dict):
        """Investigate domain and email patterns."""
        self.info(f"Investigating domain: {domain}")
        
        domain_info = {
            'domain': domain,
            'whois_lookup': f"whois {domain}",
            'dns_records': f"dig {domain} ANY",
            'email_patterns': [
                f"firstname.lastname@{domain}",
                f"firstname@{domain}",
                f"flastname@{domain}",
                f"first.last@{domain}"
            ],
            'subdomains': f"subfinder -d {domain}",
            'certificate_transparency': f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json'",
            'timestamp': datetime.now().isoformat()
        }
        
        results['technical_footprint']['domain'] = domain_info

    async def _investigate_professional_networks(self, target_info: dict, results: dict):
        """Investigate professional network presence."""
        networks = ['linkedin', 'github', 'stack-overflow', 'academia', 'researchgate']
        
        for network in networks:
            self.info(f"Checking {network} presence...")
            results['social_media'][f"{network}_professional"] = {
                'network': network,
                'search_strategy': f"Search for {target_info.get('name', '')} in {network}",
                'timestamp': datetime.now().isoformat()
            }

    async def _generate_target_profile(self, target_info: dict, results: dict, ai_assistant) -> dict:
        """Generate comprehensive target profile using AI."""
        self.info("Generating AI-powered target profile...")
        
        # Prepare data for AI analysis
        analysis_data = {
            'target_info': target_info,
            'osint_results': results,
            'findings_summary': self._summarize_findings(results)
        }
        
        # Get AI analysis
        profile_analysis = await ai_assistant.analyze_target_profile(analysis_data)
        
        return {
            'ai_analysis': profile_analysis,
            'risk_assessment': profile_analysis.get('risk_level', 'medium'),
            'attack_vectors': profile_analysis.get('attack_vectors', []),
            'recommendations': self._generate_recommendations(profile_analysis),
            'timestamp': datetime.now().isoformat()
        }

    def _summarize_findings(self, results: dict) -> str:
        """Summarize OSINT findings for AI analysis."""
        summary = []
        
        if results.get('search_results'):
            summary.append(f"Executed {len(results['search_results'])} search queries")
        
        if results.get('social_media'):
            summary.append(f"Investigated {len(results['social_media'])} social media platforms")
        
        if results.get('technical_footprint'):
            summary.append("Performed technical footprint analysis")
        
        return "; ".join(summary)

    def _generate_recommendations(self, profile_analysis: dict) -> list:
        """Generate actionable recommendations based on AI analysis."""
        recommendations = []
        
        risk_level = profile_analysis.get('risk_level', 'medium')
        
        if risk_level in ['high', 'critical']:
            recommendations.extend([
                "Consider targeted phishing campaigns",
                "Investigate privilege escalation opportunities",
                "Plan multi-vector attack approach"
            ])
        elif risk_level == 'medium':
            recommendations.extend([
                "Focus on social engineering approaches",
                "Gather additional technical intelligence",
                "Plan credential harvesting operations"
            ])
        else:
            recommendations.extend([
                "Continue passive reconnaissance",
                "Build comprehensive target database",
                "Monitor for security awareness changes"
            ])
        
        return recommendations

    async def _interactive_mode(self, target_info: dict, results: dict, ai_assistant):
        """Interactive mode for AI-assisted OSINT analysis."""
        self.info("Entering interactive AI mode...")
        self.info("You can ask questions about the target or request additional analysis.")
        self.info("Example: 'What are the best attack vectors for this target?'")
        self.info("Type 'exit' to quit interactive mode.")
        
        while True:
            try:
                # In a real implementation, you would get user input here
                # For now, we'll simulate some common queries
                sample_queries = [
                    "What are the most promising attack vectors?",
                    "Generate a phishing campaign strategy",
                    "What additional reconnaissance is needed?"
                ]
                
                for query in sample_queries:
                    self.info(f"Sample query: {query}")
                    
                    # Prepare context for AI
                    context = {
                        'target_info': target_info,
                        'osint_results': results,
                        'user_query': query
                    }
                    
                    # Get AI response
                    messages = [
                        {"role": "system", "content": "You are a cybersecurity expert providing OSINT analysis."},
                        {"role": "user", "content": f"Based on this data: {json.dumps(context, indent=2)}, answer: {query}"}
                    ]
                    
                    response = await ai_assistant.ollama.chat_completion(messages)
                    self.info(f"AI Response: {response}")
                
                break  # Exit after sample queries
                
            except KeyboardInterrupt:
                self.info("Exiting interactive mode...")
                break

    async def _save_results(self, target, results: dict):
        """Save OSINT results to files."""
        output_dir = os.path.join(self.output_dir, 'osint')
        os.makedirs(output_dir, exist_ok=True)
        
        # Save main results
        results_file = os.path.join(output_dir, f'osint_results_{target}.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Save search queries for manual execution
        queries_file = os.path.join(output_dir, f'search_queries_{target}.txt')
        with open(queries_file, 'w') as f:
            if 'strategy' in results and 'search_queries' in results['strategy']:
                f.write("# AI-Generated Search Queries\n\n")
                for query in results['strategy']['search_queries']:
                    f.write(f"{query}\n")
        
        # Save manual commands
        commands_file = os.path.join(output_dir, f'manual_commands_{target}.txt')
        with open(commands_file, 'w') as f:
            f.write("# Manual OSINT Commands\n\n")
            f.write("# Domain Investigation\n")
            if results.get('technical_footprint', {}).get('domain'):
                domain_info = results['technical_footprint']['domain']
                f.write(f"whois {domain_info['domain']}\n")
                f.write(f"dig {domain_info['domain']} ANY\n")
                f.write(f"subfinder -d {domain_info['domain']}\n")
                f.write(f"curl -s 'https://crt.sh/?q=%25.{domain_info['domain']}&output=json'\n\n")
            
            f.write("# Social Media Investigation\n")
            for platform, info in results.get('social_media', {}).items():
                if isinstance(info, dict) and 'search_terms' in info:
                    f.write(f"# {platform.title()}:\n")
                    for term in info['search_terms']:
                        f.write(f"# Manual search: {term}\n")
                    f.write("\n")
        
        self.info(f"Results saved to {output_dir}")

    def get_option(self, name):
        """Get plugin option value."""
        return getattr(self.autorecon.args, name.replace('-', '_'), None)