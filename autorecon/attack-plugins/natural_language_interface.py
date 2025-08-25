#!/usr/bin/python3

import asyncio
import os
import json
import subprocess
import re
from datetime import datetime
from autorecon.plugins import ServiceScan
from autorecon.ai_service import get_ai_assistant

class NaturalLanguageInterface(ServiceScan):
    """Natural language interface for AI-powered penetration testing commands."""

    def __init__(self):
        super().__init__()
        self.name = "Natural Language Pentesting Interface"
        self.description = "AI-powered interface that translates natural language requests into pentesting commands"
        self.type = "ai-interface"
        self.tags = ['ai', 'interface', 'automation', 'natural-language']
        self.priority = 1
        self.run_once_boolean = True
        
        # Plugin options
        self.add_option('request', help='Natural language request (e.g., "get me info on John Smith who lives in Seattle")')
        self.add_option('target-name', help='Name of person/organization to investigate')
        self.add_option('target-location', help='Location information')
        self.add_option('company', help='Company name')
        self.add_option('ai-model', default='llama3.1', help='AI model to use. Default: %(default)s')
        self.add_true_option('interactive', help='Enable interactive mode for follow-up questions')
        self.add_true_option('execute-commands', help='Automatically execute generated commands')
        self.add_option('output-format', default='detailed', help='Output format (brief,detailed,json). Default: %(default)s')
        self.add_true_option('confirm-actions', help='Confirm each action before execution')

    async def run(self, target):
        """Execute natural language pentesting interface."""
        try:
            self.info("Starting Natural Language Pentesting Interface...")
            
            # Get AI assistant
            ai_assistant = get_ai_assistant(model=self.get_option('ai_model'))
            
            # Process the natural language request
            request = self.get_option('request')
            if not request:
                request = self._build_request_from_options()
            
            if not request:
                self.error("No request provided. Use --request option or specify target details.")
                return
            
            self.info(f"Processing request: {request}")
            
            # Parse and understand the request
            parsed_request = await self._parse_request(request, ai_assistant)
            
            # Generate action plan
            action_plan = await self._generate_action_plan(parsed_request, ai_assistant)
            
            # Execute the plan
            results = await self._execute_action_plan(action_plan, target, ai_assistant)
            
            # Save results
            await self._save_results(target, request, parsed_request, action_plan, results)
            
            # Interactive mode for follow-up
            if self.get_option('interactive'):
                await self._interactive_mode(target, results, ai_assistant)
            
            self.info("Natural language interface completed successfully")
            
        except Exception as e:
            self.error(f"Natural language interface failed: {e}")

    def _build_request_from_options(self) -> str:
        """Build request from individual options if no direct request provided."""
        parts = []
        
        target_name = self.get_option('target_name')
        target_location = self.get_option('target_location')
        company = self.get_option('company')
        
        if target_name:
            parts.append(f"get me info on {target_name}")
            
            if target_location:
                parts.append(f"who lives in {target_location}")
                
            if company:
                parts.append(f"who works at {company}")
        
        return " ".join(parts) if parts else ""

    async def _parse_request(self, request: str, ai_assistant) -> dict:
        """Parse and understand the natural language request."""
        system_prompt = """You are a cybersecurity assistant that analyzes natural language requests 
        for penetration testing activities. Parse the request and extract key information including:
        - Type of activity (OSINT, reconnaissance, exploitation, social engineering)
        - Target information (names, locations, companies, domains)
        - Specific objectives
        - Risk level and legal considerations
        
        Return structured information in JSON format."""
        
        prompt = f"""Parse this penetration testing request: "{request}"

        Extract and provide:
        1. Activity type (osint, recon, exploit, social-engineering, etc.)
        2. Target details (name, location, company, domain, IP, etc.)
        3. Specific objectives
        4. Risk assessment
        5. Legal considerations
        6. Recommended tools and techniques
        
        Format as JSON with clear structure."""
        
        response = await ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        # Try to extract JSON from response
        try:
            # Look for JSON in the response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
        except:
            pass
        
        # Fallback to manual parsing
        return self._manual_parse_request(request, response)

    def _manual_parse_request(self, request: str, ai_response: str) -> dict:
        """Manually parse request if JSON extraction fails."""
        request_lower = request.lower()
        
        parsed = {
            'original_request': request,
            'ai_analysis': ai_response,
            'activity_type': 'unknown',
            'target_details': {},
            'objectives': [],
            'risk_level': 'medium',
            'timestamp': datetime.now().isoformat()
        }
        
        # Determine activity type
        if any(word in request_lower for word in ['info on', 'osint', 'intelligence', 'research']):
            parsed['activity_type'] = 'osint'
        elif any(word in request_lower for word in ['spearphish', 'phish', 'social engineering']):
            parsed['activity_type'] = 'social-engineering'
        elif any(word in request_lower for word in ['exploit', 'hack', 'penetrate', 'attack']):
            parsed['activity_type'] = 'exploitation'
        elif any(word in request_lower for word in ['scan', 'reconnaissance', 'recon']):
            parsed['activity_type'] = 'reconnaissance'
        
        # Extract target information
        # Look for names (capitalized words)
        name_matches = re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', request)
        if name_matches:
            parsed['target_details']['name'] = name_matches[0]
        
        # Look for locations
        location_keywords = ['lives in', 'located in', 'from', 'in']
        for keyword in location_keywords:
            if keyword in request_lower:
                location_match = re.search(rf'{keyword}\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', request)
                if location_match:
                    parsed['target_details']['location'] = location_match.group(1)
        
        # Look for companies
        company_keywords = ['works at', 'company', 'organization', 'corp']
        for keyword in company_keywords:
            if keyword in request_lower:
                company_match = re.search(rf'{keyword}\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', request)
                if company_match:
                    parsed['target_details']['company'] = company_match.group(1)
        
        return parsed

    async def _generate_action_plan(self, parsed_request: dict, ai_assistant) -> dict:
        """Generate a detailed action plan based on the parsed request."""
        activity_type = parsed_request.get('activity_type', 'unknown')
        target_details = parsed_request.get('target_details', {})
        
        system_prompt = f"""You are a penetration testing expert. Based on the parsed request, 
        create a detailed action plan for {activity_type} activities. Include specific commands, 
        tools, and techniques. Ensure all activities are for authorized testing only."""
        
        prompt = f"""Create an action plan for this request:
        
        Activity Type: {activity_type}
        Target Details: {json.dumps(target_details, indent=2)}
        Original Request: {parsed_request.get('original_request', '')}
        
        Provide:
        1. Step-by-step action plan
        2. Specific tools and commands to use
        3. Expected outcomes
        4. Risk mitigation strategies
        5. Legal and ethical considerations
        
        Format with clear steps and executable commands."""
        
        response = await ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        # Parse the response into structured plan
        plan = {
            'activity_type': activity_type,
            'target_details': target_details,
            'steps': self._extract_steps(response),
            'commands': self._extract_commands(response),
            'tools': self._extract_tools(response),
            'risks': self._extract_risks(response),
            'estimated_time': self._estimate_time(activity_type),
            'ai_analysis': response,
            'timestamp': datetime.now().isoformat()
        }
        
        return plan

    def _extract_steps(self, response: str) -> list:
        """Extract action steps from AI response."""
        steps = []
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith(('Step', '-', '*', '•'))):
                steps.append(line)
        
        return steps[:10]  # Limit to 10 steps

    def _extract_commands(self, response: str) -> list:
        """Extract executable commands from AI response."""
        commands = []
        lines = response.split('\n')
        
        for line in lines:
            line = line.strip()
            # Look for command-like patterns
            if any(line.startswith(cmd) for cmd in ['nmap', 'theHarvester', 'recon-ng', 'amass', 'subfinder', 'curl', 'dig', 'whois']):
                commands.append(line)
            elif line.startswith('$') or line.startswith('sudo'):
                commands.append(line.replace('$', '').strip())
        
        return commands

    def _extract_tools(self, response: str) -> list:
        """Extract tool names from AI response."""
        common_tools = [
            'nmap', 'theharvester', 'recon-ng', 'amass', 'subfinder', 'gobuster',
            'dirb', 'nikto', 'sqlmap', 'hydra', 'john', 'hashcat', 'metasploit',
            'burp', 'zap', 'wireshark', 'aircrack-ng', 'social-engineer-toolkit'
        ]
        
        tools = []
        response_lower = response.lower()
        
        for tool in common_tools:
            if tool in response_lower:
                tools.append(tool)
        
        return list(set(tools))  # Remove duplicates

    def _extract_risks(self, response: str) -> list:
        """Extract risk factors from AI response."""
        risks = []
        lines = response.split('\n')
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['risk', 'danger', 'caution', 'warning', 'legal']):
                risks.append(line.strip())
        
        return risks[:5]  # Limit to 5 risks

    def _estimate_time(self, activity_type: str) -> str:
        """Estimate time requirements for different activity types."""
        time_estimates = {
            'osint': '30-60 minutes',
            'reconnaissance': '1-2 hours',
            'social-engineering': '2-4 hours',
            'exploitation': '1-3 hours',
            'post-exploitation': '1-2 hours'
        }
        
        return time_estimates.get(activity_type, '1-2 hours')

    async def _execute_action_plan(self, action_plan: dict, target, ai_assistant) -> dict:
        """Execute the generated action plan."""
        results = {
            'plan_executed': action_plan,
            'command_results': [],
            'tool_outputs': {},
            'findings': [],
            'errors': [],
            'timestamp': datetime.now().isoformat()
        }
        
        activity_type = action_plan.get('activity_type', 'unknown')
        
        self.info(f"Executing {activity_type} action plan with {len(action_plan.get('steps', []))} steps")
        
        # Execute based on activity type
        if activity_type == 'osint':
            results.update(await self._execute_osint_plan(action_plan, target, ai_assistant))
        elif activity_type == 'reconnaissance':
            results.update(await self._execute_recon_plan(action_plan, target))
        elif activity_type == 'social-engineering':
            results.update(await self._execute_social_engineering_plan(action_plan, target, ai_assistant))
        elif activity_type == 'exploitation':
            results.update(await self._execute_exploitation_plan(action_plan, target, ai_assistant))
        
        return results

    async def _execute_osint_plan(self, action_plan: dict, target, ai_assistant) -> dict:
        """Execute OSINT-specific action plan."""
        osint_results = {
            'search_results': {},
            'social_media_findings': {},
            'domain_information': {},
            'public_records': {}
        }
        
        target_details = action_plan.get('target_details', {})
        target_name = target_details.get('name', '')
        target_location = target_details.get('location', '')
        company = target_details.get('company', '')
        
        # Generate OSINT strategy using existing AI-OSINT plugin
        if target_name:
            self.info(f"Performing OSINT on {target_name}")
            
            # Use AI to generate search queries
            search_strategy = await ai_assistant.generate_osint_strategy(target_name, target_location)
            osint_results['ai_strategy'] = search_strategy
            
            # Simulate search execution (in real implementation, would use APIs or web scraping)
            for query in search_strategy.get('search_queries', [])[:3]:
                self.info(f"Simulating search: {query}")
                osint_results['search_results'][query] = {
                    'query': query,
                    'timestamp': datetime.now().isoformat(),
                    'status': 'simulated',
                    'note': 'Manual execution required for actual searches'
                }
        
        return osint_results

    async def _execute_recon_plan(self, action_plan: dict, target) -> dict:
        """Execute reconnaissance action plan."""
        recon_results = {
            'network_scan': {},
            'service_enumeration': {},
            'web_reconnaissance': {}
        }
        
        # Execute reconnaissance commands
        for command in action_plan.get('commands', []):
            if not self.get_option('execute_commands'):
                self.info(f"Would execute: {command}")
                continue
            
            if self.get_option('confirm_actions'):
                self.info(f"Execute command: {command}? (simulated)")
            
            try:
                self.info(f"Executing: {command}")
                result = subprocess.run(command.split(), capture_output=True, text=True, timeout=60)
                recon_results['network_scan'][command] = {
                    'output': result.stdout,
                    'error': result.stderr,
                    'returncode': result.returncode
                }
            except Exception as e:
                recon_results['network_scan'][command] = {'error': str(e)}
        
        return recon_results

    async def _execute_social_engineering_plan(self, action_plan: dict, target, ai_assistant) -> dict:
        """Execute social engineering action plan."""
        se_results = {
            'phishing_templates': [],
            'pretext_scenarios': [],
            'target_profiles': {}
        }
        
        target_details = action_plan.get('target_details', {})
        
        # Generate phishing templates
        self.info("Generating AI-powered phishing templates...")
        for i in range(3):  # Generate 3 variants
            template = await ai_assistant.generate_phishing_email(target_details, f"variant_{i+1}")
            se_results['phishing_templates'].append(template)
        
        # Generate pretext scenarios
        pretext_prompt = f"""Generate social engineering pretext scenarios for targeting:
        {json.dumps(target_details, indent=2)}
        
        Create 3 different scenarios for phone-based social engineering."""
        
        pretext_response = await ai_assistant.ollama.generate_text(pretext_prompt)
        se_results['pretext_scenarios'] = [pretext_response]
        
        return se_results

    async def _execute_exploitation_plan(self, action_plan: dict, target, ai_assistant) -> dict:
        """Execute exploitation action plan."""
        exploit_results = {
            'vulnerability_scan': {},
            'exploit_attempts': [],
            'metasploit_commands': []
        }
        
        # Generate Metasploit commands
        target_info = {
            'ip': str(target),
            'port': '80',  # Default
            'service': 'http'
        }
        
        msf_commands = await ai_assistant.generate_metasploit_commands(target_info, "web application")
        exploit_results['metasploit_commands'] = msf_commands
        
        # Log exploitation attempts (without actual execution for safety)
        for command in msf_commands:
            self.info(f"Generated MSF command: {command}")
            exploit_results['exploit_attempts'].append({
                'command': command,
                'status': 'generated',
                'note': 'Manual execution required'
            })
        
        return exploit_results

    async def _interactive_mode(self, target, results: dict, ai_assistant):
        """Interactive mode for follow-up questions and guidance."""
        self.info("Entering interactive mode...")
        self.info("AI Assistant is ready for follow-up questions.")
        
        # Simulate some common follow-up scenarios
        follow_up_scenarios = [
            "What should I do next based on these results?",
            "How can I escalate my access?",
            "What are the best social engineering approaches for this target?",
            "Generate a report of findings"
        ]
        
        for scenario in follow_up_scenarios:
            self.info(f"Sample question: {scenario}")
            
            context = {
                'previous_results': results,
                'target': str(target),
                'question': scenario
            }
            
            messages = [
                {"role": "system", "content": "You are a penetration testing expert providing guidance."},
                {"role": "user", "content": f"Based on these results: {json.dumps(context, indent=2)}, {scenario}"}
            ]
            
            response = await ai_assistant.ollama.chat_completion(messages)
            self.info(f"AI Response: {response[:200]}...")
            
            await asyncio.sleep(1)

    async def _save_results(self, target, request: str, parsed_request: dict, action_plan: dict, results: dict):
        """Save comprehensive results from natural language interface."""
        comprehensive_results = {
            'original_request': request,
            'parsed_request': parsed_request,
            'action_plan': action_plan,
            'execution_results': results,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'ai_model': self.get_option('ai_model'),
                'target': str(target),
                'output_format': self.get_option('output_format')
            }
        }
        
        # Save main results
        output_dir = os.path.join(self.output_dir, 'ai_interface')
        os.makedirs(output_dir, exist_ok=True)
        
        results_file = os.path.join(output_dir, f'nl_interface_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        with open(results_file, 'w') as f:
            json.dump(comprehensive_results, f, indent=2)
        
        # Generate human-readable summary
        summary_file = os.path.join(output_dir, f'summary_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
        with open(summary_file, 'w') as f:
            f.write("# Natural Language Pentesting Interface Results\n\n")
            f.write(f"Original Request: {request}\n\n")
            f.write(f"Activity Type: {parsed_request.get('activity_type', 'unknown')}\n")
            f.write(f"Target Details: {json.dumps(parsed_request.get('target_details', {}), indent=2)}\n\n")
            
            f.write("## Action Plan Steps\n")
            for i, step in enumerate(action_plan.get('steps', []), 1):
                f.write(f"{i}. {step}\n")
            
            f.write("\n## Generated Commands\n")
            for cmd in action_plan.get('commands', []):
                f.write(f"- {cmd}\n")
            
            f.write("\n## Recommended Tools\n")
            for tool in action_plan.get('tools', []):
                f.write(f"- {tool}\n")
        
        # Generate execution script
        script_file = os.path.join(output_dir, f'execution_script_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sh')
        with open(script_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# AI-Generated Execution Script\n")
            f.write(f"# Original Request: {request}\n\n")
            
            for cmd in action_plan.get('commands', []):
                f.write(f"echo 'Executing: {cmd}'\n")
                f.write(f"# {cmd}\n\n")
        
        os.chmod(script_file, 0o755)
        
        self.info(f"Results saved to {output_dir}")
        self.info(f"Summary: {summary_file}")
        self.info(f"Execution script: {script_file}")

    def get_option(self, name):
        """Get plugin option value."""
        return getattr(self.autorecon.args, name.replace('-', '_'), None)