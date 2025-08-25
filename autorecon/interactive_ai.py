#!/usr/bin/python3

import asyncio
import os
import json
import re
import sys
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from autorecon.ai_service import get_ai_assistant, get_ai_service
from autorecon.io import info, warn, error, debug, cprint
from autorecon.targets import Target

class InteractiveAI:
    """Interactive AI terminal interface for comprehensive penetration testing."""
    
    def __init__(self, ollama_url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.ai_service = get_ai_service(ollama_url, model)
        self.ai_assistant = get_ai_assistant(ollama_url, model)
        self.conversation_history = []
        self.current_session = {
            'start_time': datetime.now(),
            'targets': [],
            'scope': {},
            'findings': [],
            'actions_taken': [],
            'reports': []
        }
        self.dangerous_keywords = [
            'attack', 'exploit', 'hack', 'penetrate', 'compromise', 'break',
            'crack', 'brute', 'inject', 'overflow', 'shell', 'payload',
            'backdoor', 'persistence', 'escalate', 'dump', 'extract'
        ]
        self.file_keywords = [
            'create', 'write', 'save', 'generate file', 'make file', 'output'
        ]
        
    async def start_interactive_session(self, scope_file: Optional[str] = None, initial_prompt: Optional[str] = None):
        """Start the interactive AI pentesting session."""
        try:
            cprint('\n{bgreen}╔══════════════════════════════════════════════════════════════════════════════════╗{rst}')
            cprint('{bgreen}║                     AutoRecon AI Interactive Pentesting Interface                   ║{rst}')
            cprint('{bgreen}╚══════════════════════════════════════════════════════════════════════════════════╝{rst}\n')
            
            info("Welcome to AutoRecon AI Interactive Mode")
            info("Powered by advanced AI for comprehensive penetration testing")
            warn("WARNING: This interface can execute dangerous commands. Use only on authorized targets.")
            
            # Load scope if provided
            if scope_file:
                await self._load_scope_file(scope_file)
            
            # Handle initial prompt if provided
            if initial_prompt:
                info(f"Processing initial prompt: {initial_prompt}")
                await self._process_user_input(initial_prompt)
            
            info("\nType your requests in natural language. Type 'exit' to quit and generate report.")
            info("Examples:")
            info("  > get me info on John Smith who lives in Seattle")
            info("  > I want to spearphish employees at TechCorp")
            info("  > confirm attack example.com with metasploit reverse shells")
            info("  > generate phishing templates for IT department")
            
            # Main interaction loop
            while True:
                try:
                    # Display prompt
                    user_input = input("\n> ").strip()
                    
                    if not user_input:
                        continue
                    
                    if user_input.lower() in ['exit', 'quit', 'done']:
                        break
                    
                    if user_input.lower() in ['help', '?']:
                        self._show_help()
                        continue
                        
                    if user_input.lower() == 'status':
                        self._show_status()
                        continue
                        
                    if user_input.lower() == 'history':
                        self._show_history()
                        continue
                    
                    # Process the user input
                    await self._process_user_input(user_input)
                    
                except KeyboardInterrupt:
                    cprint("\n{yellow}Interrupted by user. Type 'exit' to quit properly.{rst}")
                    continue
                except EOFError:
                    break
            
            # Generate final report
            await self._generate_final_report()
            
        except Exception as e:
            error(f"Interactive session failed: {e}")
            
    async def _load_scope_file(self, scope_file: str):
        """Load scope from file."""
        try:
            if not os.path.exists(scope_file):
                error(f"Scope file not found: {scope_file}")
                return
            
            with open(scope_file, 'r') as f:
                content = f.read().strip()
            
            # Try to parse as JSON first
            try:
                scope_data = json.loads(content)
                self.current_session['scope'] = scope_data
                info(f"Loaded JSON scope with {len(scope_data.get('targets', []))} targets")
            except json.JSONDecodeError:
                # Parse as plain text (one target per line)
                targets = [line.strip() for line in content.split('\n') if line.strip()]
                self.current_session['scope'] = {
                    'targets': targets,
                    'description': 'Loaded from scope file'
                }
                info(f"Loaded text scope with {len(targets)} targets")
                
        except Exception as e:
            error(f"Failed to load scope file: {e}")
    
    async def _process_user_input(self, user_input: str):
        """Process natural language input from user."""
        try:
            # Add to conversation history
            self.conversation_history.append({
                'timestamp': datetime.now().isoformat(),
                'user_input': user_input,
                'type': 'user_request'
            })
            
            info(f"Processing: {user_input}")
            
            # Check if this is a confirmed action (bypasses confirmation)
            is_confirmed = user_input.lower().startswith('confirm ')
            if is_confirmed:
                user_input = user_input[8:].strip()  # Remove 'confirm ' prefix
                info("Action pre-confirmed by user")
            
            # Parse the request using AI
            parsed_request = await self._parse_request_with_ai(user_input)
            
            # Check for dangerous actions
            if not is_confirmed and self._is_dangerous_action(user_input, parsed_request):
                if not await self._confirm_dangerous_action(user_input, parsed_request):
                    info("Action cancelled by user")
                    return
            
            # Execute the parsed request
            results = await self._execute_request(parsed_request)
            
            # Save results to session
            self.current_session['actions_taken'].append({
                'timestamp': datetime.now().isoformat(),
                'user_input': user_input,
                'parsed_request': parsed_request,
                'results': results,
                'confirmed': is_confirmed
            })
            
            # Display results summary
            await self._display_results_summary(results)
            
        except Exception as e:
            error(f"Failed to process input: {e}")
    
    async def _parse_request_with_ai(self, user_input: str) -> Dict[str, Any]:
        """Parse user input using AI to understand intent and extract parameters."""
        system_prompt = """You are an AI assistant for penetration testing. Parse the user's natural language request and extract:
        1. Action type (osint, reconnaissance, social_engineering, exploitation, reporting, help)
        2. Target information (names, companies, domains, IPs)
        3. Specific techniques or tools requested
        4. Risk level of the action
        5. Whether this involves file creation or dangerous activities
        
        Return structured JSON with clear categorization."""
        
        prompt = f"""Parse this penetration testing request: "{user_input}"

        Categorize the request and extract:
        - action_type: primary action (osint, recon, social_engineering, exploitation, reporting, etc.)
        - targets: any mentioned targets (people, companies, domains, IPs)
        - techniques: specific methods or tools mentioned
        - risk_level: low, medium, high, critical
        - involves_files: true if creating/writing files
        - involves_attacks: true if performing attacks or exploitation
        - specific_requests: detailed breakdown of what user wants
        
        Return only valid JSON format."""
        
        response = await self.ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        try:
            # Extract JSON from response
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                return parsed
        except:
            pass
        
        # Fallback manual parsing
        return self._manual_parse_request(user_input, response)
    
    def _manual_parse_request(self, user_input: str, ai_response: str) -> Dict[str, Any]:
        """Manual fallback parsing when JSON extraction fails."""
        request_lower = user_input.lower()
        
        parsed = {
            'original_request': user_input,
            'ai_analysis': ai_response,
            'action_type': 'unknown',
            'targets': [],
            'techniques': [],
            'risk_level': 'medium',
            'involves_files': False,
            'involves_attacks': False,
            'specific_requests': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # Determine action type
        if any(word in request_lower for word in ['info on', 'osint', 'intelligence', 'research', 'investigate']):
            parsed['action_type'] = 'osint'
        elif any(word in request_lower for word in ['spearphish', 'phish', 'social engineering', 'pretext']):
            parsed['action_type'] = 'social_engineering'
            parsed['involves_attacks'] = True
        elif any(word in request_lower for word in ['exploit', 'hack', 'penetrate', 'attack', 'metasploit', 'shell']):
            parsed['action_type'] = 'exploitation'
            parsed['involves_attacks'] = True
            parsed['risk_level'] = 'high'
        elif any(word in request_lower for word in ['scan', 'reconnaissance', 'recon', 'enumerate']):
            parsed['action_type'] = 'reconnaissance'
        elif any(word in request_lower for word in ['report', 'summary', 'document']):
            parsed['action_type'] = 'reporting'
        
        # Check for file operations
        if any(word in request_lower for word in self.file_keywords):
            parsed['involves_files'] = True
        
        # Extract targets (look for common patterns)
        # Names (capitalized words)
        name_matches = re.findall(r'\b[A-Z][a-z]+ [A-Z][a-z]+\b', user_input)
        parsed['targets'].extend(name_matches)
        
        # Domains
        domain_matches = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', user_input)
        parsed['targets'].extend(domain_matches)
        
        # IPs
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_input)
        parsed['targets'].extend(ip_matches)
        
        # Companies (look for Corp, Inc, LLC, etc.)
        company_matches = re.findall(r'\b[A-Z][a-zA-Z]*(?:Corp|Inc|LLC|Ltd|Company|Technologies|Tech)\b', user_input)
        parsed['targets'].extend(company_matches)
        
        return parsed
    
    def _is_dangerous_action(self, user_input: str, parsed_request: Dict[str, Any]) -> bool:
        """Determine if the action requires confirmation."""
        request_lower = user_input.lower()
        
        # Check for dangerous keywords
        has_dangerous_keywords = any(keyword in request_lower for keyword in self.dangerous_keywords)
        
        # Check parsed request indicators
        involves_attacks = parsed_request.get('involves_attacks', False)
        involves_files = parsed_request.get('involves_files', False)
        high_risk = parsed_request.get('risk_level', 'low') in ['high', 'critical']
        
        return has_dangerous_keywords or involves_attacks or involves_files or high_risk
    
    async def _confirm_dangerous_action(self, user_input: str, parsed_request: Dict[str, Any]) -> bool:
        """Ask user to confirm dangerous actions."""
        action_type = parsed_request.get('action_type', 'unknown')
        targets = parsed_request.get('targets', [])
        risk_level = parsed_request.get('risk_level', 'unknown')
        
        warn("\n⚠️  CONFIRMATION REQUIRED ⚠️")
        warn(f"Action Type: {action_type}")
        warn(f"Risk Level: {risk_level}")
        
        if targets:
            warn(f"Targets: {', '.join(targets[:5])}")
        
        if parsed_request.get('involves_attacks'):
            warn("This action involves OFFENSIVE capabilities")
        
        if parsed_request.get('involves_files'):
            warn("This action will CREATE or MODIFY files")
        
        cprint(f"\nRequest: {user_input}", 'yellow')
        
        while True:
            response = input("\nDo you want to proceed? [y/N/details]: ").strip().lower()
            
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no', '']:
                return False
            elif response in ['d', 'details']:
                # Show more details using AI
                await self._show_action_details(parsed_request)
            else:
                print("Please enter 'y' for yes, 'n' for no, or 'd' for details")
    
    async def _show_action_details(self, parsed_request: Dict[str, Any]):
        """Show detailed information about the planned action."""
        system_prompt = """You are a cybersecurity expert. Explain the potential risks, 
        legal considerations, and technical details of the planned penetration testing action.
        Be clear about what the action will do and potential consequences."""
        
        prompt = f"""Explain the details of this penetration testing action:
        {json.dumps(parsed_request, indent=2)}
        
        Cover:
        1. What exactly will be done
        2. Potential risks and consequences
        3. Legal and ethical considerations
        4. Technical impact
        5. Recommended precautions"""
        
        details = await self.ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        cprint("\n📋 ACTION DETAILS:", 'cyan')
        cprint(details[:800] + "..." if len(details) > 800 else details, 'white')
    
    async def _execute_request(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the parsed request and return results."""
        action_type = parsed_request.get('action_type', 'unknown')
        
        info(f"Executing {action_type} action...")
        
        results = {
            'action_type': action_type,
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'outputs': {},
            'errors': [],
            'generated_files': [],
            'commands_executed': []
        }
        
        try:
            if action_type == 'osint':
                results.update(await self._execute_osint(parsed_request))
            elif action_type == 'reconnaissance':
                results.update(await self._execute_reconnaissance(parsed_request))
            elif action_type == 'social_engineering':
                results.update(await self._execute_social_engineering(parsed_request))
            elif action_type == 'exploitation':
                results.update(await self._execute_exploitation(parsed_request))
            elif action_type == 'reporting':
                results.update(await self._execute_reporting(parsed_request))
            else:
                results.update(await self._execute_general_ai_request(parsed_request))
            
            results['success'] = True
            
        except Exception as e:
            error(f"Execution failed: {e}")
            results['errors'].append(str(e))
        
        return results
    
    async def _execute_osint(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute OSINT operations."""
        targets = parsed_request.get('targets', [])
        
        osint_results = {
            'target_profiles': {},
            'search_strategies': {},
            'intelligence_gathered': {}
        }
        
        for target in targets[:3]:  # Limit to 3 targets
            info(f"Performing OSINT on: {target}")
            
            # Generate OSINT strategy
            strategy = await self.ai_assistant.generate_osint_strategy(target)
            osint_results['search_strategies'][target] = strategy
            
            # Simulate intelligence gathering
            profile = await self.ai_assistant.analyze_target_profile({'name': target})
            osint_results['target_profiles'][target] = profile
            
            info(f"Generated OSINT strategy for {target}")
        
        return osint_results
    
    async def _execute_social_engineering(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute social engineering operations."""
        targets = parsed_request.get('targets', [])
        
        se_results = {
            'phishing_campaigns': {},
            'pretext_scenarios': {},
            'generated_templates': []
        }
        
        for target in targets[:2]:  # Limit to 2 targets
            info(f"Generating social engineering content for: {target}")
            
            target_info = {
                'name': target if not '.' in target else target.split('.')[0],
                'company': target if '.' in target else 'Target Organization'
            }
            
            # Generate phishing emails
            for variant in range(3):
                template = await self.ai_assistant.generate_phishing_email(
                    target_info, f"variant_{variant+1}"
                )
                se_results['generated_templates'].append(template)
            
            se_results['phishing_campaigns'][target] = {
                'target_info': target_info,
                'templates_generated': 3,
                'status': 'completed'
            }
            
            info(f"Generated social engineering content for {target}")
        
        return se_results
    
    async def _execute_exploitation(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute exploitation operations."""
        targets = parsed_request.get('targets', [])
        
        exploit_results = {
            'attack_plans': {},
            'metasploit_commands': {},
            'exploit_scenarios': {}
        }
        
        for target in targets[:2]:  # Limit to 2 targets
            info(f"Generating exploitation plan for: {target}")
            
            target_info = {
                'ip': target if '.' in target and target.replace('.', '').isdigit() else '10.0.0.1',
                'domain': target if '.' in target and not target.replace('.', '').isdigit() else target
            }
            
            # Generate attack plan
            attack_plan = await self.ai_assistant.suggest_attack_chain({'target': target_info})
            exploit_results['attack_plans'][target] = attack_plan
            
            # Generate Metasploit commands
            msf_commands = await self.ai_assistant.generate_metasploit_commands(
                target_info, "web application vulnerabilities"
            )
            exploit_results['metasploit_commands'][target] = msf_commands
            
            info(f"Generated exploitation plan for {target}")
        
        return exploit_results
    
    async def _execute_reconnaissance(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reconnaissance operations."""
        targets = parsed_request.get('targets', [])
        
        recon_results = {
            'scan_plans': {},
            'reconnaissance_commands': {},
            'enumeration_strategies': {}
        }
        
        for target in targets[:3]:  # Limit to 3 targets
            info(f"Planning reconnaissance for: {target}")
            
            # Generate reconnaissance strategy
            recon_strategy = await self._generate_recon_strategy(target)
            recon_results['scan_plans'][target] = recon_strategy
            
            info(f"Generated reconnaissance plan for {target}")
        
        return recon_results
    
    async def _execute_reporting(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute reporting operations."""
        info("Generating interim report...")
        
        report_results = {
            'interim_report': await self._generate_interim_report(),
            'report_type': 'interim',
            'timestamp': datetime.now().isoformat()
        }
        
        return report_results
    
    async def _execute_general_ai_request(self, parsed_request: Dict[str, Any]) -> Dict[str, Any]:
        """Execute general AI requests that don't fit specific categories."""
        original_request = parsed_request.get('original_request', '')
        
        system_prompt = """You are a penetration testing expert. Provide detailed, 
        actionable guidance for the user's request. Include specific tools, techniques,
        and step-by-step instructions where appropriate."""
        
        response = await self.ai_assistant.ollama.generate_text(
            f"Provide comprehensive guidance for: {original_request}",
            system_prompt
        )
        
        return {
            'ai_guidance': response,
            'response_type': 'general_assistance'
        }
    
    async def _generate_recon_strategy(self, target: str) -> Dict[str, Any]:
        """Generate reconnaissance strategy for a target."""
        system_prompt = """You are a penetration testing expert. Create a comprehensive 
        reconnaissance strategy including network scanning, service enumeration, and 
        web application testing approaches."""
        
        prompt = f"""Create a reconnaissance strategy for target: {target}
        
        Include:
        1. Network discovery commands
        2. Port scanning approaches
        3. Service enumeration techniques
        4. Web application reconnaissance
        5. Information gathering methods
        
        Provide specific commands and tool recommendations."""
        
        strategy = await self.ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        return {
            'target': target,
            'strategy': strategy,
            'generated_at': datetime.now().isoformat()
        }
    
    async def _display_results_summary(self, results: Dict[str, Any]):
        """Display a summary of the execution results."""
        action_type = results.get('action_type', 'unknown')
        success = results.get('success', False)
        
        if success:
            cprint(f"\n✅ {action_type.title()} completed successfully", 'green')
        else:
            cprint(f"\n❌ {action_type.title()} failed", 'red')
        
        # Show key outputs
        outputs = results.get('outputs', {})
        if outputs:
            info("Key outputs:")
            for key, value in list(outputs.items())[:3]:  # Show first 3
                if isinstance(value, str) and len(value) > 100:
                    info(f"  {key}: {value[:100]}...")
                else:
                    info(f"  {key}: {value}")
        
        # Show any generated files
        generated_files = results.get('generated_files', [])
        if generated_files:
            info(f"Generated {len(generated_files)} files:")
            for file_path in generated_files[:3]:
                info(f"  📁 {file_path}")
        
        # Show any errors
        errors = results.get('errors', [])
        if errors:
            warn(f"Encountered {len(errors)} errors:")
            for error_msg in errors[:2]:
                warn(f"  ⚠️  {error_msg}")
    
    def _show_help(self):
        """Show help information."""
        cprint("\n📚 AutoRecon AI Interactive Mode Help", 'cyan')
        print("\nCommands:")
        print("  exit/quit     - Exit and generate final report")
        print("  help/?        - Show this help")
        print("  status        - Show session status")
        print("  history       - Show conversation history")
        
        print("\nNatural Language Examples:")
        print("  > get me info on John Smith who lives in Seattle")
        print("  > research TechCorp executives for social engineering")
        print("  > I want to spearphish employees at example.com")
        print("  > confirm attack 192.168.1.1 with metasploit")
        print("  > generate phishing templates for IT department")
        print("  > scan example.com for vulnerabilities")
        print("  > create exploitation plan for discovered services")
        
        print("\nConfirmation:")
        print("  Prefix dangerous actions with 'confirm' to skip confirmation")
        print("  Example: 'confirm attack example.com' vs 'attack example.com'")
    
    def _show_status(self):
        """Show current session status."""
        cprint("\n📊 Session Status", 'cyan')
        start_time = self.current_session['start_time']
        elapsed = datetime.now() - start_time
        
        print(f"Session Duration: {elapsed}")
        print(f"Actions Taken: {len(self.current_session['actions_taken'])}")
        print(f"Targets in Scope: {len(self.current_session.get('scope', {}).get('targets', []))}")
        print(f"Conversation Entries: {len(self.conversation_history)}")
        
        # Show recent actions
        recent_actions = self.current_session['actions_taken'][-3:]
        if recent_actions:
            print("\nRecent Actions:")
            for action in recent_actions:
                timestamp = action['timestamp']
                user_input = action['user_input'][:50] + "..." if len(action['user_input']) > 50 else action['user_input']
                print(f"  {timestamp}: {user_input}")
    
    def _show_history(self):
        """Show conversation history."""
        cprint("\n📜 Conversation History", 'cyan')
        
        for i, entry in enumerate(self.conversation_history[-10:], 1):  # Show last 10
            timestamp = entry['timestamp']
            user_input = entry['user_input']
            print(f"{i}. [{timestamp}] {user_input}")
    
    async def _generate_interim_report(self) -> str:
        """Generate an interim report of current session."""
        system_prompt = """You are a professional penetration testing consultant. 
        Generate a comprehensive interim report based on the session data provided.
        Use professional language and structure the report with clear sections."""
        
        session_summary = {
            'duration': str(datetime.now() - self.current_session['start_time']),
            'actions_count': len(self.current_session['actions_taken']),
            'targets': self.current_session.get('scope', {}).get('targets', []),
            'recent_actions': [action['user_input'] for action in self.current_session['actions_taken'][-5:]]
        }
        
        prompt = f"""Generate an interim penetration testing report based on this session:
        {json.dumps(session_summary, indent=2)}
        
        Include:
        1. Executive Summary
        2. Scope and Methodology
        3. Activities Performed
        4. Preliminary Findings
        5. Next Steps
        6. Risk Assessment
        
        Format as a professional report."""
        
        report = await self.ai_assistant.ollama.generate_text(prompt, system_prompt)
        return report
    
    async def _generate_final_report(self):
        """Generate and save the final comprehensive report."""
        try:
            info("\n🎯 Generating final comprehensive report...")
            
            # Create output directory
            output_dir = os.path.join(os.getcwd(), 'autorecon_ai_reports')
            os.makedirs(output_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate comprehensive report using AI
            final_report = await self._create_comprehensive_report()
            
            # Save main report
            report_file = os.path.join(output_dir, f'autorecon_ai_report_{timestamp}.md')
            with open(report_file, 'w') as f:
                f.write(final_report)
            
            # Save session data
            session_file = os.path.join(output_dir, f'session_data_{timestamp}.json')
            with open(session_file, 'w') as f:
                json.dump(self.current_session, f, indent=2, default=str)
            
            # Save conversation history
            history_file = os.path.join(output_dir, f'conversation_history_{timestamp}.json')
            with open(history_file, 'w') as f:
                json.dump(self.conversation_history, f, indent=2, default=str)
            
            cprint(f"\n✅ Final report generated successfully!", 'green')
            cprint(f"📁 Report location: {report_file}", 'cyan')
            cprint(f"📊 Session data: {session_file}", 'cyan')
            cprint(f"💬 Conversation history: {history_file}", 'cyan')
            
            # Display report summary
            cprint("\n📋 Report Summary:", 'yellow')
            summary_lines = final_report.split('\n')[:10]
            for line in summary_lines:
                if line.strip():
                    print(f"  {line}")
            print("  ...")
            
        except Exception as e:
            error(f"Failed to generate final report: {e}")
    
    async def _create_comprehensive_report(self) -> str:
        """Create comprehensive final report using AI."""
        system_prompt = """You are a senior penetration testing consultant writing a comprehensive 
        final report. Create a professional, detailed report that would be suitable for 
        presentation to clients. Include executive summary, detailed findings, risk assessments,
        and actionable recommendations."""
        
        session_data = {
            'session_duration': str(datetime.now() - self.current_session['start_time']),
            'total_actions': len(self.current_session['actions_taken']),
            'scope': self.current_session.get('scope', {}),
            'actions_performed': [
                {
                    'timestamp': action['timestamp'],
                    'action': action['user_input'],
                    'type': action.get('parsed_request', {}).get('action_type', 'unknown'),
                    'success': action.get('results', {}).get('success', False)
                }
                for action in self.current_session['actions_taken']
            ]
        }
        
        prompt = f"""Create a comprehensive penetration testing report for this AI-assisted assessment:

Session Data:
{json.dumps(session_data, indent=2)}

Structure the report with:

# AutoRecon AI-Powered Penetration Testing Report

## Executive Summary
- Brief overview of assessment
- Key findings summary
- Risk level assessment
- Critical recommendations

## Assessment Scope and Methodology
- Targets assessed
- AI-powered techniques used
- Timeline and approach

## Detailed Findings
- OSINT intelligence gathered
- Technical vulnerabilities identified
- Social engineering vectors
- Exploitation possibilities

## Risk Assessment
- Critical findings
- High-risk issues
- Medium-risk issues
- Low-risk findings

## Recommendations
- Immediate actions required
- Long-term security improvements
- Monitoring and detection

## Appendices
- Tools and techniques used
- AI analysis outputs
- Detailed technical findings

Format in professional markdown with clear sections and actionable content."""
        
        report = await self.ai_assistant.ollama.generate_text(prompt, system_prompt)
        
        # Add session metadata
        header = f"""# AutoRecon AI-Powered Penetration Testing Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Session Duration:** {datetime.now() - self.current_session['start_time']}
**Total Actions:** {len(self.current_session['actions_taken'])}
**AI Model:** {self.ai_service.model}

---

"""
        
        return header + report