#!/usr/bin/python3

import requests
import json
import asyncio
import os
from typing import Dict, List, Optional, Any
from autorecon.io import info, warn, error, debug

class OllamaService:
    """Service for interacting with Ollama AI models for pentesting automation."""
    
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.1"):
        self.base_url = base_url
        self.model = model
        self.available_models = []
        self._check_connection()
    
    def _check_connection(self) -> bool:
        """Check if Ollama is running and accessible."""
        try:
            response = requests.get(f"{self.base_url}/api/version", timeout=5)
            if response.status_code == 200:
                info(f"Connected to Ollama at {self.base_url}")
                self._get_available_models()
                return True
        except requests.exceptions.RequestException as e:
            warn(f"Cannot connect to Ollama at {self.base_url}: {e}")
            return False
        return False
    
    def _get_available_models(self):
        """Get list of available models from Ollama."""
        try:
            response = requests.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                self.available_models = [model['name'] for model in data.get('models', [])]
                info(f"Available models: {', '.join(self.available_models)}")
        except Exception as e:
            warn(f"Failed to get available models: {e}")
    
    async def generate_text(self, prompt: str, system_prompt: str = None, stream: bool = False) -> str:
        """Generate text using Ollama model."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": stream
            }
            
            if system_prompt:
                payload["system"] = system_prompt
            
            response = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=120)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('response', '')
            else:
                error(f"Ollama API error: {response.status_code} - {response.text}")
                return ""
        except Exception as e:
            error(f"Error generating text with Ollama: {e}")
            return ""
    
    async def chat_completion(self, messages: List[Dict[str, str]]) -> str:
        """Chat completion using Ollama."""
        try:
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False
            }
            
            response = requests.post(f"{self.base_url}/api/chat", json=payload, timeout=120)
            
            if response.status_code == 200:
                result = response.json()
                return result.get('message', {}).get('content', '')
            else:
                error(f"Ollama chat API error: {response.status_code} - {response.text}")
                return ""
        except Exception as e:
            error(f"Error with chat completion: {e}")
            return ""

class AIAssistant:
    """AI Assistant for pentesting automation and OSINT."""
    
    def __init__(self, ollama_service: OllamaService):
        self.ollama = ollama_service
        self.conversation_history = []
    
    async def generate_phishing_email(self, target_info: Dict[str, Any], campaign_type: str = "generic") -> Dict[str, str]:
        """Generate AI-powered phishing email content."""
        system_prompt = """You are a cybersecurity professional conducting authorized penetration testing. 
        Generate realistic phishing email content for security awareness testing. 
        The content should be convincing but include subtle indicators that this is a test.
        Focus on social engineering techniques while maintaining ethical boundaries."""
        
        target_name = target_info.get('name', 'User')
        target_company = target_info.get('company', 'the organization')
        target_role = target_info.get('role', 'employee')
        
        prompt = f"""Generate a phishing email for security testing with these details:
        - Target: {target_name}
        - Company: {target_company} 
        - Role: {target_role}
        - Campaign type: {campaign_type}
        
        Create subject line and email body that would be effective for security awareness testing.
        Include realistic but harmless call-to-action."""
        
        response = await self.ollama.generate_text(prompt, system_prompt)
        
        # Parse response to extract subject and body
        lines = response.split('\n')
        subject = ""
        body = ""
        
        for i, line in enumerate(lines):
            if 'subject:' in line.lower():
                subject = line.split(':', 1)[1].strip()
            elif subject and not body:
                body = '\n'.join(lines[i:]).strip()
                break
        
        return {
            'subject': subject or "Important Security Update Required",
            'body': body or response
        }
    
    async def analyze_target_profile(self, target_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze target information and suggest attack vectors."""
        system_prompt = """You are a cybersecurity analyst conducting authorized penetration testing.
        Analyze the provided target information and suggest potential attack vectors and reconnaissance strategies.
        Focus on legitimate security testing methodologies."""
        
        prompt = f"""Analyze this target profile for authorized penetration testing:
        {json.dumps(target_info, indent=2)}
        
        Provide:
        1. Risk assessment
        2. Potential attack vectors
        3. Recommended reconnaissance techniques
        4. Social engineering approaches
        5. Technical vulnerabilities to investigate"""
        
        response = await self.ollama.generate_text(prompt, system_prompt)
        
        return {
            'analysis': response,
            'risk_level': self._extract_risk_level(response),
            'attack_vectors': self._extract_attack_vectors(response)
        }
    
    async def generate_osint_strategy(self, target_name: str, location: str = None) -> Dict[str, Any]:
        """Generate OSINT collection strategy for a target."""
        system_prompt = """You are a cybersecurity professional conducting authorized OSINT gathering.
        Provide methodical approaches for information gathering that respect privacy and legal boundaries.
        Focus on publicly available information and legitimate reconnaissance techniques."""
        
        location_text = f" in {location}" if location else ""
        prompt = f"""Create an OSINT strategy for authorized intelligence gathering on:
        Target: {target_name}{location_text}
        
        Provide:
        1. Search engine techniques
        2. Social media investigation methods
        3. Public records research
        4. Professional network analysis
        5. Technical footprint assessment
        6. Data correlation strategies
        
        Include specific search queries and techniques while respecting legal and ethical boundaries."""
        
        response = await self.ollama.generate_text(prompt, system_prompt)
        
        return {
            'strategy': response,
            'search_queries': self._extract_search_queries(response),
            'techniques': self._extract_techniques(response)
        }
    
    async def suggest_attack_chain(self, reconnaissance_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggest attack chain based on reconnaissance data."""
        system_prompt = """You are a penetration testing expert. Based on reconnaissance data,
        suggest a logical attack chain for authorized security testing. Include tool recommendations
        and techniques while emphasizing proper authorization and documentation."""
        
        prompt = f"""Based on this reconnaissance data, suggest an attack chain:
        {json.dumps(reconnaissance_data, indent=2)}
        
        Provide a step-by-step attack chain with:
        1. Initial access methods
        2. Tool recommendations
        3. Privilege escalation paths
        4. Persistence mechanisms
        5. Data exfiltration techniques
        6. Cleanup procedures
        
        Format as numbered steps with specific commands where applicable."""
        
        response = await self.ollama.generate_text(prompt, system_prompt)
        
        return self._parse_attack_chain(response)
    
    async def generate_metasploit_commands(self, target_info: Dict[str, Any], vulnerability: str) -> List[str]:
        """Generate Metasploit commands for specific vulnerability."""
        system_prompt = """You are a penetration testing expert. Generate specific Metasploit
        commands for authorized security testing. Include proper options and payloads."""
        
        prompt = f"""Generate Metasploit commands for:
        Target: {target_info.get('ip', 'TARGET_IP')}
        Port: {target_info.get('port', 'TARGET_PORT')}
        Service: {target_info.get('service', 'unknown')}
        Vulnerability: {vulnerability}
        
        Provide complete msfconsole commands including:
        1. Module selection
        2. Options configuration
        3. Payload selection
        4. Execution commands"""
        
        response = await self.ollama.generate_text(prompt, system_prompt)
        
        return self._extract_commands(response)
    
    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from analysis text."""
        text_lower = text.lower()
        if 'critical' in text_lower:
            return 'critical'
        elif 'high' in text_lower:
            return 'high'
        elif 'medium' in text_lower:
            return 'medium'
        else:
            return 'low'
    
    def _extract_attack_vectors(self, text: str) -> List[str]:
        """Extract attack vectors from analysis text."""
        vectors = []
        lines = text.split('\n')
        for line in lines:
            if 'attack vector' in line.lower() or 'vulnerability' in line.lower():
                vectors.append(line.strip())
        return vectors[:5]  # Limit to top 5
    
    def _extract_search_queries(self, text: str) -> List[str]:
        """Extract search queries from OSINT strategy."""
        queries = []
        lines = text.split('\n')
        for line in lines:
            if '"' in line and ('search' in line.lower() or 'query' in line.lower()):
                # Extract quoted strings
                import re
                quoted = re.findall(r'"([^"]*)"', line)
                queries.extend(quoted)
        return queries[:10]  # Limit to 10 queries
    
    def _extract_techniques(self, text: str) -> List[str]:
        """Extract techniques from strategy text."""
        techniques = []
        lines = text.split('\n')
        for line in lines:
            if line.strip().startswith(('-', '*', '•')) or line.strip()[0].isdigit():
                techniques.append(line.strip())
        return techniques[:15]  # Limit to 15 techniques
    
    def _parse_attack_chain(self, text: str) -> List[Dict[str, Any]]:
        """Parse attack chain from text response."""
        steps = []
        lines = text.split('\n')
        current_step = {}
        
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('Step')):
                if current_step:
                    steps.append(current_step)
                current_step = {
                    'step': line,
                    'commands': [],
                    'tools': []
                }
            elif current_step and line:
                if '```' in line or line.startswith('$') or line.startswith('msfconsole'):
                    current_step['commands'].append(line.replace('```', '').strip())
                elif any(tool in line.lower() for tool in ['nmap', 'hydra', 'metasploit', 'sqlmap']):
                    current_step['tools'].append(line)
        
        if current_step:
            steps.append(current_step)
        
        return steps
    
    def _extract_commands(self, text: str) -> List[str]:
        """Extract commands from response text."""
        commands = []
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            if line.startswith(('use ', 'set ', 'run', 'exploit', 'search ')):
                commands.append(line)
        
        return commands

# Global AI service instance
ai_service = None
ai_assistant = None

def get_ai_service(ollama_url: str = "http://localhost:11434", model: str = "llama3.1") -> OllamaService:
    """Get or create the global AI service instance."""
    global ai_service
    if ai_service is None:
        ai_service = OllamaService(ollama_url, model)
    return ai_service

def get_ai_assistant(ollama_url: str = "http://localhost:11434", model: str = "llama3.1") -> AIAssistant:
    """Get or create the global AI assistant instance."""
    global ai_assistant, ai_service
    if ai_assistant is None:
        if ai_service is None:
            ai_service = get_ai_service(ollama_url, model)
        ai_assistant = AIAssistant(ai_service)
    return ai_assistant