#!/usr/bin/env python3
"""
AI-Powered AutoRecon Demo Script

This script demonstrates the AI capabilities integrated into AutoRecon,
including OSINT gathering, social engineering, and automated attack orchestration.

Usage examples:
    python demo_ai_capabilities.py --osint-demo
    python demo_ai_capabilities.py --phishing-demo
    python demo_ai_capabilities.py --attack-demo
    python demo_ai_capabilities.py --natural-language-demo
"""

import asyncio
import json
import os
import sys
import argparse
from datetime import datetime

# Add autorecon to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'autorecon'))

try:
    from autorecon.ai_service import get_ai_assistant, get_ai_service
except ImportError:
    print("Error: Could not import AI service. Make sure autorecon is properly installed.")
    sys.exit(1)

class AIDemo:
    """Demonstration class for AI-powered AutoRecon capabilities."""
    
    def __init__(self, ollama_url="http://localhost:11434", model="llama3.1"):
        self.ollama_url = ollama_url
        self.model = model
        self.ai_service = None
        self.ai_assistant = None
    
    async def initialize(self):
        """Initialize AI services."""
        print("🤖 Initializing AI services...")
        try:
            self.ai_service = get_ai_service(self.ollama_url, self.model)
            self.ai_assistant = get_ai_assistant(self.ollama_url, self.model)
            print(f"✅ Connected to Ollama at {self.ollama_url}")
            print(f"📱 Using model: {self.model}")
        except Exception as e:
            print(f"❌ Failed to initialize AI services: {e}")
            print("💡 Make sure Ollama is running: 'ollama serve'")
            sys.exit(1)
    
    async def demo_osint_capabilities(self):
        """Demonstrate OSINT capabilities."""
        print("\n🔍 === AI-Powered OSINT Demo ===")
        
        # Sample target information
        target_info = {
            'name': 'John Smith',
            'location': 'Seattle, WA',
            'company': 'TechCorp Inc',
            'role': 'Software Engineer'
        }
        
        print(f"🎯 Target: {target_info['name']}")
        print(f"📍 Location: {target_info['location']}")
        print(f"🏢 Company: {target_info['company']}")
        
        # Generate OSINT strategy
        print("\n📋 Generating AI-powered OSINT strategy...")
        strategy = await self.ai_assistant.generate_osint_strategy(
            target_info['name'], 
            target_info['location']
        )
        
        print("✨ AI-Generated OSINT Strategy:")
        print(strategy['strategy'][:500] + "..." if len(strategy['strategy']) > 500 else strategy['strategy'])
        
        if strategy.get('search_queries'):
            print(f"\n🔍 Generated {len(strategy['search_queries'])} search queries:")
            for i, query in enumerate(strategy['search_queries'][:5], 1):
                print(f"  {i}. {query}")
        
        # Analyze target profile
        print("\n🧠 Generating AI target analysis...")
        analysis = await self.ai_assistant.analyze_target_profile(target_info)
        
        print(f"⚠️  Risk Level: {analysis.get('risk_level', 'unknown')}")
        if analysis.get('attack_vectors'):
            print("🎯 Suggested Attack Vectors:")
            for vector in analysis['attack_vectors'][:3]:
                print(f"  • {vector}")
    
    async def demo_phishing_capabilities(self):
        """Demonstrate phishing campaign generation."""
        print("\n📧 === AI-Powered Phishing Demo ===")
        
        target_info = {
            'name': 'Sarah Johnson',
            'company': 'Financial Services Corp',
            'role': 'Account Manager'
        }
        
        print(f"🎯 Target: {target_info['name']}")
        print(f"🏢 Company: {target_info['company']}")
        print(f"💼 Role: {target_info['role']}")
        
        # Generate different phishing campaign types
        campaign_types = ['generic', 'spearphishing', 'ceo-fraud', 'tech-support']
        
        for campaign_type in campaign_types:
            print(f"\n📋 Generating {campaign_type} phishing campaign...")
            
            email_content = await self.ai_assistant.generate_phishing_email(
                target_info, 
                campaign_type
            )
            
            print(f"📌 Subject: {email_content.get('subject', 'N/A')}")
            body_preview = email_content.get('body', '')[:200]
            print(f"📝 Body Preview: {body_preview}...")
            
            await asyncio.sleep(1)  # Rate limiting
    
    async def demo_attack_orchestration(self):
        """Demonstrate attack chain generation."""
        print("\n⚔️  === AI-Powered Attack Orchestration Demo ===")
        
        # Sample reconnaissance data
        recon_data = {
            'target': '192.168.1.100',
            'open_ports': [22, 80, 443, 3389],
            'services': {
                '22': 'ssh',
                '80': 'http',
                '443': 'https',
                '3389': 'rdp'
            },
            'os_detection': 'Windows Server 2019',
            'vulnerabilities': ['CVE-2021-34527', 'CVE-2020-1472'],
            'web_technologies': ['IIS 10.0', 'ASP.NET', 'Microsoft SQL Server']
        }
        
        print("🎯 Target Information:")
        print(f"  🖥️  IP: {recon_data['target']}")
        print(f"  🔌 Open Ports: {recon_data['open_ports']}")
        print(f"  🐧 OS: {recon_data['os_detection']}")
        print(f"  🔓 Vulnerabilities: {len(recon_data['vulnerabilities'])} found")
        
        # Generate attack chain
        print("\n🧠 Generating AI attack chain...")
        attack_chain = await self.ai_assistant.suggest_attack_chain(recon_data)
        
        print(f"📋 Generated {len(attack_chain)} attack steps:")
        for i, step in enumerate(attack_chain[:5], 1):  # Show first 5 steps
            print(f"\n  Step {i}: {step.get('step', 'Unknown')}")
            if step.get('commands'):
                print(f"    🔧 Commands: {len(step['commands'])}")
                for cmd in step['commands'][:2]:  # Show first 2 commands
                    print(f"      • {cmd}")
            if step.get('tools'):
                print(f"    🛠️  Tools: {', '.join(step['tools'][:3])}")
    
    async def demo_metasploit_generation(self):
        """Demonstrate Metasploit command generation."""
        print("\n💥 === AI-Powered Metasploit Demo ===")
        
        target_info = {
            'ip': '192.168.1.100',
            'port': '445',
            'service': 'smb'
        }
        
        vulnerability = "EternalBlue SMB vulnerability (MS17-010)"
        
        print(f"🎯 Target: {target_info['ip']}:{target_info['port']}")
        print(f"🔓 Vulnerability: {vulnerability}")
        
        # Generate Metasploit commands
        print("\n🧠 Generating Metasploit commands...")
        msf_commands = await self.ai_assistant.generate_metasploit_commands(
            target_info, 
            vulnerability
        )
        
        print("💻 Generated Metasploit Commands:")
        for i, cmd in enumerate(msf_commands, 1):
            print(f"  {i}. {cmd}")
    
    async def demo_natural_language_interface(self):
        """Demonstrate natural language interface."""
        print("\n🗣️  === Natural Language Interface Demo ===")
        
        # Sample natural language requests
        requests = [
            "get me info on John Smith who lives in Seattle",
            "I want to spearphish employees at TechCorp",
            "start an msf6 reverse shell against 192.168.1.100",
            "perform social engineering against the CEO of that company",
            "find vulnerabilities in their web application"
        ]
        
        for request in requests:
            print(f"\n🗣️  Request: '{request}'")
            
            # Parse the request
            system_prompt = """You are a cybersecurity assistant. Parse this penetration testing request 
            and identify the activity type, target details, and recommended approach."""
            
            response = await self.ai_assistant.ollama.generate_text(
                f"Parse this request: '{request}' and provide activity type, target details, and approach.",
                system_prompt
            )
            
            # Extract key information
            if 'osint' in response.lower() or 'info' in request.lower():
                activity = "🔍 OSINT Collection"
            elif 'phish' in response.lower() or 'phish' in request.lower():
                activity = "📧 Phishing Campaign"
            elif 'shell' in response.lower() or 'msf' in request.lower():
                activity = "💥 Exploitation"
            elif 'social' in response.lower():
                activity = "🎭 Social Engineering"
            else:
                activity = "🔧 General Reconnaissance"
            
            print(f"📋 Activity Type: {activity}")
            print(f"🧠 AI Analysis: {response[:150]}...")
            
            await asyncio.sleep(1)  # Rate limiting
    
    async def demonstrate_all(self):
        """Run all demonstrations."""
        print("🚀 Starting comprehensive AI capabilities demonstration...\n")
        
        await self.initialize()
        
        try:
            await self.demo_osint_capabilities()
            await asyncio.sleep(2)
            
            await self.demo_phishing_capabilities()
            await asyncio.sleep(2)
            
            await self.demo_attack_orchestration()
            await asyncio.sleep(2)
            
            await self.demo_metasploit_generation()
            await asyncio.sleep(2)
            
            await self.demo_natural_language_interface()
            
        except KeyboardInterrupt:
            print("\n\n⏹️  Demo interrupted by user")
        except Exception as e:
            print(f"\n\n❌ Demo error: {e}")
        
        print("\n✅ AI capabilities demonstration completed!")
        print("\n💡 Usage Examples:")
        print("  # OSINT with AI")
        print("  autorecon --enable-ai --ai-request 'get info on John Smith in Seattle' target.com")
        print("")
        print("  # AI-powered phishing campaign")
        print("  autorecon --enable-attack-mode --enable-ai --email-scans phishing-campaign target.com")
        print("")
        print("  # Full AI orchestration")
        print("  autorecon --enable-attack-mode --enable-ai --interactive-ai --auto-exploit target.com")

def main():
    """Main function to run demonstrations."""
    parser = argparse.ArgumentParser(description="AI-Powered AutoRecon Capabilities Demo")
    parser.add_argument('--osint-demo', action='store_true', help='Demo OSINT capabilities only')
    parser.add_argument('--phishing-demo', action='store_true', help='Demo phishing capabilities only')
    parser.add_argument('--attack-demo', action='store_true', help='Demo attack orchestration only')
    parser.add_argument('--metasploit-demo', action='store_true', help='Demo Metasploit generation only')
    parser.add_argument('--natural-language-demo', action='store_true', help='Demo natural language interface only')
    parser.add_argument('--ollama-url', default='http://localhost:11434', help='Ollama server URL')
    parser.add_argument('--model', default='llama3.1', help='AI model to use')
    
    args = parser.parse_args()
    
    demo = AIDemo(args.ollama_url, args.model)
    
    async def run_demo():
        await demo.initialize()
        
        if args.osint_demo:
            await demo.demo_osint_capabilities()
        elif args.phishing_demo:
            await demo.demo_phishing_capabilities()
        elif args.attack_demo:
            await demo.demo_attack_orchestration()
        elif args.metasploit_demo:
            await demo.demo_metasploit_generation()
        elif args.natural_language_demo:
            await demo.demo_natural_language_interface()
        else:
            await demo.demonstrate_all()
    
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user. Goodbye! 👋")
    except Exception as e:
        print(f"\nDemo failed: {e}")
        print("Make sure Ollama is running: 'ollama serve'")

if __name__ == "__main__":
    main()