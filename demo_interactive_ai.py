#!/usr/bin/env python3
"""
Demo script for AutoRecon AI Interactive Terminal Mode

This script demonstrates the new interactive AI capabilities.
"""

import os
import sys
import subprocess
import json
from datetime import datetime

def create_demo_scope_file():
    """Create a demo scope file for testing."""
    scope_data = {
        "description": "Demo penetration testing scope",
        "targets": [
            "example.com",
            "testphp.vulnweb.com",
            "demo.ine.local"
        ],
        "authorized_by": "Demo User",
        "test_type": "Authorized penetration test",
        "start_date": datetime.now().isoformat(),
        "restrictions": [
            "No denial of service attacks",
            "No data exfiltration",
            "Testing only during business hours"
        ]
    }
    
    with open('demo_scope.json', 'w') as f:
        json.dump(scope_data, f, indent=2)
    
    print("Created demo_scope.json")
    return 'demo_scope.json'

def demo_interactive_mode():
    """Demonstrate interactive AI mode."""
    print("\n🤖 AutoRecon AI Interactive Mode Demo")
    print("=" * 50)
    
    print("\n1. Creating demo scope file...")
    scope_file = create_demo_scope_file()
    
    print("\n2. Example commands you can use in interactive mode:")
    examples = [
        "get me info on John Smith who lives in Seattle",
        "research example.com for vulnerabilities", 
        "I want to spearphish employees at TechCorp",
        "confirm attack testphp.vulnweb.com with web exploits",
        "generate phishing templates for IT department",
        "create social engineering campaign for executives",
        "scan example.com for web application vulnerabilities",
        "generate metasploit commands for discovered services",
        "create comprehensive report of findings"
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"   > {example}")
    
    print("\n3. Starting interactive mode...")
    print("   Use Ctrl+C to interrupt, or type 'exit' to quit properly")
    print("   The AI will ask for confirmation before dangerous actions")
    print("   Prefix commands with 'confirm' to skip confirmation")
    
    # Start interactive mode
    cmd = [
        sys.executable, 'autorecon.py',
        '--enable-ai',
        '--interactive-terminal',
        '--scope-file', scope_file,
        '--ai-model', 'llama3.1'
    ]
    
    try:
        subprocess.run(cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"Demo failed: {e}")
    finally:
        # Cleanup
        if os.path.exists(scope_file):
            os.remove(scope_file)
            print(f"Cleaned up {scope_file}")

def demo_single_command():
    """Demonstrate single command execution."""
    print("\n🎯 AutoRecon AI Single Command Demo")
    print("=" * 50)
    
    print("\nThis mode is perfect for GitHub Actions or automation")
    
    commands_to_demo = [
        "get me info on example.com",
        "research testphp.vulnweb.com for web vulnerabilities",
        "generate phishing templates for corporate targets",
    ]
    
    scope_file = create_demo_scope_file()
    
    for i, prompt in enumerate(commands_to_demo, 1):
        print(f"\n{i}. Testing command: '{prompt}'")
        
        cmd = [
            sys.executable, 'autorecon.py',
            '--enable-ai',
            '--single-command',
            '--scope-file', scope_file,
            '--initial-prompt', prompt,
            '--ai-model', 'llama3.1'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                                   cwd=os.path.dirname(os.path.abspath(__file__)))
            
            if result.returncode == 0:
                print(f"   ✅ Command completed successfully")
                if result.stdout:
                    print(f"   Output preview: {result.stdout[:200]}...")
            else:
                print(f"   ❌ Command failed with return code {result.returncode}")
                if result.stderr:
                    print(f"   Error: {result.stderr[:200]}...")
                    
        except subprocess.TimeoutExpired:
            print(f"   ⏰ Command timed out after 120 seconds")
        except Exception as e:
            print(f"   💥 Command failed: {e}")
    
    # Cleanup
    if os.path.exists(scope_file):
        os.remove(scope_file)

def check_prerequisites():
    """Check if prerequisites are installed."""
    print("🔍 Checking prerequisites...")
    
    # Check if Ollama is running
    try:
        import requests
        response = requests.get('http://localhost:11434/api/version', timeout=5)
        if response.status_code == 200:
            print("   ✅ Ollama is running")
        else:
            print("   ❌ Ollama is not responding properly")
            return False
    except Exception as e:
        print(f"   ❌ Ollama is not accessible: {e}")
        print("   Please install and start Ollama:")
        print("   curl -fsSL https://ollama.ai/install.sh | sh")
        print("   ollama serve")
        print("   ollama pull llama3.1")
        return False
    
    # Check if autorecon.py exists
    autorecon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'autorecon.py')
    if os.path.exists(autorecon_path):
        print("   ✅ AutoRecon found")
    else:
        print("   ❌ AutoRecon not found in expected location")
        return False
    
    return True

def main():
    """Main demo function."""
    print("🚀 AutoRecon AI Interactive Terminal Demo")
    print("This demo showcases the new AI-powered interactive capabilities")
    print("=" * 60)
    
    if not check_prerequisites():
        print("\nPlease fix the prerequisites and try again.")
        sys.exit(1)
    
    print("\nChoose demo mode:")
    print("1. Interactive Terminal Mode (full interactive experience)")
    print("2. Single Command Mode (GitHub Actions style)")
    print("3. Both modes")
    
    try:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            demo_interactive_mode()
        elif choice == '2':
            demo_single_command()
        elif choice == '3':
            demo_single_command()
            print("\n" + "="*60)
            demo_interactive_mode()
        else:
            print("Invalid choice. Running interactive mode by default.")
            demo_interactive_mode()
            
    except KeyboardInterrupt:
        print("\nDemo cancelled by user")
    except Exception as e:
        print(f"Demo failed: {e}")

if __name__ == '__main__':
    main()