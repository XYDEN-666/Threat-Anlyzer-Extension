import os
import re
import json
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any
import requests
from transformers import pipeline

class CredentialLeakDetector:
    def __init__(self, config_path: str = 'config.json'):
        """
        Initialize the Credential Leak Detector with configuration and setup.
        
        :param config_path: Path to the configuration JSON file
        """
        # Load configuration
        self.load_config(config_path)
        
        # Setup logging
        self.setup_logging()
        
        # Initialize AI models
        self.setup_ai_models()
        
        # Initialize sensitive data patterns
        self.sensitive_patterns = self.load_sensitive_patterns()
    
    def load_config(self, config_path: str):
        """
        Load configuration from a JSON file.
        
        :param config_path: Path to the configuration file
        :raises: JSONDecodeError if config file is malformed
        """
        try:
            with open(config_path, 'r') as config_file:
                self.config = json.load(config_file)
        except FileNotFoundError:
            self.logger.warning(f"Config file not found at {config_path}, using defaults")
            self.config = {
                'scan_sources': ['local_files', 'clipboard', 'network_logs'],
                'sensitive_data_types': ['credit_card', 'social_security', 'api_keys', 'passwords'],
                'ai_model_threshold': 0.7,
                'log_path': 'credential_leak_detector.log',  # Simple filename in current directory
                'network_log_path': 'network.log'  # Simple filename in current directory for Windows compatibility
            }
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def setup_logging(self):
        """
        Configure logging for the credential leak detector.
        """
        log_path = self.config.get('log_path', 'credential_leak_detector.log')
        
        # Create directory only if log_path contains a directory path
        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('CredentialLeakDetector')
    
    def setup_ai_models(self):
        """
        Initialize AI models for sensitive data detection.
        
        :raises: RuntimeError if models fail to load
        """
        try:
            self.sensitive_data_classifier = pipeline(
                'text-classification', 
                model='distilbert-base-uncased-finetuned-sst-2-english',
                device=-1  # Use CPU by default
            )
            
            self.ner_model = pipeline(
                'ner', 
                model='dslim/bert-base-NER',
                device=-1
            )
        except Exception as e:
            self.logger.error(f"Failed to load AI models: {e}")
            raise RuntimeError(f"AI model initialization failed: {e}")
    
    def load_sensitive_patterns(self) -> List[Dict[str, Any]]:
        """
        Load and compile regex patterns for sensitive data detection.
        
        :return: List of sensitive data pattern configurations
        """
        patterns = [
            {
                'type': 'credit_card',
                'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b',
                'mask_method': self.mask_credit_card
            },
            {
                'type': 'social_security',
                'pattern': r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b',
                'mask_method': self.mask_ssn
            },
            {
                'type': 'api_key',
                'pattern': r'\b(?:[A-Za-z0-9+/]{32,}|sk-[A-Za-z0-9]{32,}|gh[puos]_[A-Za-z0-9]{36}|ey[IJ][0-9a-zA-Z_-]{40,})\b',
                'mask_method': self.mask_api_key
            },
            {
                'type': 'email_credential',
                'pattern': r'\b[A-Za-z0-9._%+-]+:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'mask_method': self.mask_email_credential
            }
        ]
        
        # Compile patterns for better performance
        for pattern in patterns:
            pattern['compiled'] = re.compile(pattern['pattern'])
        
        return patterns
    
    def scan_sources(self) -> List[Dict[str, Any]]:
        """
        Scan configured sources for potential credential leaks.
        
        :return: List of detected sensitive data instances
        """
        detected_leaks = []
        scan_sources = self.config.get('scan_sources', [])
        
        source_methods = {
            'local_files': self.scan_local_files,
            'clipboard': self.scan_clipboard,
            'network_logs': self.scan_network_logs
        }
        
        for source in scan_sources:
            if source in source_methods:
                try:
                    leaks = source_methods[source]()
                    detected_leaks.extend(leaks)
                except Exception as e:
                    self.logger.error(f"Error scanning {source}: {e}")
        
        return detected_leaks
    
    def scan_local_files(self) -> List[Dict[str, Any]]:
        """
        Scan local files for sensitive data.
        
        :return: List of detected sensitive data in local files
        """
        detected_leaks = []
        scan_extensions = {'.txt', '.log', '.csv', '.json', '.env', '.yaml', '.yml', '.conf'}
        
        for root, _, files in os.walk('.', followlinks=False):
            # Skip hidden directories and virtual environments
            if any(part.startswith('.') for part in root.split(os.sep)) or 'venv' in root:
                continue
                
            for file in files:
                if os.path.splitext(file)[1].lower() in scan_extensions:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            file_leaks = self.detect_sensitive_data(content, source=file_path)
                            detected_leaks.extend(file_leaks)
                    except (UnicodeDecodeError, PermissionError) as e:
                        self.logger.warning(f"Could not scan file {file_path}: {e}")
        
        return detected_leaks
    
    def scan_clipboard(self) -> List[Dict[str, Any]]:
        """
        Scan clipboard content for sensitive data.
        
        :return: List of detected sensitive data in clipboard
        :raises: ImportError if pyperclip is not installed
        """
        try:
            import pyperclip
            clipboard_content = pyperclip.paste()
            return self.detect_sensitive_data(clipboard_content, source='Clipboard')
        except ImportError:
            self.logger.warning("Pyperclip not installed. Clipboard scanning disabled.")
            return []
    
    def scan_network_logs(self) -> List[Dict[str, Any]]:
        """
        Scan network logs for potential credential leaks.
        
        :return: List of detected sensitive data in network logs
        """
        detected_leaks = []
        network_log_path = self.config.get('network_log_path', '/var/log/network.log')
        
        if os.path.exists(network_log_path):
            try:
                with open(network_log_path, 'r') as log_file:
                    content = log_file.read()
                    detected_leaks = self.detect_sensitive_data(content, source='Network Logs')
            except Exception as e:
                self.logger.error(f"Could not scan network logs: {e}")
        else:
            self.logger.warning(f"Network log file not found at {network_log_path}")
        
        return detected_leaks
    
    def detect_sensitive_data(self, text: str, source: str = 'Unknown') -> List[Dict[str, Any]]:
        """
        Detect sensitive data using regex patterns and AI models.
        
        :param text: Text to scan for sensitive data
        :param source: Source of the text (file, clipboard, etc.)
        :return: List of detected sensitive data instances
        """
        detected_leaks = []
        
        # Regex-based pattern matching
        for pattern_config in self.sensitive_patterns:
            matches = pattern_config['compiled'].finditer(text)
            for match in matches:
                detected_leaks.append({
                    'type': pattern_config['type'],
                    'match': match.group(),
                    'masked_match': pattern_config['mask_method'](match.group()),
                    'source': source,
                    'timestamp': datetime.now().isoformat()
                })
        
        # AI-based sensitive data classification
        try:
            if len(text.strip()) > 0:
                # Use text classification to detect potentially sensitive contexts
                ai_classification = self.sensitive_data_classifier(text[:512])
                if ai_classification[0]['score'] > self.config.get('ai_model_threshold', 0.7):
                    detected_leaks.append({
                        'type': 'ai_detected_sensitive',
                        'confidence': ai_classification[0]['score'],
                        'source': source,
                        'timestamp': datetime.now().isoformat()
                    })
        except Exception as e:
            self.logger.error(f"AI classification failed for {source}: {e}")
        
        return detected_leaks
    
    def mask_credit_card(self, card_number: str) -> str:
        """Mask credit card number."""
        return f"CARD-{'*' * (len(card_number) - 4)}{card_number[-4:]}"
    
    def mask_ssn(self, ssn: str) -> str:
        """Mask social security number."""
        return f"SSN-XXX-XX-{ssn[-4:]}"
    
    def mask_api_key(self, api_key: str) -> str:
        """Mask API key."""
        return f"API-{hashlib.sha256(api_key.encode()).hexdigest()[:10]}"
    
    def mask_email_credential(self, email_cred: str) -> str:
        """Mask email credentials."""
        username, email = email_cred.split(':')
        domain = email.split('@')[1]
        return f"CRED-{username[:3]}***@{domain}"
    
    def generate_report(self, detected_leaks: List[Dict[str, Any]]):
        """
        Generate a comprehensive report of detected credential leaks.
        
        :param detected_leaks: List of detected sensitive data
        """
        if not detected_leaks:
            self.logger.info("No sensitive data leaks detected.")
            return
        
        report = {
            'total_leaks': len(detected_leaks),
            'leak_types': {},
            'leak_sources': {},
            'leak_details': detected_leaks,
            'timestamp': datetime.now().isoformat()
        }
        
        # Aggregate statistics
        for leak in detected_leaks:
            leak_type = leak['type']
            leak_source = leak['source']
            report['leak_types'][leak_type] = report['leak_types'].get(leak_type, 0) + 1
            report['leak_sources'][leak_source] = report['leak_sources'].get(leak_source, 0) + 1
        
        # Log the report
        self.logger.warning(json.dumps(report, indent=2))
        
        # Send alert
        self.send_alert(report)
    
    def send_alert(self, report: Dict[str, Any]):
        """
        Send an alert about detected credential leaks.
        
        :param report: Detected leaks report
        """
        alert_message = (
            f"ALERT: {report['total_leaks']} Potential Credential Leak(s) Detected!\n"
            f"Timestamp: {report['timestamp']}\n\n"
            "Summary by type:\n"
        )
        
        for leak_type, count in report['leak_types'].items():
            alert_message += f"- {leak_type}: {count}\n"
        
        alert_message += "\nSummary by source:\n"
        for source, count in report['leak_sources'].items():
            alert_message += f"- {source}: {count}\n"
        
        print(alert_message)
        self.logger.warning(alert_message)
    
    def run(self):
        """
        Main method to run the credential leak detector.
        """
        start_time = datetime.now()
        self.logger.info("Starting Credential Leak Detection...")
        
        try:
            detected_leaks = self.scan_sources()
            self.generate_report(detected_leaks)
        except Exception as e:
            self.logger.error(f"Credential leak detection failed: {e}")
            raise
        finally:
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            self.logger.info(f"Credential Leak Detection Complete. Duration: {duration:.2f} seconds")

def create_config_template():
    """Create a default configuration file for the Credential Leak Detector."""
    default_config = {
        'scan_sources': ['local_files', 'clipboard', 'network_logs'],
        'sensitive_data_types': ['credit_card', 'social_security', 'api_keys', 'passwords'],
        'ai_model_threshold': 0.7,
        'log_path': 'credential_leak_detector.log',  # Simple filename in current directory
        'network_log_path': 'network.log'  # Simple filename in current directory for Windows compatibility
    }
    
    with open('config.json', 'w') as config_file:
        json.dump(default_config, config_file, indent=4)
        
if __name__ == '__main__':
    # Ensure configuration exists
    if not os.path.exists('config.json'):
        create_config_template()
    
    # Initialize and run the detector
    detector = CredentialLeakDetector()
    detector.run()