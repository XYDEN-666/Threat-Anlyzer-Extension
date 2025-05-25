# AI Credential Leak Detector

A Python-based tool leveraging AI and regex patterns to detect potential credential leaks in local files, clipboard content, and network logs.

## Features

* **Multi-Source Scanning**: Scans local files (e.g., .txt, .log, .json, .env), clipboard content, and specified network logs.
* **Regex-based Detection**: Utilizes predefined regex patterns for common sensitive data types like credit card numbers, Social Security Numbers (SSN), API keys, and email credentials.
* **AI-powered Classification**: Employs a Hugging Face 'text-classification' model ('distilbert-base-uncased-finetuned-sst-2-english') to identify potentially sensitive contexts.
* **Data Masking**: Automatically masks detected sensitive information in reports for enhanced security.
* **Configurable**: Easy-to-modify config.json for custom scan sources, sensitive data types, and AI model thresholds.
* **Comprehensive Reporting**: Generates a detailed report of detected leaks, including type, source, and masked matches.
* **Logging**: Logs all activities and detected leaks to a specified log file.

## Installation

1.  **Clone the repository:**
    `ash
    git clone [https://github.com/YOUR_USERNAME/AI-Credential-Leak-Detector.git](https://github.com/YOUR_USERNAME/AI-Credential-Leak-Detector.git)
    cd AI-Credential-Leak-Detector
    `

2.  **Create a virtual environment (recommended):**
    `ash
    python -m venv .venv
    # On Windows
    .venv\Scripts\activate
    # On macOS/Linux
    source .venv/bin/activate
    `

3.  **Install dependencies:**
    `ash
    pip install -r requirements.txt
    `

## Usage

1.  **Configure the detector:**
    Modify config.json to customize scan sources, sensitive data types, and AI model threshold. If config.json doesn't exist, running main.py will create a default one.

    `json
    {
        "scan_sources": [
            "local_files",
            "clipboard",
            "network_logs"
        ],
        "sensitive_data_types": [
            "credit_card",
            "social_security",
            "api_keys",
            "passwords"
        ],
        "ai_model_threshold": 0.7,
        "log_path": "credential_leak_detector.log",
        "network_log_path": "network.log"
    }
    `

2.  **Run the detector:**
    `ash
    python main.py
    `

    The detector will scan the configured sources and print an alert summary to the console, while a detailed report will be logged in credential_leak_detector.log.

## Models Used

* **Sensitive Data Classifier**: 'distilbert-base-uncased-finetuned-sst-2-english' (Hugging Face Transformers)
* **NER Model**: 'dslim/bert-base-NER' (Hugging Face Transformers)

## Contributing

Feel free to open issues or submit pull requests.

## License

(Optional: Add a license section if you choose to include a LICENSE file, e.g., MIT License)
