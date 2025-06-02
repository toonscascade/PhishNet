# PhishNet

Empower Your Browsing, Defend Against Phishing Threats

![Last Commit](https://img.shields.io/badge/last%20commit-today-blue) ![Python 100%](https://img.shields.io/badge/python-100%25-blue) ![Languages 1](https://img.shields.io/badge/languages-1-blue)

Built with the tools and technologies:

![Markdown](https://img.shields.io/badge/-Markdown-blue) ![Python](https://img.shields.io/badge/-Python-blue)

## Overview
PhishNet is a project designed to help users identify and avoid phishing attempts. It provides tools and resources to enhance online security through URL analysis and phishing detection.

## Features
- 🔍 Real-time phishing detection
- 🎯 Risk scoring system (Low, Medium, High)
- 🎨 Visual risk indicators using emojis
- 🔄 Typosquatting detection using fuzzy string matching
- 📝 Optional logging of results to JSON file
- 🎯 Detection of:
  - Suspicious keywords
  - IP addresses instead of domains
  - URL shorteners
  - Excessive subdomains
- User-friendly interface
- Educational resources on phishing awareness

## Installation
To install PhishNet, follow these steps:
1. Clone the repository.
   ```bash
   git clone https://github.com/yourusername/phishnet.git
   cd phishnet
   ```
2. Install the required dependencies.
   ```bash
   pip install -r requirements.txt
   ```
3. Run the setup script.
   ```bash
   python setup.py install
   ```

## Usage
After installation, you can start PhishNet by running the main script:
```bash
python main.py
```

The tool will:
1. Analyze URLs for potential phishing indicators
2. Display a risk score and level
3. Show detailed findings
4. Optionally log results to a JSON file

Example output:
```
==================================================
PhishNet Analysis Results
==================================================

URL: https://example.com/login/verify
Risk Level: 🟡 MEDIUM
Risk Score: 35/100

Findings:
• Contains suspicious keyword: login
• Contains suspicious keyword: verify

==================================================
```

## How It Works

PhishNet uses several techniques to detect potential phishing URLs:

1. **Keyword Analysis**: Checks for common phishing-related keywords
2. **Domain Analysis**: Identifies suspicious domain patterns
3. **URL Structure**: Analyzes URL structure for red flags
4. **Typosquatting Detection**: Uses fuzzy string matching to detect similar domains

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
This tool is for educational purposes only. It should not be used as the sole method for determining if a URL is safe. Always use multiple security measures and common sense when dealing with suspicious links.

## Thank You
Thank you for checking out PhishNet! 