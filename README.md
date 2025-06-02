# PhishNet+ - URL Phishing Detection Tool

PhishNet+ is a beginner-friendly Python tool designed to help detect potentially malicious or phishing URLs using simple keyword-based analysis. This tool is perfect for learning about cybersecurity concepts and understanding how phishing attacks work.

## Features

- 🔍 URL analysis for common phishing indicators
- 🎯 Risk scoring system (Low, Medium, High)
- 🎨 Visual risk indicators using emojis
- 🔄 Typosquatting detection using fuzzy string matching
- 📝 Optional logging of results to JSON file
- 🎯 Detection of:
  - Suspicious keywords
  - IP addresses instead of domains
  - URL shorteners
  - Excessive subdomains

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/phishnet-plus.git
cd phishnet-plus
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the script:
```bash
python phishnet.py
```

Enter URLs to analyze when prompted. The tool will:
1. Analyze the URL for potential phishing indicators
2. Display a risk score and level
3. Show detailed findings
4. Optionally log results to a JSON file

Example output:
```
==================================================
PhishNet+ Analysis Results
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

PhishNet+ uses several techniques to detect potential phishing URLs:

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