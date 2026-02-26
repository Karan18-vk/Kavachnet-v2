# 🛡️ Email Threat Intelligence & Cybersecurity Detection System

A **production-grade**, **multi-layer** email threat detection system that reads
emails from Gmail, Outlook, IMAP, or POP3 and detects:

| Threat | Detection Method |
|---|---|
| **Phishing** | Rules + PhishTank API + HuggingFace BERT NLP |
| **Malware Links** | VirusTotal + AbuseIPDB + DNS + URL Heuristics |
| **Malicious Attachments** | ClamAV + VirusTotal Hash + python-magic MIME |
| **Spoofed Senders** | SPF/DKIM/DMARC headers + DNS + Display-name spoofing |
| **Spam** | SpamAssassin-style keyword scoring + header analysis |
| **Social Engineering** | Pattern matching + spaCy NER + BEC detection |

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python -c "import nltk; nltk.download('stopwords'); nltk.download('punkt')"
```

### 2. Configure API keys
```bash
cp config.yaml my_config.yaml
# Edit my_config.yaml with your API keys
```

Or use environment variables:
```bash
export VIRUSTOTAL_API_KEY="your_key"
export ABUSEIPDB_API_KEY="your_key"
export PHISHTANK_API_KEY="your_key"
```

### 3. Set up Gmail
1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create project → Enable Gmail API
3. Create OAuth2 credentials (Desktop App)
4. Download JSON → `credentials/gmail_credentials.json`

### 4. Run
```bash
# Scan Gmail inbox (last 50 emails)
python main.py --provider gmail --limit 50

# Scan Outlook
python main.py --provider outlook --limit 100

# Scan via IMAP
python main.py --provider imap --host imap.example.com --user me@example.com

# Custom threshold + JSON output
python main.py --provider gmail --threshold 0.7 --format json --output results.json

# Console output (fastest)
python main.py --provider gmail --format console --no-nlp

# Scan emails since a date
python main.py --provider gmail --since 2024-01-01 --limit 200
```

---

## 📁 Project Structure

```
email_threat_detector/
├── main.py                          # Entry point & CLI
├── config.yaml                      # Configuration template
├── requirements.txt
│
├── core/
│   ├── config.py                    # Config dataclass (YAML + env vars)
│   ├── models.py                    # EmailMessage, ThreatIndicator, etc.
│   ├── auth_manager.py              # Provider authentication factory
│   └── orchestrator.py             # Parallel threat analysis coordinator
│
├── connectors/
│   ├── gmail_connector.py           # Gmail API (OAuth 2.0)
│   ├── outlook_connector.py         # Microsoft Graph (MSAL device flow)
│   ├── imap_connector.py            # IMAP via imaplib
│   └── pop3_connector.py            # POP3 via poplib
│
├── detectors/
│   ├── base_detector.py             # Abstract base class
│   ├── phishing_detector.py         # Rules + PhishTank + NLP
│   ├── link_detector.py             # VirusTotal + AbuseIPDB + heuristics
│   ├── sender_detector.py           # SPF/DKIM/DMARC + display-name spoof
│   ├── spam_detector.py             # Keyword scoring + header analysis
│   └── social_engineering_detector.py  # BEC + NER + manipulation tactics
│
├── scanners/
│   └── attachment_scanner.py        # ClamAV + VirusTotal + python-magic
│
├── nlp/
│   └── phishing_classifier.py       # Transformers + sklearn + NLTK
│
├── utils/
│   ├── email_parser.py              # MIME parsing + URL extraction
│   ├── cache.py                     # File-based API response cache
│   ├── logger.py                    # Coloured logging setup
│   ├── display.py                   # Terminal output formatting
│   └── hasher.py                    # SHA-256 / MD5 helpers
│
└── reports/
    └── report_generator.py          # HTML / JSON / console reports
```

---

## 🔑 API Keys Required

| API | Free Tier | Get Key |
|-----|-----------|---------|
| **VirusTotal** | 4 req/min | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| **AbuseIPDB** | 1,000 req/day | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| **PhishTank** | Unlimited | [phishtank.com](https://www.phishtank.com/api_info.php) |
| **Gmail** | Free | [console.cloud.google.com](https://console.cloud.google.com) |
| **MS Graph** | Free | [portal.azure.com](https://portal.azure.com) |

---

## ⚙️ ClamAV Setup (Optional)
```bash
# Ubuntu/Debian
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-daemon
sudo freshclam   # Update virus definitions

# macOS
brew install clamav
freshclam
```

---

## 🎯 Threat Scoring

Each email receives a composite threat score (0.0 – 1.0):

| Severity | Score Range | Action |
|----------|-------------|--------|
| CRITICAL | ≥ 90% | Block immediately |
| HIGH | ≥ 70% | Quarantine + alert |
| MEDIUM | ≥ 50% | Flag for review |
| LOW | ≥ 30% | Monitor |
| NONE | < 30% | Clean |
