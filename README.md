# Phishing Awareness Tool

A FastAPI-based web application for analyzing URLs and identifying common phishing indicators. The project also provides an educational email feature designed to help users learn about phishing threats.

## Features

### URL Analysis

* URL validation and parsing
* Hostname inspection
* Registered domain detection
* Subdomain detection
* Subdomain level counting
* TLD identification
* Protocol detection
* Query parameter analysis
* Suspicious URL indicator detection

### Risk Analysis

* Risk score calculation from 0 to 100
* Overall risk classification:

  * Safe
  * Suspicious
  * High Risk
* Severity classification for individual indicators
* Human-readable explanations for detected indicators
* Visual risk score and risk bar in the web interface

### Awareness & Education

* Educational phishing awareness email
* SMTP-based email sending
* Custom recipient, subject, and message
* Built-in phishing awareness tips

### Web Interface

* Jinja2-based web interface
* Responsive design
* Interactive URL analysis
* Risk visualization
* Detected indicator list
* URL information display
* Educational email form

### API

* FastAPI REST endpoints
* Pydantic request validation
* Automatic API documentation
* Swagger UI
* ReDoc

---

## Tech Stack

* Python 3
* FastAPI
* Pydantic
* Jinja2
* Uvicorn
* tldextract
* HTML5
* CSS3
* JavaScript
* SMTP

---

## Project Structure

```text
M_Project/
│
├── app/
│   ├── analyzer/
│   │   ├── risk_engine.py
│   │   └── url_analyzer.py
│   │
│   ├── database/
│   │
│   ├── models/
│   │   └── schemas.py
│   │
│   └── email_sender.py
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
├── templates/
│   └── index.html
│
├── main.py
├── requirements.txt
├── env.example
├── .gitignore
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/MoSaZo/M_Project.git
cd M_Project
```

Create and activate a virtual environment:

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

## Environment Configuration

The educational email feature uses SMTP configuration through environment variables.

Create a `.env` file based on `env.example`.

Example:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your_username
SMTP_PASSWORD=your_password
SMTP_FROM=your_email@example.com
SMTP_USE_TLS=true
```

**Do not commit real passwords, API keys, tokens, or other credentials to GitHub.**

---

## Running the Application

Start the FastAPI development server:

```bash
uvicorn main:app --reload
```

The application will be available at:

```text
http://127.0.0.1:8000
```

Open the address in a browser to use the web interface.

---

## API Endpoints

| Method | Endpoint                | Description                                  |
| ------ | ----------------------- | -------------------------------------------- |
| GET    | `/`                     | Web application homepage                     |
| POST   | `/analyze`              | Analyze a URL for phishing indicators        |
| POST   | `/send-awareness-email` | Send an educational phishing awareness email |

---

## API Documentation

After starting the server, FastAPI automatically provides interactive API documentation.

### Swagger UI

```text
http://127.0.0.1:8000/docs
```

### ReDoc

```text
http://127.0.0.1:8000/redoc
```

---

## Risk Scoring

The application calculates a phishing risk score based on detected URL indicators.

The final score is normalized to a maximum of 100.

|  Score | Risk Level |
| -----: | ---------- |
|   0–19 | Safe       |
|  20–49 | Suspicious |
| 50–100 | High Risk  |

Individual indicators are also assigned a severity level:

| Indicator Score | Severity |
| --------------: | -------- |
|             0–7 | Low      |
|            8–14 | Medium   |
|             15+ | High     |

The final classification is intended as an educational risk assessment and should not be considered a definitive determination that a URL is malicious.

---

## Awareness Email

The application includes an educational email feature for phishing awareness.

The email functionality uses SMTP and requires valid SMTP configuration through environment variables.

This feature is intended for **legitimate security awareness and educational purposes**.

---

## Security Considerations

This project is designed as an educational phishing-awareness and URL-analysis application.

The URL analyzer uses heuristic indicators and does not guarantee that a URL is safe or malicious.

For production-grade threat intelligence, additional external reputation and security services would be required.

Never store sensitive credentials directly in source code or commit them to the repository.

---

## Future Improvements

The following features are planned improvements and are **not currently implemented**:

* Database integration
* URL scan history
* Analytics dashboard
* User authentication and authorization
* WHOIS information lookup
* SSL/TLS certificate inspection
* VirusTotal API integration
* Google Safe Browsing API integration
* DNS information lookup
* URL reputation services
* Reporting and export functionality
* Unit and integration tests
* Docker support
* GitHub Actions / CI/CD
* Improved logging and monitoring

---

## Project Goals

The main goals of this project are:

1. Demonstrate URL analysis techniques.
2. Identify common phishing indicators.
3. Provide an understandable risk score.
4. Educate users about phishing threats.
5. Provide a foundation for developing a more comprehensive phishing intelligence platform.

---

## License

MIT License

---

## Author

**MoSaZo**

GitHub:
https://github.com/MoSaZo
