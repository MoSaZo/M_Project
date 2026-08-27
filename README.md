# Hybrid Phishing URL Detection System

A hybrid phishing URL detection system built with **FastAPI**, combining **rule-based analysis** and **machine learning** to identify suspicious URLs. The project provides a REST API, PDF report generation, scan history, phishing awareness email functionality, and a comprehensive automated test suite.

---

# Features

## URL Analysis

* URL validation and parsing
* Hostname extraction
* Registered domain detection
* Subdomain detection
* Subdomain level counting
* Protocol detection
* Path analysis
* Query parameter analysis
* Suspicious character detection
* Trusted-domain impersonation detection
* External redirect detection
* Phishing keyword detection
* Compound phishing rule detection

---

## Hybrid Risk Engine

The project combines:

* Rule-based phishing detection
* Machine Learning prediction
* Hybrid risk classification
* Risk score normalization (0–100)

Risk Levels:

|  Score | Level      |
| -----: | ---------- |
|   0–19 | Safe       |
|  20–49 | Suspicious |
| 50–100 | High Risk  |

Machine Learning predictions can increase the final risk level when phishing confidence is high.

---

## Machine Learning

The system includes a phishing prediction model capable of classifying URLs as:

* Legitimate
* Phishing

The prediction is combined with rule-based analysis to improve detection accuracy.

---

## Reports

The application can generate:

* Analysis report
* PDF report
* Human-readable phishing explanations
* Indicator severity list

---

## Database

SQLite is used to store:

* Scan history
* Analysis results

---

## Awareness Email

SMTP-based educational email functionality allows sending phishing awareness messages.

---

## REST API

Available endpoints include:

| Method | Endpoint           | Description                   |
| ------ | ------------------ | ----------------------------- |
| POST   | `/analyze`         | Analyze a URL                 |
| GET    | `/history`         | Retrieve scan history         |
| GET    | `/report/{id}`     | Generate analysis report      |
| GET    | `/report/{id}/pdf` | Download PDF report           |
| POST   | `/email`           | Send phishing awareness email |

FastAPI automatically provides:

* Swagger UI
* ReDoc

---

# Technology Stack

* Python 3.10
* FastAPI
* Pydantic
* SQLAlchemy
* SQLite
* scikit-learn
* ReportLab
* Jinja2
* pytest
* pytest-cov
* Uvicorn

---

# Project Structure

```text
M_Project/
│
├── app/
│   ├── analyzer/
│   ├── api/
│   ├── core/
│   ├── database/
│   ├── models/
│   ├── schemas/
│   ├── services/
│   ├── utils/
│   └── main.py
│
├── tests/
│
├── htmlcov/
│
├── requirements.txt
├── .env.example
├── README.md
└── .gitignore
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/MoSaZo/M_Project.git

cd M_Project
```

Create a virtual environment.

Windows:

```powershell
python -m venv .venv

.venv\Scripts\activate
```

Linux/macOS:

```bash
python3 -m venv .venv

source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Environment Variables

Create a `.env` file from `.env.example`.

Example:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=username
SMTP_PASSWORD=password
SMTP_FROM=noreply@example.com
SMTP_USE_TLS=true
```

Never commit credentials or API keys to the repository.

---

# Running the Application

```bash
uvicorn app.main:app --reload
```

Default server:

```
http://127.0.0.1:8000
```

---

# API Documentation

Swagger:

```
http://127.0.0.1:8000/docs
```

ReDoc:

```
http://127.0.0.1:8000/redoc
```

---

# Running Tests

Run all tests:

```bash
pytest
```

Verbose output:

```bash
pytest -v
```

Generate coverage:

```bash
pytest --cov=app --cov-report=html --cov-report=term-missing
```

---

# Test Statistics

Current project status:

* **94 automated tests**
* **94 passing**
* **79% total code coverage**
* Core analyzer coverage up to **100%**
* Risk engine coverage **100%**
* Indicators coverage **97%**
* Compound rules coverage **94%**

---

# Example Response

```json
{
  "risk_score": 52,
  "risk_level": "High Risk",
  "ml_prediction": "phishing",
  "ml_probability": 0.91,
  "reasons": [
    "Trusted-domain impersonation detected.",
    "Multiple phishing keywords detected."
  ]
}
```

---

# Screenshots

The following screenshots can be added:

* Home page
* URL analysis
* Swagger UI
* ReDoc
* PDF report
* Coverage report

---

# Security Notice

This project is intended for educational purposes and phishing awareness.

The analysis combines heuristic rules and machine learning, but no automated system can guarantee that a URL is completely safe or malicious.

For production deployments, additional threat intelligence services (such as Google Safe Browsing or VirusTotal) are recommended.

---

# Future Improvements

Planned enhancements include:

* Docker deployment
* Docker Compose
* PostgreSQL support
* Redis caching
* JWT authentication
* CI/CD with GitHub Actions
* VirusTotal integration
* Google Safe Browsing integration
* WHOIS lookup
* SSL certificate inspection
* User dashboard
* Multi-user support

---

# License

This project is released under the MIT License.

---

# Author

**MoSaZo**

GitHub:

https://github.com/MoSaZo
