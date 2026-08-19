# Phishing Awareness Tool

A FastAPI-based web application for analyzing URLs and identifying common phishing indicators. The project also includes an awareness email feature to help educate users about phishing threats.

## Features

- URL phishing analysis
- Risk scoring engine
- Domain inspection
- Suspicious URL detection
- Awareness email sending
- Web interface using Jinja2
- Interactive API documentation (Swagger UI)

## Tech Stack

- Python 3
- FastAPI
- Pydantic
- Jinja2
- Uvicorn
- tldextract

## Project Structure

```text
app/
├── analyzer/
│   ├── risk_engine.py
│   └── url_analyzer.py
├── database/
├── models/
│   └── schemas.py
├── email_sender.py
main.py
requirements.txt
```

## Installation

```bash
git clone https://github.com/MoSaZo/M_project.git
cd M_project
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
uvicorn main:app --reload
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | / | Home page |
| POST | /analyze | Analyze a URL for phishing indicators |
| POST | /send-awareness-email | Send phishing awareness email |

## API Documentation

After running the server:

- Swagger UI: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

## Future Improvements

- VirusTotal integration
- Google Safe Browsing API
- WHOIS lookup
- SSL certificate validation
- User authentication
- Dashboard
- History of scanned URLs
- Docker support
- GitHub Actions
- Unit and integration tests

## License

MIT

## Author

MoSaZo
