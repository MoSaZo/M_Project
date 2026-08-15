from app.models.schemas import (
    URLRequest,
    AwarenessEmailRequest
)

from app.email_sender import send_awareness_email

from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.models.schemas import URLRequest
from app.analyzer.url_analyzer import analyze_url


BASE_DIR = Path(__file__).resolve().parent


app = FastAPI(
    title="Phishing Awareness Tool",
    description=(
        "A tool for analyzing URLs and detecting "
        "common phishing indicators."
    ),
    version="1.0.0"
)


# Static files

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)


# HTML templates

templates = Jinja2Templates(
    directory=BASE_DIR / "templates"
)


@app.get("/")
def home(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request
        }
    )


@app.post("/analyze")
def analyze(request: URLRequest):

    try:
        return analyze_url(request.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc)
        ) from exc

@app.post("/send-awareness-email")
def send_email(request: AwarenessEmailRequest):

    try:

        send_awareness_email(
            recipient=request.recipient,
            subject=request.subject,
            body=request.body
        )

        return {
            "success": True,
            "message": "Educational email sent successfully."
        }

    except Exception as exc:

        return {
            "success": False,
            "message": str(exc)
        }
