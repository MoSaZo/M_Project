from fastapi import FastAPI
from app.models.schemas import URLRequest
from app.analyzer.url_analyzer import analyze_url


app = FastAPI(
    title="Phishing Awareness Tool",
    description="A tool for analyzing URLs and detecting phishing indicators.",
    version="1.0.0"
)


@app.get("/")
def home():
    return {
        "message": "Phishing Awareness Tool API is running."
    }


@app.post("/analyze")
def analyze(request: URLRequest):
    result = analyze_url(request.url)
    return result