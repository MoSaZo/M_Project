from dataclasses import dataclass


@dataclass
class AnalysisResult:
    domain: str
    score: float
    prediction: str