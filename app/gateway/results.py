"""
Gateway analysis result models.
"""

from dataclasses import dataclass


@dataclass
class AnalysisResult:
    """
    Result produced by the Gateway analysis pipeline.

    prediction and probability represent the independent
    machine-learning assessment.

    risk_score and risk_level represent the final
    rule-based risk assessment.
    """

    domain: str
    score: float
    prediction: str
    probability: float = 0.0
    risk_score: int = 0
    risk_level: str = "Safe"