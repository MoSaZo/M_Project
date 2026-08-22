"""
Pydantic request schemas.

Defines request models accepted by the API.
"""

from pydantic import BaseModel
from pydantic import EmailStr


class URLRequest(BaseModel):
    """
    URL analysis request.
    """

    url: str


class AwarenessEmailRequest(BaseModel):
    """
    Awareness email request.
    """

    recipient: EmailStr

    subject: str

    body: str