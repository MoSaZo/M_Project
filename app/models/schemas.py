from pydantic import BaseModel


class URLRequest(BaseModel):
    url: str


class AwarenessEmailRequest(BaseModel):
    recipient: str
    subject: str
    body: str
