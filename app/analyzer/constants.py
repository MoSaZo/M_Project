"""
Analyzer constants.
"""

SUSPICIOUS_KEYWORDS = [
    "login",
    "secure",
    "account",
    "verify",
    "verification",
    "update",
    "password",
    "signin",
    "banking",
    "confirm",
]

REDIRECT_PARAMETERS = [
    "redirect",
    "redirect_url",
    "next",
    "url",
    "target",
    "return",
    "return_url",
    "continue",
]

SUSPICIOUS_CHARACTERS = [
    "%",
    "_",
]

LONG_URL_THRESHOLD = 100

LONG_PATH_THRESHOLD = 50

MAX_KEYWORD_SCORE = 20