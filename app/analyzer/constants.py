"""
Analyzer constants.
"""

# ============================================================
# Suspicious URL Keywords
# ============================================================

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


# ============================================================
# Redirect Parameters
# ============================================================

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


# ============================================================
# Suspicious Characters
# ============================================================

SUSPICIOUS_CHARACTERS = [
    "%",
    "_",
]


# ============================================================
# URL Thresholds
# ============================================================

LONG_URL_THRESHOLD = 100

LONG_PATH_THRESHOLD = 50


# ============================================================
# Scoring
# ============================================================

MAX_KEYWORD_SCORE = 20


# ============================================================
# Trusted Domains
# ============================================================

TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "youtube.com",
    "linkedin.com",
    "stackoverflow.com",
    "yahoo.com",
    "yahoodns.net",
    "deepseek.com",
    "volces.com",
}


# ============================================================
# Trusted Brands
#
# Used for typosquatting detection.
# The values represent the canonical brand/domain names
# without protocol or www.
# ============================================================

TRUSTED_BRANDS = {
    "google": "google.com",
    "github": "github.com",
    "microsoft": "microsoft.com",
    "openai": "openai.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "facebook": "facebook.com",
    "youtube": "youtube.com",
    "linkedin": "linkedin.com",
    "stackoverflow": "stackoverflow.com",
    "paypal": "paypal.com",
}


# ============================================================
# Typosquatting Configuration
# ============================================================

# Minimum similarity required before a domain is considered
# a possible typo of a trusted brand.
#
# Example:
#
#   google
#   gooogle
#
# can produce a high similarity score.
#
TYPOSQUATTING_SIMILARITY_THRESHOLD = 0.80


# Risk points assigned when a possible typosquatting
# attempt is detected.
TYPOSQUATTING_SCORE = 30


# Minimum length difference allowed for comparison.
#
# This prevents very short domains from accidentally
# matching long brand names too easily.
TYPOSQUATTING_MAX_LENGTH_DIFFERENCE = 3