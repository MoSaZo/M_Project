from urllib.parse import urlparse
import ipaddress
import tldextract

from app.analyzer.risk_engine import calculate_risk


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for common phishing indicators.
    """

    # Add a scheme if the user did not provide one
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # Extract domain information
    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # Store detected risk indicators
    indicators = []

    # 1. Long URL
    if len(url) > 100:
        indicators.append({
            "score": 10,
            "reason": "URL is unusually long."
        })

    # 2. @ symbol
    if "@" in url:
        indicators.append({
            "score": 20,
            "reason": "URL contains the @ symbol."
        })

    # 3. IP address instead of domain
    try:
        ipaddress.ip_address(hostname)

        indicators.append({
            "score": 25,
            "reason": "URL uses an IP address instead of a domain name."
        })

    except ValueError:
        pass

    # 4. Multiple subdomains
    if subdomain:
        subdomain_count = len(subdomain.split("."))

        if subdomain_count >= 3:
            indicators.append({
                "score": 25,
                "reason": (
                    f"URL contains {subdomain_count} subdomains, "
                    "which can be used to imitate a legitimate domain."
                )
            })

        elif subdomain_count == 2:
            indicators.append({
                "score": 15,
                "reason": "URL contains multiple subdomains."
            })

    # 5. Suspicious characters
    suspicious_characters = ["%", "_"]

    for char in suspicious_characters:
        if char in url:
            indicators.append({
                "score": 5,
                "reason": f"URL contains suspicious character: {char}"
            })

    # 6. Too many hyphens in hostname
    if hostname.count("-") >= 2:
        indicators.append({
            "score": 10,
            "reason": "Domain contains multiple hyphens."
        })

    # 7. Long path
    if len(path) > 50:
        indicators.append({
            "score": 10,
            "reason": "URL has an unusually long path."
        })

    # 8. HTTP instead of HTTPS
    if parsed.scheme == "http":
        indicators.append({
            "score": 5,
            "reason": "URL does not use HTTPS."
        })

    # 9. Suspicious keywords
    suspicious_words = [
        "login",
        "secure",
        "account",
        "verify",
        "verification",
        "update",
        "password",
        "signin",
        "banking",
        "confirm"
    ]

    url_lower = url.lower()

    found_words = []

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    if found_words:
        keyword_score = min(len(found_words) * 5, 20)

        indicators.append({
            "score": keyword_score,
            "reason": (
                f"Suspicious keywords found: "
                f"{', '.join(found_words)}"
            )
        })

    # Calculate final risk
    risk_result = calculate_risk(indicators)

    return {
        "url": url,
        "hostname": hostname,
        "domain": domain,
        "suffix": suffix,
        **risk_result
    }