from urllib.parse import (
    urlparse,
    unquote,
    parse_qsl
)

import ipaddress
import tldextract

from app.analyzer.risk_engine import calculate_risk


def analyze_url(url: str) -> dict:
    """
    Analyze a URL for common phishing indicators.
    """

    # --------------------------------------------------
    # 1. Clean input
    # --------------------------------------------------

    url = url.strip()

    if not url:
        raise ValueError(
            "URL cannot be empty."
        )


    # --------------------------------------------------
    # 2. Add scheme if missing
    # --------------------------------------------------

    if not url.startswith(
        ("http://", "https://")
    ):

        url = "http://" + url


    # --------------------------------------------------
    # 3. Parse URL
    # --------------------------------------------------

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""


    # --------------------------------------------------
    # 4. Validate hostname
    # --------------------------------------------------

    if not hostname:

        raise ValueError(
            "Invalid URL: hostname not found."
        )


    # --------------------------------------------------
    # 5. Decode path and query
    # --------------------------------------------------

    decoded_path = unquote(path)
    decoded_query = unquote(query)


    # --------------------------------------------------
    # 6. Parse query parameters
    # --------------------------------------------------

    query_params = parse_qsl(
        query,
        keep_blank_values=True
    )


    # --------------------------------------------------
    # 7. Extract domain information
    # --------------------------------------------------

    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix


    # Registered domain

    registered_domain = domain

    if suffix:

        registered_domain = (
            f"{domain}.{suffix}"
        )


    # --------------------------------------------------
    # 8. Subdomain analysis
    # --------------------------------------------------

    subdomain_parts = [
        part
        for part in subdomain.split(".")
        if part
    ]

    subdomain_levels = len(
        subdomain_parts
    )


    # --------------------------------------------------
    # 9. Store indicators
    # --------------------------------------------------

    indicators = []


    # --------------------------------------------------
    # 10. Long URL
    # --------------------------------------------------

    if len(url) > 100:

        indicators.append({
            "score": 10,
            "reason": (
                "URL is unusually long."
            )
        })


    # --------------------------------------------------
    # 11. @ symbol
    # --------------------------------------------------

    if "@" in url:

        indicators.append({
            "score": 20,
            "reason": (
                "URL contains the @ symbol."
            )
        })


    # --------------------------------------------------
    # 12. IP address
    # --------------------------------------------------

    try:

        ipaddress.ip_address(
            hostname
        )

        indicators.append({
            "score": 25,
            "severity": "High",
            "reason": "URL uses an IP address instead of a domain name."
        })

    except ValueError:

        pass


    # --------------------------------------------------
    # 13. Multiple subdomains
    # --------------------------------------------------

    if subdomain:

        if subdomain_levels >= 4:

            indicators.append({
                "score": 20,
                "reason": (
                    f"URL contains "
                    f"{subdomain_levels} "
                    "subdomains."
                )
            })

        elif subdomain_levels == 3:

            indicators.append({
                "score": 15,
                "reason": (
                    "URL contains several "
                    "subdomain levels."
                )
            })

        elif subdomain_levels == 2:

            indicators.append({
                "score": 10,
                "reason": (
                    "URL contains multiple "
                    "subdomains."
                )
            })


    # --------------------------------------------------
    # 14. Suspicious characters
    # --------------------------------------------------

    suspicious_characters = [
        "%",
        "_"
    ]

    for char in suspicious_characters:

        if char in url:

            indicators.append({
                "score": 5,
                "reason": (
                    "URL contains suspicious "
                    f"character: {char}"
                )
            })


    # --------------------------------------------------
    # 15. Multiple hyphens
    # --------------------------------------------------

    if hostname.count("-") >= 2:

        indicators.append({
            "score": 10,
            "reason": (
                "Domain contains multiple "
                "hyphens."
            )
        })


    # --------------------------------------------------
    # 16. Long path
    # --------------------------------------------------

    if len(path) > 50:

        indicators.append({
            "score": 10,
            "reason": (
                "URL has an unusually "
                "long path."
            )
        })


    # --------------------------------------------------
    # 17. HTTP instead of HTTPS
    # --------------------------------------------------

    if parsed.scheme.lower() == "http":

        indicators.append({
            "score": 5,
            "reason": (
                "URL uses HTTP instead "
                "of HTTPS."
            )
        })


    # --------------------------------------------------
    # 18. Context-aware keywords
    # --------------------------------------------------

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


    hostname_lower = hostname.lower()
    path_lower = decoded_path.lower()
    query_lower = decoded_query.lower()


    keyword_locations = {
        "hostname": [],
        "path": [],
        "query": []
    }


    for word in suspicious_words:

        if word in hostname_lower:

            keyword_locations[
                "hostname"
            ].append(word)

        elif word in path_lower:

            keyword_locations[
                "path"
            ].append(word)

        elif word in query_lower:

            keyword_locations[
                "query"
            ].append(word)


    keyword_score = 0
    found_keywords = []


    for location, words in (
        keyword_locations.items()
    ):

        if not words:
            continue

        found_keywords.extend(
            words
        )


        if location == "hostname":

            keyword_score += (
                len(words) * 4
            )

        elif location == "path":

            keyword_score += (
                len(words) * 2
            )

        elif location == "query":

            keyword_score += len(words)


    keyword_score = min(
        keyword_score,
        20
    )


    if found_keywords:

        location_parts = []


        for location, words in (
            keyword_locations.items()
        ):

            if words:

                location_parts.append(
                    f"{location}: "
                    f"{', '.join(words)}"
                )


        indicators.append({
            "score": keyword_score,
            "reason": (
                "Suspicious keywords "
                "detected — "
                + "; ".join(
                    location_parts
                )
            )
        })


    # --------------------------------------------------
    # 19. Query parameter analysis
    # --------------------------------------------------

    if query_params:

        indicators.append({
            "score": 0,
            "reason": (
                f"URL contains "
                f"{len(query_params)} "
                "query parameter(s)."
            )
        })


    # --------------------------------------------------
    # 20. External redirect analysis
    # --------------------------------------------------

    redirect_parameters = [
        "redirect",
        "redirect_url",
        "next",
        "url",
        "target",
        "return",
        "return_url",
        "continue"
    ]


    redirect_findings = []


    for key, value in query_params:

        key_lower = key.lower()


        if key_lower not in (
            redirect_parameters
        ):

            continue


        decoded_value = (
            unquote(value).strip()
        )


        if not decoded_value.startswith(
            ("http://", "https://")
        ):

            continue


        target = urlparse(
            decoded_value
        )


        target_hostname = (
            target.hostname or ""
        )


        if not target_hostname:
            continue


        target_extracted = (
            tldextract.extract(
                decoded_value
            )
        )


        target_domain = (
            target_extracted.domain
        )

        target_suffix = (
            target_extracted.suffix
        )


        target_registered_domain = (
            target_domain
        )


        if target_suffix:

            target_registered_domain = (
                f"{target_domain}."
                f"{target_suffix}"
            )


        # Compare registered domains

        if (
            target_registered_domain.lower()
            != registered_domain.lower()
        ):

            redirect_findings.append({
                "parameter": key,
                "target": target_hostname,
                "target_registered_domain":
                    target_registered_domain
            })


    if redirect_findings:

        redirect_details = []


        for finding in redirect_findings:

            redirect_details.append(
                f"{finding['parameter']} "
                f"→ {finding['target']}"
            )


        indicators.append({
            "score": 15,
            "reason": (
                "External redirect detected: "
                + ", ".join(
                    redirect_details
                )
            )
        })


    # --------------------------------------------------
    # 21. URL encoding analysis
    # --------------------------------------------------

    encoded_count = url.count("%")


    if encoded_count >= 5:

        indicators.append({
            "score": 10,
            "reason": (
                "URL contains excessive "
                "encoding "
                f"({encoded_count} "
                "encoded characters)."
            )
        })


    # --------------------------------------------------
    # 22. Double encoding
    # --------------------------------------------------

    double_encoded_count = (
        url.lower().count("%25")
    )


    if double_encoded_count > 0:

        indicators.append({
            "score": 15,
            "reason": (
                "URL contains possible "
                "double encoding "
                f"({double_encoded_count} "
                "occurrence(s) of %25)."
            )
        })

    # Compound phishing risk rules

    has_ip_address = False
    has_http = parsed.scheme.lower() == "http"
    has_external_redirect = bool(redirect_findings)
    has_suspicious_keywords = bool(found_keywords)
    has_many_subdomains = subdomain_levels >= 3

    try:
        ipaddress.ip_address(hostname)
        has_ip_address = True

    except ValueError:
        pass

    # Dangerous combination:
    # IP address + HTTP

    if has_ip_address and has_http:
        indicators.append({
            "score": 10,
            "reason": (
                "High-risk combination detected: "
                "IP address used over HTTP."
            )
        })

    # Dangerous combination:
    # External redirect + suspicious keywords

    if has_external_redirect and has_suspicious_keywords:
        indicators.append({
            "score": 8,
            "reason": (
                "Suspicious combination detected: "
                "redirect target combined with phishing-related keywords."
            )
        })

    # Dangerous combination:
    # Multiple subdomains + suspicious keywords

    if has_many_subdomains and has_suspicious_keywords:
        indicators.append({
            "score": 8,
            "reason": (
                "Suspicious combination detected: "
                "multiple subdomains combined with phishing-related keywords."
            )
        })


    # --------------------------------------------------
    # 23. Calculate final risk
    # --------------------------------------------------

    risk_result = calculate_risk(
        indicators
    )


    # --------------------------------------------------
    # 24. Final response
    # --------------------------------------------------

    return {

        "url": url,

        "hostname": hostname,

        "registered_domain":
            registered_domain,

        "subdomain":
            subdomain,

        "subdomain_levels":
            subdomain_levels,

        "domain":
            domain,

        "suffix":
            suffix,

        "protocol":
            parsed.scheme.lower(),

        "path":
            decoded_path,

        "has_query":
            bool(query),

        "query_parameter_count":
            len(query_params),

        **risk_result
    }