
import re
import ipaddress
from urllib.parse import urlparse


def extract_url_features(url):
    url = str(url).strip()

    # Add a scheme only for parsing
    parsed = urlparse(
        url if "://" in url else "http://" + url
    )

    hostname = (parsed.hostname or "").lower()
    hostname = hostname.removeprefix("www.")

    normalized = re.sub(
        r"^https?://", "", url, flags=re.I
    )
    normalized = re.sub(
        r"^www\.", "", normalized, flags=re.I
    )

    # Check whether hostname is an IP address
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    letters = sum(c.isalpha() for c in normalized)
    digits = sum(c.isdigit() for c in normalized)
    special = sum(not c.isalnum() for c in normalized)

    suspicious_words = [
        "login", "verify", "account", "update", "secure",
        "banking", "signin", "password", "confirm", "wallet"
    ]

    features = {
        "DomainLength": len(hostname),
        "HostnameDots": hostname.count("."),
        "NoOfSubDomain": max(0, hostname.count(".") - 1),
        "IsDomainIP": is_ip,
        "PathLength": len(parsed.path),
        "QueryLength": len(parsed.query),
        "NoOfLetters": letters,
        "NoOfDigits": digits,
        "NoOfSpecialChars": special,
        "DigitRatio": digits / max(1, len(normalized)),
        "SpecialCharRatio": special / max(1, len(normalized)),
        "NoOfHyphens": normalized.count("-"),
        "NoOfDots": normalized.count("."),
        "NoOfAtSymbols": normalized.count("@"),
        "NoOfUnderscores": normalized.count("_"),
        "NoOfPercentSymbols": normalized.count("%"),
        "NoOfSlashes": normalized.count("/"),
        "NoOfQuestionMarks": normalized.count("?"),
        "NoOfEquals": normalized.count("="),
        "NoOfAmpersands": normalized.count("&"),
        "HasObfuscation": int(
            "%" in normalized or "@" in normalized
        ),
        "HasPunycode": int("xn--" in hostname),
        "SuspiciousWordCount": sum(
            word in normalized.lower()
            for word in suspicious_words
        )
    }

    return features
