import re
import socket

# Example list of known phishing domains (expand as needed)
SUSPICIOUS_DOMAINS = {
    "free-gift.com",
    "secure-login.xyz",
    "bank-update.net",
    "verify-paypal.info",
    "login-verify-security.com",
}

# Common phishing keywords in URLs
PHISHING_KEYWORDS = [
    "secure", "verify", "update", "login", "account", "banking", "free", "gift", "reward", "paypal", "apple", "amazon"
]

# Suspicious TLDs often used in phishing attacks
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".info", ".online", ".site", ".tk", ".ml", ".cf", ".ga", ".gq"}

def extract_domain(url: str) -> str:
    """
    Extracts the domain from a URL.
    """
    url = url.lower().replace("http://", "").replace("https://", "").split("/")[0]
    return url.split(":")[0]  # Remove port if present

def check_blacklist(domain: str) -> bool:
    """
    Checks if the domain is in a known phishing blacklist.
    """
    return domain in SUSPICIOUS_DOMAINS

def heuristic_analysis(url: str) -> bool:
    """
    Uses heuristic techniques to detect phishing attempts.
    """
    # Check if URL contains phishing keywords
    if any(keyword in url.lower() for keyword in PHISHING_KEYWORDS):
        return True

    # Check if domain has a suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if url.endswith(tld):
            return True

    return False

def check_dns_records(domain: str) -> bool:
    """
    Checks if the domain has valid DNS records.
    Many phishing sites use temporary domains with no proper DNS setup.
    """
    try:
        socket.gethostbyname(domain)
        return True  # Domain is valid
    except socket.gaierror:
        return False  # No valid DNS record found

def detect_phishing(url: str) -> dict:
    """
    Analyzes a URL for phishing threats and returns a detailed report.
    """
    domain = extract_domain(url)
    is_blacklisted = check_blacklist(domain)
    heuristic_match = heuristic_analysis(url)
    has_valid_dns = check_dns_records(domain)

    return {
        "url": url,
        "domain": domain,
        "blacklist_match": is_blacklisted,
        "heuristic_match": heuristic_match,
        "valid_dns": has_valid_dns,
        "is_phishing": is_blacklisted or heuristic_match or not has_valid_dns
    }
