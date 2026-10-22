from urllib.parse import urlparse
import ipaddress
import socket
import csv
from datetime import datetime, timezone

import requests


SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "Medium",
        "purpose": "Encourages browsers to use HTTPS for future connections."
    },
    "Content-Security-Policy": {
        "severity": "Medium",
        "purpose": "Helps reduce certain content-injection and cross-site scripting risks."
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "purpose": "Helps prevent MIME-type sniffing; commonly set to nosniff."
    },
    "X-Frame-Options": {
        "severity": "Low",
        "purpose": "Helps control whether the page can be embedded in frames."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "purpose": "Controls how much referrer information browsers send."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "purpose": "Lets a site restrict access to selected browser features."
    },
}


def _is_public_hostname(hostname: str) -> bool:
    """Resolve hostname and reject localhost/private/reserved IP addresses."""
    if not hostname:
        return False
    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return False
    try:
        addresses = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Could not resolve the hostname. Check the URL and internet connection.")

    if not addresses:
        return False

    for item in addresses:
        ip_text = item[4][0].split("%")[0]
        ip_obj = ipaddress.ip_address(ip_text)
        if not ip_obj.is_global:
            return False
    return True


def validate_target_url(url: str) -> str:
    """Validate a public HTTP(S) URL and return a normalized URL."""
    url = (url or "").strip()
    if not url:
        raise ValueError("Enter a website URL, for example https://example.com")
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// URLs are supported.")
    if not parsed.hostname:
        raise ValueError("The URL must contain a valid hostname.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing usernames or passwords are not allowed.")
    if parsed.port and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid port.")
    if not _is_public_hostname(parsed.hostname):
        raise ValueError("Only public websites are allowed; localhost and private/reserved addresses are blocked.")
    return url


def scan_website(url: str, timeout: int = 8) -> dict:
    """
    Perform a lightweight, non-invasive check of a single URL.
    Checks HTTPS usage and common response security headers only.
    Run only against websites you own or have permission to assess.
    """
    normalized_url = validate_target_url(url)
    headers = {
        "User-Agent": "SecureScan-Educational-Auditor/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }

    try:
        response = requests.get(
            normalized_url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        try:
            status_code = response.status_code
            final_url = response.url
            response_headers = response.headers
        finally:
            response.close()
    except requests.RequestException as exc:
        raise RuntimeError(f"Request failed: {exc}") from exc

    final_parsed = urlparse(final_url)
    is_https = final_parsed.scheme == "https"

    findings = []
    passed = 0
    for header, details in SECURITY_HEADERS.items():
        value = response_headers.get(header)
        if value:
            passed += 1
            status = "Present"
            recommendation = "Review the value to confirm it matches the site's intended policy."
        else:
            status = "Missing"
            recommendation = f"Consider configuring {header}; validate the correct policy for this website before deployment."
        findings.append({
            "header": header,
            "status": status,
            "severity_if_missing": details["severity"],
            "purpose": details["purpose"],
            "observed_value": value or "",
            "recommendation": recommendation,
        })

    total_checks = len(SECURITY_HEADERS) + 1
    score = round(((passed + int(is_https)) / total_checks) * 100)
    if score >= 85:
        rating = "Good"
    elif score >= 60:
        rating = "Needs Improvement"
    else:
        rating = "Poor"

    return {
        "scan_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "input_url": normalized_url,
        "final_url": final_url,
        "http_status": status_code,
        "https_enabled": is_https,
        "security_headers_present": passed,
        "security_headers_total": len(SECURITY_HEADERS),
        "score": score,
        "rating": rating,
        "findings": findings,
        "disclaimer": "This is a basic configuration check, not a penetration test or proof that a website is secure.",
    }


def print_report(report: dict) -> None:
    print("=" * 68)
    print("SECURESCAN - AUTOMATED WEBSITE SECURITY AUDITOR")
    print("=" * 68)
    print(f"Scanned URL : {report['input_url']}")
    print(f"Final URL   : {report['final_url']}")
    print(f"HTTP status : {report['http_status']}")
    print(f"HTTPS       : {'Enabled' if report['https_enabled'] else 'Not enabled'}")
    print(f"Header score: {report['security_headers_present']}/{report['security_headers_total']} headers present")
    print(f"Security score (educational): {report['score']}/100 - {report['rating']}")
    print(f"Scan time   : {report['scan_time_utc']}")
    print("-" * 68)
    for item in report["findings"]:
        print(f"[{item['status'].upper():7}] {item['header']} (missing severity: {item['severity_if_missing']})")
        if item["observed_value"]:
            print(f"          Observed: {item['observed_value']}")
        else:
            print(f"          Recommendation: {item['recommendation']}")
    print("-" * 68)
    print(report["disclaimer"])


def export_csv(report: dict, filename: str = "securescan_report.csv") -> str:
    """Export scan findings to a CSV file."""
    fieldnames = [
        "scan_time_utc", "input_url", "final_url", "http_status",
        "https_enabled", "score", "rating", "header", "status",
        "severity_if_missing", "observed_value", "purpose", "recommendation"
    ]
    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for finding in report["findings"]:
            writer.writerow({
                "scan_time_utc": report["scan_time_utc"],
                "input_url": report["input_url"],
                "final_url": report["final_url"],
                "http_status": report["http_status"],
                "https_enabled": report["https_enabled"],
                "score": report["score"],
                "rating": report["rating"],
                **finding,
            })
    return filename


if __name__ == "__main__":
    target = input("Enter a public website URL you own or are authorized to test: ").strip()
    try:
        result = scan_website(target)
        print_report(result)
        saved_file = export_csv(result)
        print(f"\nCSV report saved to: {saved_file}")
    except (ValueError, RuntimeError) as error:
        print(f"\nScan could not be completed: {error}")
