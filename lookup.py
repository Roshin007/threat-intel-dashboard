import os, ipaddress, requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("ABUSEIPDB_KEY")

def check_ip(ip):
    """Returns (result_dict, error_message). One of them is always None."""
    try:
        ipaddress.ip_address(ip)   # rejects anything that isn't a real IP
    except ValueError:
        return None, "That doesn't look like a valid IP address."
    if not API_KEY:
        return None, "API key not found. Check your .env file."
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15)
        if r.status_code != 200:
            return None, f"AbuseIPDB returned an error (code {r.status_code})."
        return r.json()["data"], None
    except requests.RequestException:
        return None, "Could not reach AbuseIPDB. Check your internet."
