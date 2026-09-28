import requests, sqlite3, os

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DB = "data/intel.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS kev (
        cve_id TEXT PRIMARY KEY, vendor TEXT, product TEXT,
        name TEXT, date_added TEXT, ransomware_use TEXT)""")
    con.commit()
    return con

def collect():
    data = requests.get(URL, timeout=30).json()
    con = init_db()
    for v in data["vulnerabilities"]:
        con.execute("INSERT OR REPLACE INTO kev VALUES (?,?,?,?,?,?)", (
            v["cveID"], v["vendorProject"], v["product"],
            v["vulnerabilityName"], v["dateAdded"],
            v["knownRansomwareCampaignUse"]))
    con.commit()
    print(f"Stored {len(data['vulnerabilities'])} KEV entries")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    collect()
