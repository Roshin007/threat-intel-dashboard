import requests, sqlite3

DB = "data/intel.db"
URL = "https://api.first.org/data/v1/epss"

def collect():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS epss (
        cve_id TEXT PRIMARY KEY, epss REAL, percentile REAL)""")
    cves = [r[0] for r in con.execute("SELECT cve_id FROM kev")]
    # ask for 100 CVEs at a time so the request isn't too long
    for i in range(0, len(cves), 100):
        batch = cves[i:i + 100]
        r = requests.get(URL, params={"cve": ",".join(batch)}, timeout=30)
        for row in r.json().get("data", []):
            con.execute("INSERT OR REPLACE INTO epss VALUES (?,?,?)",
                        (row["cve"], float(row["epss"]), float(row["percentile"])))
    con.commit()
    print(f"Stored EPSS scores for {len(cves)} CVEs")

if __name__ == "__main__":
    collect()
