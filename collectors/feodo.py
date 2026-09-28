import requests, sqlite3, os

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
DB = "data/intel.db"

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS c2_servers (
        ip TEXT, port INTEGER, status TEXT, country TEXT,
        malware TEXT, as_name TEXT, first_seen TEXT, last_online TEXT,
        PRIMARY KEY (ip, port))""")
    con.commit()
    return con

def collect():
    data = requests.get(URL, timeout=30).json()
    con = init_db()
    for s in data:
        con.execute("INSERT OR REPLACE INTO c2_servers VALUES (?,?,?,?,?,?,?,?)", (
            s.get("ip_address"), s.get("port"), s.get("status"),
            s.get("country"), s.get("malware"), s.get("as_name"),
            s.get("first_seen"), s.get("last_online")))
    con.commit()
    print(f"Stored {len(data)} C2 servers")

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    collect()
