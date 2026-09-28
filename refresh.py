import sqlite3, os, traceback
from datetime import datetime, timezone

from collectors import kev, feodo, epss

DB = "data/intel.db"
os.makedirs("data", exist_ok=True)

con = sqlite3.connect(DB)
con.execute("""CREATE TABLE IF NOT EXISTS feed_runs (
    source TEXT, run_time TEXT, status TEXT)""")

# Order matters: epss reads the CVE list that kev stores
for name, module in [("kev", kev), ("feodo", feodo), ("epss", epss)]:
    try:
        module.collect()
        status = "ok"
    except Exception:
        traceback.print_exc()
        status = "failed"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    con.execute("INSERT INTO feed_runs VALUES (?,?,?)", (name, now, status))
    con.commit()
    print(f"{name}: {status}")

con.close()
