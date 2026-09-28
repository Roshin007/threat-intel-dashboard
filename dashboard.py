import streamlit as st
import pandas as pd
import plotly.express as px
import sqlite3

st.set_page_config(page_title="Threat Intel Dashboard", layout="wide")
st.title("Threat Intelligence Dashboard")

con = sqlite3.connect("data/intel.db")
kev = pd.read_sql("SELECT * FROM kev", con)
try:
    c2 = pd.read_sql("SELECT * FROM c2_servers", con)
except Exception:
    c2 = pd.DataFrame()

# Top numbers
col1, col2, col3 = st.columns(3)
col1.metric("Actively exploited CVEs", len(kev))
col2.metric("Ransomware-linked CVEs", (kev["ransomware_use"] == "Known").sum())
col3.metric("Botnet C2 servers", len(c2))

# Chart: top vendors with exploited vulnerabilities
st.subheader("Top vendors by actively exploited CVEs")
top = kev["vendor"].value_counts().head(10).reset_index()
top.columns = ["vendor", "count"]
st.plotly_chart(px.bar(top, x="vendor", y="count"), use_container_width=True)

# Table: newest additions
st.subheader("Latest exploited vulnerabilities")
st.dataframe(kev.sort_values("date_added", ascending=False).head(20),
             use_container_width=True)

# C2 servers
if not c2.empty:
    st.subheader("Botnet C2 servers")
    st.dataframe(c2, use_container_width=True)
st.subheader("Most likely to be exploited next (EPSS)")
try:
    epss = pd.read_sql("""SELECT k.cve_id, k.vendor, k.product, e.epss, e.percentile
                          FROM kev k JOIN epss e ON k.cve_id = e.cve_id
                          ORDER BY e.epss DESC LIMIT 15""", con)
    st.dataframe(epss, use_container_width=True)
except Exception:
    st.info("Run collectors/epss.py first")
from lookup import check_ip

st.subheader("IP Lookup")
ip = st.text_input("Enter an IP address to check")

if ip:
    ip = ip.strip()
    result, error = check_ip(ip)
    if error:
        st.error(error)
    else:
        a, b, c = st.columns(3)
        a.metric("Abuse confidence score", f"{result['abuseConfidenceScore']}%")
        b.metric("Total reports", result["totalReports"])
        c.metric("Country", result.get("countryCode") or "Unknown")
        st.write(f"**ISP:** {result.get('isp')}  |  **Usage type:** {result.get('usageType')}")
        st.write(f"**Last reported:** {result.get('lastReportedAt') or 'Never'}")

    # Also check our own Feodo botnet list
    if not c2.empty and ip in c2["ip"].values:
        st.error("This IP is in your Feodo botnet C2 list!")
from mitre import FAMILIES, TECHNIQUES, normalize

st.subheader("MITRE ATT&CK mapping")

family = st.selectbox("Pick a malware family", sorted(FAMILIES.keys()))

rows = []
for tid in FAMILIES[family]:
    name, tactic = TECHNIQUES[tid]
    url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
    rows.append({"Tactic": tactic, "Technique ID": tid,
                 "Technique": name, "Link": url})

st.dataframe(pd.DataFrame(rows), use_container_width=True,
             column_config={"Link": st.column_config.LinkColumn()})

# Is this family showing up in your live C2 data?
if not c2.empty:
    live = {normalize(m) for m in c2["malware"].dropna()}
    if family in live:
        st.warning(f"{family.title()} C2 servers are in your live Feodo data.")
    else:
        st.info(f"No {family.title()} C2 servers in your current data.")
st.subheader("Data freshness")
try:
    runs = pd.read_sql("""SELECT source, MAX(run_time) AS last_run, status
                          FROM feed_runs GROUP BY source""", con)
    st.dataframe(runs, use_container_width=True)
except Exception:
    st.info("Run refresh.py to see when each feed was last updated")
