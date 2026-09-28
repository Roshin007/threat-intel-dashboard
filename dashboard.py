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
