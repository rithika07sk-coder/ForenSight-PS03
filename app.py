import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="ForenSight",
    page_icon="🔍",
    layout="wide"
)

st.title("🔍 ForenSight")
st.caption("From Scattered Logs to a Clear Attack Story")

files = [
    "data/auth_logs.csv",
    "data/file_access_logs.csv",
    "data/system_events.csv",
    "data/network_logs.csv"
]

logs = []

for file in files:
    logs.append(pd.read_csv(file))

events = pd.concat(logs, ignore_index=True)

events["timestamp"] = pd.to_datetime(events["timestamp"])

events = events.sort_values("timestamp")

st.subheader("Investigation Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(events))
col2.metric("Affected Users", events["user"].nunique())
col3.metric("Affected Hosts", events["host"].nunique())
col4.metric(
    "Critical Events",
    len(events[events["severity"] == "critical"])
)

st.subheader("Chronological Incident Timeline")

timeline = px.scatter(
    events,
    x="timestamp",
    y="source",
    color="severity",
    hover_data=[
        "event_id",
        "user",
        "host",
        "action",
        "object"
    ],
    title="Multi-Source Forensic Event Timeline"
)

st.plotly_chart(timeline, use_container_width=True)

st.subheader("All Collected Evidence")

st.dataframe(events, use_container_width=True)

st.subheader("Preliminary Attack Story")

st.warning(
    "Possible credential compromise: account student01 had repeated "
    "failed VPN logins followed by a successful login from external IP "
    "203.0.113.45."
)

st.error(
    "Possible data exfiltration: the same account accessed a sensitive "
    "research file, compressed it, and transferred the archive to "
    "external IP 198.51.100.20."
)

st.info(
    "Confidence: High. Supporting evidence: AUTH001–AUTH004, "
    "FILE001–FILE002, SYS001–SYS002, NET001. "
    "Requires human investigator verification."
)
