# ForenSight Project Guide

## Run the Application

Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

Start the Streamlit dashboard:

```powershell
py -m streamlit run app.py
```

Open the local link displayed in the terminal, usually:

```text
http://localhost:8501
```

## Required Python Packages

```text
streamlit
pandas
plotly
networkx
```

## Dashboard Features

- Combines authentication, file-access, system, and network logs.
- Filters evidence by log source, severity, user, and host.
- Shows event, user, host, and critical-event metrics.
- Displays a chronological cross-source incident timeline.
- Displays the filtered raw evidence table.
- Shows an attack relationship graph.
- Generates an evidence-backed preliminary attack story.
- Requires human investigator verification before a conclusion is treated as final.

## Demonstrated Attack Path

```text
203.0.113.45
→ student01
→ vpn-server
→ research-server
→ solar_grid_results.xlsx
→ research_archive.zip
→ 198.51.100.20
```

## Supporting Evidence

```text
AUTH001–AUTH004
FILE001–FILE002
SYS001–SYS002
NET001
```

## Project Files

```text
app.py
requirements.txt
README.md
PROJECT_GUIDE.md
data/auth_logs.csv
data/file_access_logs.csv
data/system_events.csv
data/network_logs.csv
```