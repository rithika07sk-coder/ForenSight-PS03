import sqlite3
from pathlib import Path

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


st.set_page_config(
    page_title="ForenSight",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 ForenSight")
st.caption("From Scattered Logs to a Clear Attack Story")


# ============================================================
# Phase 5: Evidence Ingestion and Local SQLite Storage
# ============================================================

DEFAULT_LOG_FILES = [
    "data/auth_logs.csv",
    "data/file_access_logs.csv",
    "data/system_events.csv",
    "data/network_logs.csv",
]

REQUIRED_COLUMNS = [
    "timestamp",
    "source",
    "severity",
    "user",
    "host",
    "action",
    "object",
]


def normalise_events(frame, source_name="uploaded"):
    """Convert supported evidence into one common forensic-event format."""
    frame = frame.copy()
    frame.columns = [str(column).strip().lower() for column in frame.columns]

    aliases = {
        "time": "timestamp",
        "datetime": "timestamp",
        "date_time": "timestamp",
        "event_time": "timestamp",
        "log_source": "source",
        "logsource": "source",
        "level": "severity",
        "username": "user",
        "account": "user",
        "hostname": "host",
        "device": "host",
        "event": "action",
        "activity": "action",
        "file": "object",
        "filename": "object",
        "path": "object",
        "resource": "object",
    }

    frame = frame.rename(columns=aliases)

    if "event_id" not in frame.columns:
        frame["event_id"] = [
            f"UPL{index + 1:03d}" for index in range(len(frame))
        ]

    if "source" not in frame.columns:
        frame["source"] = source_name

    defaults = {
        "severity": "medium",
        "user": "unknown",
        "host": "unknown",
        "action": "unknown",
        "object": "unknown",
    }

    for column in REQUIRED_COLUMNS:
        if column not in frame.columns:
            frame[column] = defaults.get(column, "unknown")

    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"],
        errors="coerce",
    )

    frame = frame.dropna(subset=["timestamp"])

    for column in [
        "event_id",
        "source",
        "severity",
        "user",
        "host",
        "action",
        "object",
    ]:
        frame[column] = frame[column].fillna("unknown").astype(str)

    return frame[["event_id"] + REQUIRED_COLUMNS]


@st.cache_data
def load_default_evidence():
    frames = []

    for log_file in DEFAULT_LOG_FILES:
        frame = pd.read_csv(log_file)

        source_name = (
            Path(log_file)
            .stem.replace("_logs", "")
            .replace("_events", "")
        )

        frames.append(normalise_events(frame, source_name))

    return pd.concat(frames, ignore_index=True)


def read_uploaded_evidence(uploaded_file):
    file_name = uploaded_file.name.lower()
    source_name = Path(uploaded_file.name).stem

    if file_name.endswith(".csv"):
        frame = pd.read_csv(uploaded_file)
    elif file_name.endswith(".json"):
        frame = pd.read_json(uploaded_file)
    else:
        raise ValueError("Only CSV and JSON evidence files are supported.")

    return normalise_events(frame, source_name)


def save_evidence_to_sqlite(frame):
    connection = sqlite3.connect("forensight_evidence.db")

    frame.to_sql(
        "forensic_events",
        connection,
        if_exists="replace",
        index=False,
    )

    connection.close()


def load_evidence_from_sqlite():
    database_path = Path("forensight_evidence.db")

    if not database_path.exists():
        return None

    connection = sqlite3.connect(database_path)

    frame = pd.read_sql_query(
        "SELECT * FROM forensic_events",
        connection,
    )

    connection.close()

    frame["timestamp"] = pd.to_datetime(
        frame["timestamp"],
        errors="coerce",
    )

    return frame.dropna(subset=["timestamp"])


st.sidebar.header("Evidence Ingestion")

input_mode = st.sidebar.radio(
    "Evidence source",
    [
        "Default simulated evidence",
        "Upload CSV or JSON evidence",
        "Load saved SQLite evidence",
    ],
)

uploaded_files = []

if input_mode == "Upload CSV or JSON evidence":
    uploaded_files = st.sidebar.file_uploader(
        "Upload one or more CSV or JSON log files",
        type=["csv", "json"],
        accept_multiple_files=True,
        help=(
            "Supported fields: timestamp, source, severity, user, "
            "host, action, object, event_id."
        ),
    )

if input_mode == "Default simulated evidence":
    events = load_default_evidence()

elif input_mode == "Upload CSV or JSON evidence":
    if uploaded_files:
        uploaded_frames = []

        for uploaded_file in uploaded_files:
            try:
                uploaded_frames.append(
                    read_uploaded_evidence(uploaded_file)
                )
            except Exception as error:
                st.sidebar.error(
                    f"Could not read {uploaded_file.name}: {error}"
                )

        if uploaded_frames:
            events = pd.concat(
                uploaded_frames,
                ignore_index=True,
            )

            st.sidebar.success(
                f"Loaded {len(events)} uploaded event(s)."
            )
        else:
            events = load_default_evidence()

            st.sidebar.warning(
                "No valid upload was loaded. Default evidence is shown."
            )
    else:
        events = load_default_evidence()

        st.sidebar.info(
            "Upload CSV or JSON files to replace the default "
            "simulated evidence."
        )

else:
    saved_events = load_evidence_from_sqlite()

    if saved_events is not None and not saved_events.empty:
        events = saved_events

        st.sidebar.success(
            f"Loaded {len(events)} event(s) from SQLite storage."
        )
    else:
        events = load_default_evidence()

        st.sidebar.warning(
            "No saved SQLite evidence was found. "
            "Default evidence is shown."
        )

if st.sidebar.button("Save Current Evidence to SQLite"):
    save_evidence_to_sqlite(events)

    st.sidebar.success(
        f"Saved {len(events)} event(s) to forensight_evidence.db"
    )

events["timestamp"] = pd.to_datetime(
    events["timestamp"],
    errors="coerce",
)

events = (
    events.dropna(subset=["timestamp"])
    .sort_values("timestamp")
    .reset_index(drop=True)
)


# ============================================================
# Phase 2: Investigation Filters and Evidence Display
# ============================================================

st.sidebar.header("Investigation Filters")

selected_sources = st.sidebar.multiselect(
    "Select Log Source",
    options=events["source"].unique(),
    default=events["source"].unique(),
)

selected_severity = st.sidebar.multiselect(
    "Select Severity",
    options=events["severity"].unique(),
    default=events["severity"].unique(),
)

selected_users = st.sidebar.multiselect(
    "Select User",
    options=events["user"].unique(),
    default=events["user"].unique(),
)

selected_hosts = st.sidebar.multiselect(
    "Select Host",
    options=events["host"].unique(),
    default=events["host"].unique(),
)

filtered_events = events[
    events["source"].isin(selected_sources)
    & events["severity"].isin(selected_severity)
    & events["user"].isin(selected_users)
    & events["host"].isin(selected_hosts)
].copy()


st.subheader("Investigation Summary")

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Events", len(filtered_events))
col2.metric("Affected Users", filtered_events["user"].nunique())
col3.metric("Affected Hosts", filtered_events["host"].nunique())

col4.metric(
    "Critical Events",
    len(
        filtered_events[
            filtered_events["severity"].str.lower() == "critical"
        ]
    ),
)


st.subheader("Chronological Incident Timeline")

if filtered_events.empty:
    st.info("No evidence matches the current filters.")

else:
    timeline = px.scatter(
        filtered_events,
        x="timestamp",
        y="source",
        color="severity",
        hover_data=[
            "event_id",
            "user",
            "host",
            "action",
            "object",
        ],
        title="Multi-Source Forensic Event Timeline",
    )

    st.plotly_chart(
        timeline,
        width="stretch",
    )


st.subheader("All Collected Evidence")

st.dataframe(
    filtered_events,
    width="stretch",
    hide_index=True,
)

# ============================================================
# Phase 6: Dynamic Attack Relationship Graph
# ============================================================

st.subheader("Dynamic Attack Relationship Graph")
st.caption(
    "Nodes and links are created from the evidence currently selected by the investigator."
)

if filtered_events.empty:
    st.info("No filtered evidence is available to build the relationship graph.")
else:
    dynamic_graph = nx.DiGraph()
    node_types = {}
    node_event_ids = {}

    def add_node(node_name, node_type, event_id):
        if not node_name or str(node_name).strip().lower() in ["", "unknown", "nan"]:
            return

        node_name = str(node_name).strip()

        if node_name not in dynamic_graph:
            dynamic_graph.add_node(node_name)
            node_types[node_name] = node_type
            node_event_ids[node_name] = []

        if event_id not in node_event_ids[node_name]:
            node_event_ids[node_name].append(event_id)

    def add_edge(source_node, target_node, relationship, event_id):
        if not source_node or not target_node:
            return

        source_node = str(source_node).strip()
        target_node = str(target_node).strip()

        if source_node == target_node:
            return

        if dynamic_graph.has_edge(source_node, target_node):
            current_label = dynamic_graph[source_node][target_node]["label"]
            current_ids = dynamic_graph[source_node][target_node]["event_ids"]

            if relationship not in current_label:
                dynamic_graph[source_node][target_node]["label"] = (
                    current_label + ", " + relationship
                )

            if event_id not in current_ids:
                current_ids.append(event_id)
        else:
            dynamic_graph.add_edge(
                source_node,
                target_node,
                label=relationship,
                event_ids=[event_id],
            )

    def extract_ips(text):
        if pd.isna(text):
            return []

        matches = pd.Series([str(text)]).str.extractall(
            r"(\b(?:\d{1,3}\.){3}\d{1,3}\b)"
        )

        if matches.empty:
            return []

        return matches[0].tolist()

    for _, event in filtered_events.iterrows():
        event_id = str(event.get("event_id", "unknown"))
        source = str(event.get("source", "unknown")).lower()
        user = str(event.get("user", "unknown"))
        host = str(event.get("host", "unknown"))
        action = str(event.get("action", "unknown"))
        obj = str(event.get("object", "unknown"))

        is_valid_user = user.strip().lower() not in ["", "unknown", "nan"]
        is_valid_host = host.strip().lower() not in ["", "unknown", "nan"]
        is_valid_object = obj.strip().lower() not in ["", "unknown", "nan"]

        ips = []
        for field in [obj, action, host]:
            ips.extend(extract_ips(field))
        ips = list(dict.fromkeys(ips))

        if is_valid_user:
            add_node(user, "User Account", event_id)

        if is_valid_host:
            host_type = "System"
            if "vpn" in host.lower():
                host_type = "VPN Server"
            elif "research" in host.lower():
                host_type = "Research Server"
            add_node(host, host_type, event_id)

        if "auth" in source or "authentication" in source:
            for ip_address in ips:
                add_node(ip_address, "External IP", event_id)
                if is_valid_user:
                    add_edge(ip_address, user, action, event_id)

            if is_valid_user and is_valid_host:
                add_edge(user, host, action, event_id)

        elif "file" in source:
            if is_valid_object:
                object_type = "File"
                if any(extension in obj.lower() for extension in [".xlsx", ".xls", ".csv", ".pdf"]):
                    object_type = "Sensitive File"
                add_node(obj, object_type, event_id)

            if is_valid_user and is_valid_host:
                add_edge(user, host, action, event_id)

            if is_valid_host and is_valid_object:
                add_edge(host, obj, action, event_id)

        elif "system" in source:
            if is_valid_object:
                object_type = "Archive File" if any(
                    extension in obj.lower() for extension in [".zip", ".rar", ".7z"]
                ) else "System Object"
                add_node(obj, object_type, event_id)

            if is_valid_host and is_valid_object:
                add_edge(host, obj, action, event_id)

            elif "network" in source:
                for ip_address in ips:
                    add_node(ip_address, "External Destination", event_id)

                if is_valid_host:
                    add_edge(host, ip_address, action, event_id)

                if is_valid_object:
                    object_type = "Archive File" if any(
                        extension in obj.lower() for extension in [".zip", ".rar", ".7z"]
                    ) else "Network Object"
                    add_node(obj, object_type, event_id)
                    add_edge(obj, ip_address, action, event_id)

            if is_valid_host and is_valid_object:
                object_type = "Archive File" if any(
                    extension in obj.lower() for extension in [".zip", ".rar", ".7z"]
                ) else "Network Object"
                add_node(obj, object_type, event_id)
                add_edge(host, obj, action, event_id)

    if dynamic_graph.number_of_nodes() == 0:
        st.info("No usable entities were found in the selected evidence.")
    else:
        positions = nx.spring_layout(dynamic_graph, seed=42, k=1.2)

        edge_x = []
        edge_y = []

        for source_node, target_node in dynamic_graph.edges():
            x0, y0 = positions[source_node]
            x1, y1 = positions[target_node]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])

        edge_trace = go.Scatter(
            x=edge_x,
            y=edge_y,
            line=dict(width=2, color="#64748b"),
            hoverinfo="none",
            mode="lines",
        )

        node_x = []
        node_y = []
        node_text = []
        node_hovertext = []
        node_color = []

        color_map = {
            "External IP": "#ef4444",
            "External Destination": "#dc2626",
            "User Account": "#3b82f6",
            "VPN Server": "#14b8a6",
            "Research Server": "#f59e0b",
            "System": "#f59e0b",
            "Sensitive File": "#8b5cf6",
            "Archive File": "#ec4899",
            "File": "#8b5cf6",
            "System Object": "#64748b",
            "Network Object": "#64748b",
        }

        for node_name in dynamic_graph.nodes():
            x, y = positions[node_name]
            node_type = node_types.get(node_name, "Entity")
            supporting_ids = ", ".join(node_event_ids.get(node_name, []))

            node_x.append(x)
            node_y.append(y)
            node_text.append(node_name)
            node_hovertext.append(
                f"<b>{node_name}</b><br>Type: {node_type}<br>Evidence: {supporting_ids}"
            )
            node_color.append(color_map.get(node_type, "#64748b"))

        node_trace = go.Scatter(
            x=node_x,
            y=node_y,
            mode="markers+text",
            text=node_text,
            textposition="bottom center",
            hoverinfo="text",
            hovertext=node_hovertext,
            marker=dict(
                size=28,
                color=node_color,
                line=dict(width=2, color="white"),
            ),
        )

        figure = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title="Evidence-Derived Entity Relationships",
                showlegend=False,
                hovermode="closest",
                margin=dict(b=20, l=20, r=20, t=60),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                height=700,
            ),
        )

        st.plotly_chart(figure, width="stretch")

        relationship_rows = []
        for source_node, target_node, data in dynamic_graph.edges(data=True):
            relationship_rows.append(
                {
                    "From": source_node,
                    "Relationship": data["label"],
                    "To": target_node,
                    "Supporting Event IDs": ", ".join(data["event_ids"]),
                }
            )

        if relationship_rows:
            st.markdown("### Relationships Identified From Evidence")
            st.dataframe(
                pd.DataFrame(relationship_rows),
                width="stretch",
                hide_index=True,
            )

# ============================================================
# Phase 4: Dynamic Investigation Findings
# ============================================================

st.divider()

st.subheader("Automated Investigation Findings")

st.caption(
    "Findings are calculated from the currently filtered evidence. "
    "They are preliminary and require investigator verification."
)

if filtered_events.empty:
    st.warning(
        "No events match the selected filters. "
        "Adjust the filters to run the analysis."
    )

else:
    analysis = filtered_events.copy()

    for column in [
        "source",
        "severity",
        "user",
        "host",
        "action",
        "object",
    ]:
        analysis[f"{column}_text"] = (
            analysis[column]
            .fillna("")
            .astype(str)
            .str.lower()
        )

    def event_ids(frame):
        if frame.empty:
            return "None"

        return ", ".join(
            frame["event_id"]
            .astype(str)
            .tolist()
        )

    def values(frame, column):
        if frame.empty or column not in frame.columns:
            return []

        return [
            str(value)
            for value in (
                frame[column]
                .dropna()
                .astype(str)
                .unique()
                .tolist()
            )
            if str(value).strip()
            and str(value).lower() != "nan"
        ]

    auth_events = analysis[
        analysis["source_text"].str.contains(
            "auth|authentication",
            na=False,
        )
    ]

    failed_logins = auth_events[
        auth_events["action_text"].str.contains(
            "fail|denied|invalid",
            na=False,
        )
    ]

    successful_logins = auth_events[
        auth_events["action_text"].str.contains(
            "success|login",
            na=False,
        )
        & ~auth_events["action_text"].str.contains(
            "fail|denied|invalid",
            na=False,
        )
    ]

    network_events = analysis[
        analysis["source_text"].str.contains(
            "network",
            na=False,
        )
    ]

    sensitive_file_events = analysis[
        analysis["object_text"].str.contains(
            r"\.xlsx|\.xls|\.csv|\.pdf|sensitive|research|confidential",
            regex=True,
            na=False,
        )
    ]

    archive_events = analysis[
        analysis["object_text"].str.contains(
            r"\.zip|\.rar|\.7z|archive",
            regex=True,
            na=False,
        )
        | analysis["action_text"].str.contains(
            "compress|archive|zip|create archive",
            na=False,
        )
    ]

    external_transfer_events = network_events[
        network_events["action_text"].str.contains(
            "transfer|upload|outbound|exfil|send|connect",
            na=False,
        )
        | network_events["object_text"].str.contains(
            r"external|outbound|upload|transfer|198\.51\.100",
            regex=True,
            na=False,
        )
    ]

    affected_users = values(
        analysis,
        "user",
    )

    affected_hosts = values(
        analysis,
        "host",
    )

    sensitive_files = values(
        sensitive_file_events,
        "object",
    )

    archives = values(
        archive_events,
        "object",
    )

    destinations = values(
        external_transfer_events,
        "object",
    )

    possible_external_ips = []

    for column in [
        "object",
        "host",
        "action",
    ]:
        for value in values(analysis, column):
            clean_value = value.strip()

            if (
                clean_value.startswith("203.")
                or clean_value.startswith("198.")
            ):
                possible_external_ips.append(clean_value)

        extracted_ips = (
            analysis[column]
            .fillna("")
            .astype(str)
            .str.extractall(
                r"(\b(?:203|198)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)"
            )[0]
            .tolist()
        )

        possible_external_ips.extend(extracted_ips)

    possible_external_ips = list(
        dict.fromkeys(possible_external_ips)
    )

    initial_entry = None

    if not successful_logins.empty:
        initial_entry = (
            successful_logins
            .sort_values("timestamp")
            .iloc[0]
        )

    score = 0
    score_reasons = []

    if not failed_logins.empty:
        score += 20
        score_reasons.append(
            "failed authentication attempts (+20)"
        )

    if initial_entry is not None:
        score += 20
        score_reasons.append(
            "successful authentication after suspicious attempts (+20)"
        )

    if not sensitive_file_events.empty:
        score += 20
        score_reasons.append(
            "sensitive-file access (+20)"
        )

    if not archive_events.empty:
        score += 20
        score_reasons.append(
            "archive or compression activity (+20)"
        )

    if not external_transfer_events.empty:
        score += 20
        score_reasons.append(
            "external network transfer activity (+20)"
        )

    if score >= 80:
        confidence_label = "High"
    elif score >= 40:
        confidence_label = "Medium"
    else:
        confidence_label = "Low"

    left, right = st.columns(2)

    with left:
        st.markdown("### Possible Initial Entry Point")

        if initial_entry is not None:
            entry_user = str(
                initial_entry.get(
                    "user",
                    "Unknown user",
                )
            )

            entry_host = str(
                initial_entry.get(
                    "host",
                    "Unknown host",
                )
            )

            entry_object = str(
                initial_entry.get(
                    "object",
                    "Unknown source",
                )
            )

            entry_time = pd.to_datetime(
                initial_entry["timestamp"]
            ).strftime("%Y-%m-%d %H:%M:%S")

            entry_id = str(
                initial_entry.get(
                    "event_id",
                    "Unknown event",
                )
            )

            st.success(
                f"Possible entry: **{entry_user}** "
                f"successfully authenticated to "
                f"**{entry_host}** at {entry_time}. "
                f"Related source/IP: **{entry_object}**. "
                f"Supporting event: **{entry_id}**."
            )

        else:
            st.info(
                "No successful authentication event is available "
                "under the current filters. Select authentication "
                "logs to evaluate a likely entry point."
            )

    with right:
        st.markdown("### Confidence Score")

        st.metric(
            "Correlation Confidence",
            f"{score}/100",
            confidence_label,
        )

        if score_reasons:
            st.write(
                "Rule evidence: "
                + "; ".join(score_reasons)
                + "."
            )
        else:
            st.write(
                "No correlation rules matched the currently "
                "filtered records."
            )

    left, right = st.columns(2)

    with left:
        st.markdown("### Suspicious Activity Trace")

        if not failed_logins.empty:
            st.warning(
                f"{len(failed_logins)} failed login event(s) were "
                f"detected before or alongside the investigation. "
                f"Evidence: {event_ids(failed_logins)}."
            )
        else:
            st.info(
                "No failed-login evidence is included in the "
                "current filtered view."
            )

        if not sensitive_file_events.empty:
            st.warning(
                f"Sensitive-file-related access was detected: "
                f"{', '.join(sensitive_files) if sensitive_files else 'identified file activity'}. "
                f"Evidence: {event_ids(sensitive_file_events)}."
            )

        if not archive_events.empty:
            st.warning(
                f"Archive/compression activity was detected: "
                f"{', '.join(archives) if archives else 'identified archive activity'}. "
                f"Evidence: {event_ids(archive_events)}."
            )

        if not external_transfer_events.empty:
            st.error(
                f"Potential external transfer activity was detected: "
                f"{', '.join(destinations) if destinations else 'external network activity'}. "
                f"Evidence: {event_ids(external_transfer_events)}."
            )

    with right:
        st.markdown("### Blast Radius")

        st.write(
            f"**Affected accounts:** "
            f"{', '.join(affected_users) if affected_users else 'None identified'}"
        )

        st.write(
            f"**Affected systems:** "
            f"{', '.join(affected_hosts) if affected_hosts else 'None identified'}"
        )

        st.write(
            f"**Sensitive files:** "
            f"{', '.join(sensitive_files) if sensitive_files else 'None identified'}"
        )

        st.write(
            f"**Archives:** "
            f"{', '.join(archives) if archives else 'None identified'}"
        )

        st.write(
            f"**Possible external entities:** "
            f"{', '.join(possible_external_ips) if possible_external_ips else 'None identified'}"
        )

    st.markdown("### Evidence-Backed Preliminary Attack Story")

    story_parts = []

    if not failed_logins.empty:
        story_parts.append(
            f"{len(failed_logins)} failed authentication attempt(s) "
            f"were recorded"
        )

    if initial_entry is not None:
        story_parts.append(
            f"a successful authentication involving "
            f"{initial_entry.get('user', 'an account')} and "
            f"{initial_entry.get('host', 'a host')} followed"
        )

    if not sensitive_file_events.empty:
        story_parts.append(
            "sensitive-file-related activity was observed afterward"
        )

    if not archive_events.empty:
        story_parts.append(
            "the data was then archived or compressed"
        )

    if not external_transfer_events.empty:
        story_parts.append(
            "network evidence then indicated a possible "
            "external transfer"
        )

    if story_parts:
        st.info(
            ". Then ".join(story_parts)
            + ". This is a rule-based preliminary correlation, "
            + "not a confirmed incident. A human investigator must "
            + "validate timestamps, identities, data classification, "
            + "and network context before containment or attribution "
            + "decisions."
        )
    else:
        st.info(
            "The current filter selection does not contain enough "
            "linked evidence to generate a preliminary attack story."
        )

    all_supporting = pd.concat(
        [
            failed_logins,
            successful_logins,
            sensitive_file_events,
            archive_events,
            external_transfer_events,
        ],
        ignore_index=True,
    )

    if not all_supporting.empty:
        all_supporting = all_supporting.drop_duplicates(
            subset=["event_id"]
        )

        st.markdown("### Supporting Evidence Used by Phase 4")

        evidence_columns = [
            column
            for column in [
                "event_id",
                "timestamp",
                "source",
                "severity",
                "user",
                "host",
                "action",
                "object",
            ]
            if column in all_supporting.columns
        ]

        st.dataframe(
            all_supporting[evidence_columns]
            .sort_values("timestamp"),
            width="stretch",
            hide_index=True,
        )