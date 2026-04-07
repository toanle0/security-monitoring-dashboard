import streamlit as st
import pandas as pd

st.set_page_config(page_title="Security Monitoring Dashboard", layout="wide")

st.title("Security Monitoring Dashboard")
st.write("Monitor events, classify incidents, and identify high-priority alerts.")

# -----------------------------
# RULES (DETECTION LOGIC)
# -----------------------------
def classify_event(message: str) -> str:
    msg = str(message).lower()

    if "forced_open" in msg or "service_down" in msg:
        return "HIGH"
    if "failed_login" in msg or "multiple_failed_logins" in msg:
        return "HIGH"
    if "access_denied" in msg:
        return "MEDIUM"
    return "LOW"

def categorize_event(message: str) -> str:
    msg = str(message).lower()

    if "failed_login" in msg or "multiple_failed_logins" in msg:
        return "Authentication"
    if "access_denied" in msg or "forced_open" in msg:
        return "Physical Access"
    if "service_down" in msg:
        return "System Outage"
    return "General Activity"

# -----------------------------
# FILE INPUT
# -----------------------------
uploaded_file = st.file_uploader("Upload log CSV", type=["csv"])

if uploaded_file:
    df = pd.read_csv(uploaded_file)
else:
    st.info("No file uploaded. Using sample_logs.csv")
    df = pd.read_csv("sample_logs.csv")

# -----------------------------
# VALIDATION
# -----------------------------
required_columns = {"timestamp", "message"}
missing = required_columns - set(df.columns)

if missing:
    st.error(f"Missing required columns: {', '.join(sorted(missing))}")
    st.stop()

# -----------------------------
# PROCESSING
# -----------------------------
df["severity"] = df["message"].apply(classify_event)
df["category"] = df["message"].apply(categorize_event)
df["status"] = df["severity"].apply(lambda x: "Escalate" if x == "HIGH" else "Monitor")

# ✅ NEW: Incident ID
df["incident_id"] = ["INC-" + str(i).zfill(4) for i in range(1, len(df) + 1)]

# ✅ NEW: Convert timestamp
df["timestamp"] = pd.to_datetime(df["timestamp"])

# -----------------------------
# FILTER (NEW)
# -----------------------------
severity_filter = st.selectbox("Filter by Severity", ["ALL", "HIGH", "MEDIUM", "LOW"])

if severity_filter != "ALL":
    df_filtered = df[df["severity"] == severity_filter]
else:
    df_filtered = df

# -----------------------------
# METRICS
# -----------------------------
st.subheader("Alert Summary")
col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(df))
col2.metric("High Severity", int((df["severity"] == "HIGH").sum()))
col3.metric("Escalations", int((df["status"] == "Escalate").sum()))

# -----------------------------
# TABLE
# -----------------------------
st.subheader("Security Events")
st.dataframe(df_filtered, use_container_width=True)

# -----------------------------
# CHARTS
# -----------------------------
st.subheader("Severity Counts")
st.bar_chart(df_filtered["severity"].value_counts())

st.subheader("Incident Categories")
st.bar_chart(df_filtered["category"].value_counts())

# -----------------------------
# TIMELINE (NEW)
# -----------------------------
st.subheader("Event Timeline")
timeline = df_filtered.groupby(df_filtered["timestamp"].dt.minute).size()
st.line_chart(timeline)

# -----------------------------
# HIGH SEVERITY SECTION
# -----------------------------
st.subheader("High Severity Incidents")
high_df = df_filtered[df_filtered["severity"] == "HIGH"]

if high_df.empty:
    st.success("No high severity incidents found.")
else:
    st.dataframe(high_df, use_container_width=True)
