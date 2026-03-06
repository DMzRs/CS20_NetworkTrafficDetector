import streamlit as st
import pandas as pd
import joblib
import altair as alt
from scapy.all import rdpcap, IP
import tempfile
import os
import numpy as np

# --- PAGE CONFIG ---
st.set_page_config(page_title="NetGuard | Malware Detector", page_icon="🛡️", layout="wide")

# --- GLOBAL CSS ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap');

:root {
  --bg-void:       #0d0a14;
  --bg-deep:       #130f1e;
  --bg-surface:    #1c1630;
  --bg-raised:     #261e42;
  --border:        #3a2e5a;
  --accent-violet: #7c3aed;
  --accent-purple: #a855f7;
  --accent-glow:   #c084fc;
  --text-primary:  #ede9f8;
  --text-muted:    #9b8fc0;
  --text-dim:      #5c4f80;
  --safe:          #22c55e;
  --danger:        #f43f5e;
}

/* ── BACKGROUNDS ── */
.stApp { background-color: var(--bg-void) !important; }

section[data-testid="stSidebar"],
section[data-testid="stSidebar"] > div:first-child {
  background-color: #0f0c19 !important;
  border-right: 1px solid var(--border) !important;
}

/* ── GLOBAL FONT + TEXT ── */
html, body, .stApp, .stApp * {
  font-family: 'Syne', sans-serif !important;
}
.stApp p, .stApp span, .stApp div, .stApp label,
.stApp h1, .stApp h2, .stApp h3, .stApp h4 {
  color: var(--text-primary) !important;
}

/* ── SELECTBOX (baseweb) ── */
div[data-baseweb="select"] > div {
  background-color: var(--bg-surface) !important;
  border-color: var(--border) !important;
  border-radius: 8px !important;
}
div[data-baseweb="select"] span {
  color: var(--text-primary) !important;
}
div[data-baseweb="select"] svg { fill: var(--text-muted) !important; }

/* Dropdown popup */
div[data-baseweb="popover"] > div,
ul[data-baseweb="menu"] {
  background-color: var(--bg-raised) !important;
  border: 1px solid var(--border) !important;
}
li[role="option"] {
  color: var(--text-primary) !important;
  background-color: var(--bg-raised) !important;
}
li[role="option"]:hover,
li[aria-selected="true"] {
  background-color: var(--accent-violet) !important;
  color: white !important;
}

/* ── RADIO ── */
div[data-baseweb="radio"] > label {
  color: var(--text-primary) !important;
}
/* radio dot outer ring */
div[data-baseweb="radio"] div[class] {
  border-color: var(--border) !important;
}
/* selected radio */
div[data-baseweb="radio"] input:checked + div {
  border-color: var(--accent-purple) !important;
  background-color: var(--accent-violet) !important;
}

/* ── FILE UPLOADER ── */
div[data-testid="stFileUploader"] section {
  background-color: var(--bg-surface) !important;
  border: 2px dashed var(--border) !important;
  border-radius: 10px !important;
}
div[data-testid="stFileUploader"] small,
div[data-testid="stFileUploader"] span {
  color: var(--text-muted) !important;
}
div[data-testid="stFileUploader"] button {
  background-color: var(--bg-raised) !important;
  border: 1px solid var(--accent-violet) !important;
  color: var(--accent-glow) !important;
  border-radius: 6px !important;
}
div[data-testid="stFileUploader"] button:hover {
  background-color: var(--accent-violet) !important;
  color: #fff !important;
}

/* ── METRIC CARDS ── */
div[data-testid="stMetric"] {
  background: var(--bg-raised) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
  padding: 1rem 1.4rem !important;
}
div[data-testid="stMetricLabel"] p {
  color: var(--text-muted) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.72rem !important;
  letter-spacing: 0.12em !important;
  text-transform: uppercase !important;
}
div[data-testid="stMetricValue"] {
  color: var(--accent-glow) !important;
  font-size: 2rem !important;
  font-weight: 800 !important;
}
div[data-testid="stMetricDelta"] {
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.68rem !important;
}

/* ── DATAFRAME ── */
div[data-testid="stDataFrame"] {
  border: 1px solid var(--border) !important;
  border-radius: 10px !important;
  overflow: hidden !important;
}

/* ── TABLE ── */
thead tr th {
  background-color: var(--bg-raised) !important;
  color: var(--accent-purple) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.7rem !important;
  letter-spacing: 0.1em !important;
  text-transform: uppercase !important;
  padding: 0.75rem 1rem !important;
  border-bottom: 1px solid var(--border) !important;
}
tbody tr td {
  background-color: var(--bg-surface) !important;
  color: var(--text-primary) !important;
  font-family: 'JetBrains Mono', monospace !important;
  font-size: 0.8rem !important;
  padding: 0.6rem 1rem !important;
  border-bottom: 1px solid var(--border) !important;
}
tbody tr:hover td { background-color: var(--bg-raised) !important; }

/* ── SPINNER ── */
div[data-testid="stSpinner"] p { color: var(--accent-purple) !important; }

/* ── DIVIDER ── */
hr { border-color: var(--border) !important; opacity: 0.4 !important; }

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-deep); }
::-webkit-scrollbar-thumb { background: var(--accent-violet); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--accent-purple); }

/* ── HIDE STREAMLIT CHROME ── */
#MainMenu { visibility: hidden; }
footer    { visibility: hidden; }
div[data-testid="stToolbar"] { display: none; }

/* ── COLUMN GAP ── */
div[data-testid="stHorizontalBlock"] { gap: 1.5rem !important; }
</style>
""", unsafe_allow_html=True)

# ── HERO HEADER ──
st.markdown("""
<div style="
  background: linear-gradient(135deg, #1c1630 0%, #130f1e 60%, #0d0a14 100%);
  border: 1px solid #3a2e5a;
  border-radius: 16px;
  padding: 2.5rem 3rem 2rem 3rem;
  margin-bottom: 2rem;
  position: relative;
  overflow: hidden;
">
  <div style="position:absolute;top:-40px;right:-40px;width:220px;height:220px;
    background:radial-gradient(circle,rgba(124,58,237,0.3) 0%,transparent 70%);
    border-radius:50%;pointer-events:none;"></div>
  <div style="position:absolute;bottom:-30px;left:45%;width:160px;height:160px;
    background:radial-gradient(circle,rgba(168,85,247,0.15) 0%,transparent 70%);
    border-radius:50%;pointer-events:none;"></div>

  <div style="display:flex;align-items:center;gap:0.8rem;margin-bottom:0.5rem;">
    <span style="font-size:1.3rem;background:linear-gradient(135deg,#7c3aed,#a855f7);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;">&#11042;</span>
    <span style="font-family:'JetBrains Mono',monospace;font-size:0.63rem;
      color:#5c4f80;letter-spacing:0.28em;text-transform:uppercase;">
      NETGUARD v1.0 &nbsp;|&nbsp; THREAT INTELLIGENCE
    </span>
  </div>

  <h1 style="font-family:'Syne',sans-serif;font-size:2.4rem;font-weight:800;
    color:#ede9f8 !important;margin:0 0 0.4rem 0;letter-spacing:-0.02em;line-height:1.15;">
    Network Malware
    <span style="background:linear-gradient(90deg,#a855f7,#c084fc);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;">
      Classifier
    </span>
  </h1>
  <p style="color:#9b8fc0 !important;font-size:0.85rem;margin:0;
    font-family:'JetBrains Mono',monospace;letter-spacing:0.04em;">
    Upload a PCAP capture &nbsp;&middot;&nbsp; Choose a model &nbsp;&middot;&nbsp; Identify threats
  </p>
</div>
""", unsafe_allow_html=True)

# --- CACHED LOADERS ---
@st.cache_resource
def load_assets():
    knn    = joblib.load("network_traffic_model_knn.pkl")
    rf     = joblib.load("network_traffic_model_rf.pkl")
    scaler = joblib.load("robust_scaler.pkl")
    return knn, rf, scaler

# --- FEATURE EXTRACTION ---
def process_pcap_scapy(pcap_path):
    packets = rdpcap(pcap_path)
    flows = {}
    for pkt in packets:
        if IP in pkt:
            key = (pkt[IP].src, pkt[IP].dst)
            flows.setdefault(key, []).append(pkt)
    rows = []
    for (src, dst), pkt_list in flows.items():
        fwd = [len(p) for p in pkt_list if p[IP].src == src]
        bwd = [len(p) for p in pkt_list if p[IP].src == dst]
        dur = float(pkt_list[-1].time - pkt_list[0].time)
        rows.append({
            "Src_IP": src, "Dst_IP": dst,
            "Fwd_Pkt_Len_Min":  min(fwd) if fwd else 0,
            "Tot_Fwd_Pkts":     len(fwd),
            "TotLen_Fwd_Pkts":  sum(fwd),
            "Tot_Bwd_Pkts":     len(bwd),
            "Flow_Duration":    dur * 1_000_000,
            "Flow_Byts/s":      sum(fwd + bwd) / dur if dur > 0 else 0,
            "Flow_Pkts/s":      len(pkt_list) / dur if dur > 0 else 0,
            "Fwd_Pkt_Len_Mean": np.mean(fwd) if fwd else 0,
            "Fwd_Pkt_Len_Std":  np.std(fwd)  if fwd else 0,
            "Fwd_Pkt_Len_Max":  max(fwd) if fwd else 0,
        })
    return pd.DataFrame(rows)

knn_model, rf_model, scaler = load_assets()

# ── SIDEBAR ──
with st.sidebar:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
      color:#5c4f80;letter-spacing:0.22em;text-transform:uppercase;
      margin-bottom:1.2rem;padding-bottom:0.8rem;border-bottom:1px solid #3a2e5a;">
      — Configuration —
    </div>""", unsafe_allow_html=True)

    model_choice = st.selectbox("Detection Model", ("KNN", "Random Forest"))
    chart_type   = st.radio("Analysis View", ("Bar Chart", "Pie Chart"))

    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
      color:#5c4f80;letter-spacing:0.22em;text-transform:uppercase;
      margin:1.4rem 0 0.8rem 0;padding-top:0.8rem;border-top:1px solid #3a2e5a;">
      — Upload Capture —
    </div>""", unsafe_allow_html=True)

    uploaded_file = st.file_uploader("PCAP File", type=["pcap"], label_visibility="collapsed")

    st.markdown("""
    <div style="margin-top:1.8rem;padding:1rem;background:#130f1e;
      border:1px solid #3a2e5a;border-radius:10px;
      font-family:'JetBrains Mono',monospace;font-size:0.68rem;
      color:#5c4f80;line-height:2.1;">
      <span style="color:#7c3aed;">&#9632;</span> KNN + Robust Scaler<br>
      <span style="color:#a855f7;">&#9632;</span> Random Forest (raw)<br>
      <span style="color:#3a2e5a;">&#9632;</span> Flow-level analysis<br>
      <span style="color:#3a2e5a;">&#9632;</span> Src / Dst IP tracking
    </div>""", unsafe_allow_html=True)

COLS = ["Fwd_Pkt_Len_Min","Tot_Fwd_Pkts","TotLen_Fwd_Pkts","Tot_Bwd_Pkts",
        "Flow_Duration","Flow_Byts/s","Flow_Pkts/s","Fwd_Pkt_Len_Mean",
        "Fwd_Pkt_Len_Std","Fwd_Pkt_Len_Max"]

def section_label(text):
    st.markdown(f"""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;
      color:#5c4f80;letter-spacing:0.2em;text-transform:uppercase;
      margin-bottom:0.7rem;">— {text} —</div>
    """, unsafe_allow_html=True)

# ── IDLE STATE ──
if not uploaded_file:
    st.markdown("""
    <div style="display:flex;flex-direction:column;align-items:center;
      justify-content:center;min-height:380px;
      background:linear-gradient(160deg,#1c1630 0%,#130f1e 100%);
      border:2px dashed #3a2e5a;border-radius:16px;
      text-align:center;padding:3rem;position:relative;overflow:hidden;">
      <div style="position:absolute;top:50%;left:50%;
        transform:translate(-50%,-50%);width:300px;height:300px;
        background:radial-gradient(circle,rgba(124,58,237,0.07) 0%,transparent 70%);
        border-radius:50%;pointer-events:none;"></div>
      <div style="font-size:3rem;margin-bottom:1rem;opacity:0.45;">&#128225;</div>
      <h3 style="font-family:'Syne',sans-serif;font-size:1.2rem;font-weight:700;
        color:#9b8fc0 !important;margin:0 0 0.5rem 0;">No capture loaded</h3>
      <p style="font-family:'JetBrains Mono',monospace;font-size:0.75rem;
        color:#5c4f80 !important;margin:0;letter-spacing:0.05em;">
        Upload a .pcap file from the sidebar to begin analysis
      </p>
    </div>""", unsafe_allow_html=True)

else:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    try:
        with st.spinner(f"Scanning with {model_choice}…"):
            df    = process_pcap_scapy(tmp_path)
            X_raw = df[COLS].fillna(0)

            if model_choice == "KNN":
                X_ready = scaler.transform(X_raw)
                model   = knn_model
            else:
                X_ready = X_raw.values
                model   = rf_model

            df['Prediction']     = ["BENIGN" if p == 0 else "MALWARE"
                                    for p in model.predict(X_ready)]
            probs                = model.predict_proba(X_ready)
            df['Confidence (%)'] = np.max(probs, axis=1) * 100

        stats         = df['Prediction'].value_counts().reset_index()
        stats.columns = ['Status','Count']
        n_total       = len(df)
        n_malware     = df[df['Prediction'] == "MALWARE"].shape[0]
        n_benign      = n_total - n_malware
        risk_rate     = (n_malware / n_total * 100) if n_total else 0

        # ── KPI STRIP ──
        k1, k2, k3, k4 = st.columns(4)
        with k1: st.metric("Total Flows", f"{n_total:,}")
        with k2: st.metric("Malicious",   f"{n_malware:,}",
                           delta="Threats Found" if n_malware else "Clean",
                           delta_color="inverse")
        with k3: st.metric("Benign",      f"{n_benign:,}")
        with k4: st.metric("Risk Score",  f"{risk_rate:.1f}%",
                           delta="Critical" if risk_rate > 30 else "Normal",
                           delta_color="inverse" if risk_rate > 30 else "normal")

        st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)

        col_chart, col_table = st.columns([1, 1.7], gap="large")

        ax_cfg = dict(
            labelColor='#9b8fc0', titleColor='#5c4f80',
            labelFont='JetBrains Mono', labelFontSize=10,
            gridColor='#261e42', domainColor='#3a2e5a', tickColor='#3a2e5a'
        )
        color_scale = alt.Scale(domain=['BENIGN','MALWARE'], range=['#22c55e','#f43f5e'])

        with col_chart:
            section_label("Traffic Distribution")
            if chart_type == "Bar Chart":
                chart = (
                    alt.Chart(stats)
                    .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
                    .encode(
                        x=alt.X('Status:N', axis=alt.Axis(**ax_cfg)),
                        y=alt.Y('Count:Q',  axis=alt.Axis(**ax_cfg)),
                        color=alt.Color('Status:N', scale=color_scale, legend=None),
                        tooltip=['Status','Count']
                    )
                    .properties(height=300, background='#130f1e',
                                padding={"left":16,"right":16,"top":16,"bottom":8})
                    .configure_view(stroke='#3a2e5a')
                )
            else:
                chart = (
                    alt.Chart(stats)
                    .mark_arc(innerRadius=55, outerRadius=110)
                    .encode(
                        theta=alt.Theta(field="Count", type="quantitative"),
                        color=alt.Color(field="Status", type="nominal",
                                        scale=color_scale,
                                        legend=alt.Legend(
                                            labelColor='#9b8fc0',
                                            labelFont='JetBrains Mono',
                                            labelFontSize=11,
                                            symbolStrokeColor='transparent'
                                        )),
                        tooltip=['Status','Count']
                    )
                    .properties(height=300, background='#130f1e',
                                padding={"left":16,"right":16,"top":16,"bottom":8})
                    .configure_view(stroke='#3a2e5a')
                )
            st.altair_chart(chart, use_container_width=True)

            if model_choice == "KNN":
                st.markdown("""<div style="font-family:'JetBrains Mono',monospace;
                  font-size:0.65rem;color:#7c3aed;letter-spacing:0.06em;margin-top:0.3rem;">
                  &#11042; Robust Scaler applied for KNN</div>""",
                  unsafe_allow_html=True)

        with col_table:
            section_label("Top Malicious Destinations")
            malicious_df = df[df['Prediction'] == "MALWARE"]
            if not malicious_df.empty:
                suspect = (
                    malicious_df
                    .groupby('Dst_IP')
                    .agg(Flows=('Prediction','count'),
                         Avg_Conf=('Confidence (%)','mean'))
                    .sort_values('Flows', ascending=False)
                    .head(10)
                    .rename(columns={'Avg_Conf':'Avg Conf (%)'})
                )
                suspect['Avg Conf (%)'] = suspect['Avg Conf (%)'].map('{:.1f}%'.format)
                st.table(suspect)
            else:
                st.markdown("""
                <div style="background:#0a1a10;border:1px solid #166534;
                  border-radius:10px;padding:1.4rem;text-align:center;
                  font-family:'JetBrains Mono',monospace;font-size:0.85rem;
                  color:#22c55e;letter-spacing:0.04em;">
                  &#10003;&nbsp; No malicious destinations detected
                </div>""", unsafe_allow_html=True)

        st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
        st.markdown("<hr>", unsafe_allow_html=True)
        section_label("Detailed Flow Inspection")

        display_df = df[["Src_IP","Dst_IP","Prediction","Confidence (%)"] + COLS].copy()
        display_df['Confidence (%)'] = display_df['Confidence (%)'].map('{:.2f}%'.format)

        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "Prediction":     st.column_config.TextColumn("Prediction", width="small"),
                "Confidence (%)": st.column_config.TextColumn("Confidence", width="small"),
                "Src_IP":         st.column_config.TextColumn("Source IP",  width="medium"),
                "Dst_IP":         st.column_config.TextColumn("Dest IP",    width="medium"),
            }
        )

    finally:
        os.remove(tmp_path)