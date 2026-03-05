import streamlit as st
import pandas as pd
import joblib
import altair as alt
from scapy.all import rdpcap, IP
import tempfile
import os
import numpy as np

# --- PAGE CONFIG ---
st.set_page_config(page_title="Malware Detector", page_icon="🛡️", layout="wide")

st.title("Multi-Model Network Malware Classifier")

# --- CACHED MODEL LOADER ---
@st.cache_resource
def load_selected_model(model_name):
    filename = "network_traffic_model_knn.pkl" if "KNN" in model_name else "network_traffic_model_rf.pkl"
    return joblib.load(filename)

# --- STABLE FEATURE EXTRACTION (SCAPY) ---
def process_pcap_scapy(pcap_path):
    packets = rdpcap(pcap_path)
    flows = {}

    for pkt in packets:
        if IP in pkt:
            key = (pkt[IP].src, pkt[IP].dst)
            if key not in flows:
                flows[key] = []
            flows[key].append(pkt)

    rows = []
    for (src, dst), pkt_list in flows.items():
        fwd_lengths = [len(p) for p in pkt_list if p[IP].src == src]
        bwd_lengths = [len(p) for p in pkt_list if p[IP].src == dst]
        
        duration = float(pkt_list[-1].time - pkt_list[0].time)
        duration_us = duration * 1000000
        
        rows.append({
            "Src_IP": src,
            "Dst_IP": dst,
            "Fwd_Pkt_Len_Min": min(fwd_lengths) if fwd_lengths else 0,
            "Tot_Fwd_Pkts": len(fwd_lengths),
            "TotLen_Fwd_Pkts": sum(fwd_lengths),
            "Tot_Bwd_Pkts": len(bwd_lengths),
            "Flow_Duration": duration_us,
            "Flow_Byts/s": sum(fwd_lengths + bwd_lengths) / duration if duration > 0 else 0,
            "Flow_Pkts/s": len(pkt_list) / duration if duration > 0 else 0,
            "Fwd_Pkt_Len_Mean": np.mean(fwd_lengths) if fwd_lengths else 0,
            "Fwd_Pkt_Len_Std": np.std(fwd_lengths) if fwd_lengths else 0,
            "Fwd_Pkt_Len_Max": max(fwd_lengths) if fwd_lengths else 0
        })
    return pd.DataFrame(rows)

# --- UI SIDEBAR ---
st.sidebar.header("Configuration")
model_choice = st.sidebar.selectbox("Select Model", ("KNN", "Random Forest"))
chart_type = st.sidebar.radio("Analysis View", ("Bar Chart", "Pie Chart")) # Toggle added here
uploaded_file = st.sidebar.file_uploader("Upload PCAP", type=['pcap'])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getvalue())
        tmp_path = tmp.name

    try:
        model = load_selected_model(model_choice)
        with st.spinner(f'Analyzing with {model_choice}...'):
            df = process_pcap_scapy(tmp_path)
            
            cols = ["Fwd_Pkt_Len_Min", "Tot_Fwd_Pkts", "TotLen_Fwd_Pkts", "Tot_Bwd_Pkts",
                    "Flow_Duration", "Flow_Byts/s", "Flow_Pkts/s", "Fwd_Pkt_Len_Mean",
                    "Fwd_Pkt_Len_Std", "Fwd_Pkt_Len_Max"]
            
            X = df[cols].fillna(0)
            
            # Predictions and Confidence
            df['Prediction'] = ["BENIGN" if p == 0 else "MALWARE" for p in model.predict(X)]
            
            # Calculate Confidence (Probability)
            probs = model.predict_proba(X)
            df['Confidence (%)'] = np.max(probs, axis=1) * 100

        # --- DISPLAY RESULTS ---
        st.subheader(f"Results: {model_choice}")
        
        stats = df['Prediction'].value_counts().reset_index()
        stats.columns = ['Status', 'Count']
        
        col1, col2 = st.columns([1, 2])

        with col1:
            risk_rate = (df[df['Prediction'] == "MALWARE"].shape[0] / len(df)) * 100
            st.metric("Network Risk", f"{risk_rate:.1f}%", delta="Critical" if risk_rate > 30 else "Normal", delta_color="inverse")

            # --- DYNAMIC CHART SELECTION ---
            if chart_type == "Bar Chart":
                chart = alt.Chart(stats).mark_bar().encode(
                    x=alt.X('Status:N', sort='ascending'),
                    y='Count:Q',
                    color=alt.Color('Status:N', scale=alt.Scale(domain=['BENIGN', 'MALWARE'], range=['#2ecc71', '#e74c3c']), legend=None),
                    tooltip=['Status', 'Count']
                ).properties(height=350)
            else:
                chart = alt.Chart(stats).mark_arc(innerRadius=50).encode(
                    theta=alt.Theta(field="Count", type="quantitative"),
                    color=alt.Color(field="Status", type="nominal", scale=alt.Scale(domain=['BENIGN', 'MALWARE'], range=['#2ecc71', '#e74c3c'])),
                    tooltip=['Status', 'Count']
                ).properties(height=350)
            
            st.altair_chart(chart, use_container_width=True)

        with col2:
            st.write("Top Malicious Destination IPs:")
            malicious_df = df[df['Prediction'] == "MALWARE"]
            if not malicious_df.empty:
                # Grouping for report table
                suspect_table = malicious_df.groupby('Dst_IP').agg({'Prediction': 'count', 'Confidence (%)': 'mean'}).rename(columns={'Prediction': 'Flow Count', 'Confidence (%)': 'Avg Confidence'}).sort_values('Flow Count', ascending=False).head(10)
                st.table(suspect_table)
            else:
                st.success("No threats detected.")

        st.divider()
        st.write("### Detailed Flow Inspection (with Model Confidence)")
        st.dataframe(df[["Src_IP", "Dst_IP", "Prediction", "Confidence (%)"] + cols], use_container_width=True)

    finally:
        os.remove(tmp_path)