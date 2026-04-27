import streamlit as st
import pandas as pd
import numpy as np
import os
import time
from datetime import datetime, timedelta
import matplotlib.pyplot as plt

from utils.preprocessing import load_and_clean_dataset, generate_sample_dataset, get_feature_columns
from utils.detector import ThreatDetector
from utils.visualizer import (plot_traffic_over_time, plot_spike_detection, plot_heatmap,
                               plot_bytes_sent_vs_received, plot_daily_attack_trend,
                               plot_protocol_distribution, plot_anomaly_clusters)
from utils.report import generate_pdf_report, export_csv_threats, save_figure

# Page config for premium look
st.set_page_config(
    page_title="Manufacturing Threat Hunter",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme and styling
st.markdown("""
    <style>
    .main { background-color: #0e0e1a; color: white; }
    .stMetric { background-color: #1e1e2f; padding: 15px; border-radius: 10px; border: 1px solid #2d2d44; }
    .stTabs [data-baseweb="tab-list"] { gap: 20px; }
    .stTabs [data-baseweb="tab"] { 
        background-color: #1e1e2f; 
        border-radius: 5px 5px 0 0; 
        padding: 10px 20px;
        color: white;
    }
    .stTabs [aria-selected="true"] { background-color: #2d2d44 !important; border-bottom: 2px solid #007bff !important; }
    </style>
    """, unsafe_allow_html=True)

# Ensure sample dataset exists
if not os.path.exists('data/sample_network_logs.csv'):
    os.makedirs('data', exist_ok=True)
    generate_sample_dataset(1500, 'data/sample_network_logs.csv')

# Initialize session state
if 'live_df' not in st.session_state:
    st.session_state.live_df = None
if 'live_detector' not in st.session_state:
    st.session_state.live_detector = None
if 'live_active' not in st.session_state:
    st.session_state.live_active = False
if 'report_data' not in st.session_state:
    st.session_state.report_data = None
if 'spike_pred' not in st.session_state:
    st.session_state.spike_pred = None

# Sidebar Controls
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=80)
st.sidebar.title("Threat Hunter Control")

uploaded_file = st.sidebar.file_uploader("📂 Upload Network Logs (CSV)", type=["csv"])
analyze_btn = st.sidebar.button("🚀 Analyze Traffic", use_container_width=True, type="primary")

st.sidebar.markdown("---")
st.sidebar.subheader("📡 Real-Time Simulation")
live_toggle = st.sidebar.toggle("Enable Live Monitoring", value=st.session_state.live_active)
st.session_state.live_active = live_toggle

st.sidebar.markdown("---")
st.sidebar.subheader("📥 Export Center")
if st.sidebar.button("🛠️ Generate Security Report", use_container_width=True):
    if st.session_state.report_data:
        with st.spinner("Compiling security findings..."):
            df, threat_results, summary = st.session_state.report_data
            pdf_path = generate_pdf_report(df, threat_results, summary)
            csv_path = export_csv_threats(threat_results)
            
            st.sidebar.success("✅ Reports Ready")
            with open(pdf_path, "rb") as f:
                st.sidebar.download_button("📥 Download PDF Report", f, file_name="security_report.pdf", use_container_width=True)
            with open(csv_path, "rb") as f:
                st.sidebar.download_button("📊 Download Threat CSV", f, file_name="threat_logs.csv", use_container_width=True)
    else:
        st.sidebar.error("No data analyzed yet!")

# Main Content
st.title("🛡️ Manufacturing Threat Hunter")
st.markdown("### AI-Powered Cyber Threat Detection & Visualization")

# Processing logic
def process_data(file_path):
    df = load_and_clean_dataset(file_path)
    feature_cols = get_feature_columns(df)
    detector = ThreatDetector()
    detector.train_models(df, feature_cols)
    threat_results = detector.detect_threats(df)
    spike_pred = detector.predict_next_spike(df)
    
    summary = {
        'total_logs': len(df),
        'suspicious_events': int(threat_results['anomaly_ml'].sum()),
        'critical_threats': int((threat_results['threat_score'] >= 75).sum()),
        'peak_traffic_time': df.groupby(df['timestamp'].dt.hour)['total_bytes'].sum().idxmax()
    }
    
    st.session_state.live_df = df.copy()
    st.session_state.live_detector = detector
    st.session_state.report_data = (df, threat_results, summary)
    st.session_state.spike_pred = spike_pred
    return df, threat_results, summary, spike_pred

# Initial load or analysis
if analyze_btn:
    if uploaded_file:
        with open("temp_upload.csv", "wb") as f:
            f.write(uploaded_file.getbuffer())
        with st.spinner("Analyzing network logs..."):
            process_data("temp_upload.csv")
            st.success("Analysis complete!")
    else:
        st.sidebar.error("⚠️ Please upload a CSV file first.")

# Top Metrics Row
if st.session_state.report_data:
    df, threat_results, summary = st.session_state.report_data
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("📊 Total Logs", summary['total_logs'])
    m2.metric("⚠️ Suspicious Events", summary['suspicious_events'], delta=None, delta_color="inverse")
    m3.metric("🔥 Critical Threats", summary['critical_threats'], delta=None, delta_color="inverse")
    m4.metric("⏰ Peak Traffic Time", f"{summary['peak_traffic_time']}:00")

    # Tabs
    tab1, tab2 = st.tabs(["📈 Security Analytics", "📋 Detailed Data & AI Insights"])

    with tab1:
        c1, c2 = st.columns(2)
        with c1:
            st.pyplot(plot_traffic_over_time(df))
        with c2:
            st.pyplot(plot_spike_detection(df, np.percentile(df['bytes_sent'], 95)))
            
        c3, c4 = st.columns(2)
        with c3:
            st.pyplot(plot_heatmap(df))
        with c4:
            st.pyplot(plot_bytes_sent_vs_received(df))
            
        c5, c6 = st.columns(2)
        with c5:
            st.pyplot(plot_daily_attack_trend(df))
        with c6:
            st.pyplot(plot_protocol_distribution(df))
            
        st.pyplot(plot_anomaly_clusters(df, threat_results))

    with tab2:
        st.subheader("🛡️ AI Detection Summary")
        a1, a2, a3, a4 = st.columns(4)
        a1.info(f"**Isolation Forest:** {threat_results['iforest_anomaly'].sum()} anomalies")
        a2.info(f"**Local Outlier Factor:** {threat_results['lof_anomaly'].sum()} anomalies")
        a3.info(f"**K-Means Clusters:** {threat_results['kmeans_anomaly'].sum()} outliers")
        a4.info(f"**Random Forest:** {threat_results['rf_anomaly'].sum()} flagged")
        
        if st.session_state.spike_pred:
            sp = st.session_state.spike_pred
            st.warning(f"**Next Hour Prediction:** {'⚠️ SPIKE LIKELY' if sp['next_hour_spike'] else '✅ Normal expected'}")
        
        st.subheader("📋 Traffic Logs Preview")
        st.dataframe(df.head(100), use_container_width=True)
else:
    # Placeholder screen when no data is uploaded
    st.info("👋 Welcome to Manufacturing Threat Hunter!")
    st.markdown("""
    To get started:
    1. **Upload** a network log CSV file in the sidebar.
    2. Click **Analyze Traffic** to start the AI-powered detection.
    3. Explore the **Security Analytics** and **AI Insights** once processing is complete.
    
    *Note: The system expects CSV files with network traffic metrics such as bytes sent/received, connections, and protocols.*
    """)
    
    # Show a sample of what's expected
    with st.expander("👁️ View Expected Data Format"):
        sample_df = pd.read_csv('data/sample_network_logs.csv').head(5)
        st.write("Your CSV should look similar to this:")
        st.dataframe(sample_df)

# Live Simulation Execution
if st.session_state.live_active and st.session_state.live_df is not None:
    time.sleep(3) # Wait for simulation interval
    
    # Generate new row
    last_row = st.session_state.live_df.iloc[-1].copy()
    new_time = last_row['timestamp'] + timedelta(seconds=10)
    
    if np.random.random() < 0.1:
        bytes_sent = np.random.uniform(8000, 50000)
        connections = np.random.poisson(80)
        status = 'Suspicious'
    else:
        bytes_sent = max(100, last_row['bytes_sent'] + np.random.normal(0, 200))
        connections = max(1, last_row['connections'] + np.random.poisson(2))
        status = 'Normal'
        
    new_row = pd.DataFrame([{
        'timestamp': new_time,
        'device_ip': last_row['device_ip'],
        'protocol': last_row['protocol'],
        'bytes_sent': bytes_sent,
        'bytes_received': np.random.exponential(300),
        'connections': connections,
        'status': status,
        'hour': new_time.hour,
        'day_of_week': new_time.dayofweek,
        'total_bytes': bytes_sent + last_row['bytes_received'],
        'protocol_encoded': last_row['protocol_encoded']
    }])
    
    st.session_state.live_df = pd.concat([st.session_state.live_df, new_row], ignore_index=True)
    if len(st.session_state.live_df) > 2000:
        st.session_state.live_df = st.session_state.live_df.iloc[-2000:]
        
    # Update report data for the main UI to show
    df = st.session_state.live_df
    threat_results = st.session_state.live_detector.detect_threats(df)
    summary = {
        'total_logs': len(df),
        'suspicious_events': int(threat_results['anomaly_ml'].sum()),
        'critical_threats': int((threat_results['threat_score'] >= 75).sum()),
        'peak_traffic_time': df.groupby(df['timestamp'].dt.hour)['total_bytes'].sum().idxmax()
    }
    st.session_state.report_data = (df, threat_results, summary)
    
    st.rerun()