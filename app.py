#!/usr/bin/env python3
"""
Streamlit UI - Advanced Network Forensics Pipeline (fixed for Cloud)
"""

import os
from pathlib import Path
from datetime import datetime
import time
import logging

# matplotlib backend MUST be set before importing pyplot
import matplotlib
matplotlib.use("Agg")

import streamlit as st

# Import modules from package (ensure core/ has __init__.py)
from core.analyzer import PacketAnalyzer
from core.detector import ThreatDetector
from core.reporter import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

st.set_page_config(
    page_title="Network Forensics Pipeline",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Ensure directories exist in a cloud-friendly way
BASE_DIR = Path.cwd()
TEMP_DIR = BASE_DIR / "temp_uploads"
REPORTS_DIR = BASE_DIR / "reports"
TEMP_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Session state
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'packet_data' not in st.session_state:
    st.session_state.packet_data = None
if 'threats' not in st.session_state:
    st.session_state.threats = None
if 'report_dir' not in st.session_state:
    st.session_state.report_dir = None

# Simple header
st.markdown("""
# 🛡️ Advanced Network Forensics Pipeline
Professional-grade PCAP analysis & threat detection
""")

# Sidebar settings
with st.sidebar:
    st.markdown("### ⚙️ Settings")
    max_packets = st.slider("Max Packets to Analyze", 1000, 50000, 50000, step=5000)
    quick_mode = st.checkbox("Quick Analysis Mode", value=False)
    st.markdown("---")
    st.markdown("### 📋 About")
    st.info("""
**Version:** 1.0  
**Analysis Phases:** 1. Packet Analysis  2. Threat Detection  3. Report Generation
""")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload & Analyze", "📊 Results", "🚨 Threats", "📑 Reports"])

with tab1:
    st.markdown("### Step 1: Upload PCAP File")
    col1, col2 = st.columns([3, 1])
    with col1:
        uploaded_file = st.file_uploader("Select a PCAP file for analysis", type=['pcap', 'pcapng'])
    with col2:
        st.metric("Max Packets", f"{max_packets:,}")

    if uploaded_file is not None:
        temp_file = TEMP_DIR / uploaded_file.name
        with open(temp_file, "wb") as f:
            f.write(uploaded_file.getbuffer())
        st.success(f"✅ File uploaded: `{uploaded_file.name}` ({uploaded_file.size / 1024:.2f} KB)")

        col1, col2, col3 = st.columns(3)
        with col1:
            if st.button("🚀 Start Analysis", use_container_width=True):
                try:
                    with st.spinner("🔄 Analyzing PCAP file..."):
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        status_text.text("📊 Phase 1: Analyzing packets...")
                        progress_bar.progress(20)
                        time.sleep(0.2)

                        analyzer = PacketAnalyzer()
                        packet_data = analyzer.analyze(str(temp_file), max_packets=max_packets)
                        st.session_state.packet_data = packet_data

                        status_text.text("🚨 Phase 2: Detecting threats...")
                        progress_bar.progress(60)
                        time.sleep(0.2)

                        detector = ThreatDetector()
                        threats = detector.analyze(packet_data)
                        st.session_state.threats = threats

                        status_text.text("📄 Phase 3: Generating reports...")
                        progress_bar.progress(90)
                        time.sleep(0.2)

                        reporter = ReportGenerator()
                        report_dir = reporter.generate(packet_data, threats, str(REPORTS_DIR))
                        st.session_state.report_dir = report_dir

                        progress_bar.progress(100)
                        status_text.text("✅ Analysis complete!")
                        time.sleep(0.3)
                        progress_bar.empty()
                        status_text.empty()

                        st.success("✅ Analysis Complete!")
                except Exception as e:
                    st.error(f"❌ Analysis failed: {str(e)}")
                    logger.error(f"Analysis error: {str(e)}")

        with col2:
            if st.button("📋 Load Sample Data", use_container_width=True):
                st.info("Sample data feature - not implemented in Cloud mode")
        with col3:
            if st.button("🔄 Clear", use_container_width=True):
                st.session_state.analysis_results = None
                st.session_state.packet_data = None
                st.session_state.threats = None
                st.session_state.report_dir = None
                st.rerun()

with tab2:
    if st.session_state.packet_data is None:
        st.info("📤 Upload and analyze a PCAP file to view results")
    else:
        packet_data = st.session_state.packet_data
        st.markdown("### 📊 Network Statistics")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Packets", f"{packet_data['total_packets']:,}")
        with col2:
            st.metric("Protocols", len(packet_data['protocols']))
        with col3:
            st.metric("Conversations", len(packet_data['conversations']))
        with col4:
            st.metric("DNS Queries", len(packet_data['dns_queries']))

        if packet_data['protocols']:
            proto_data = dict(packet_data['protocols'].most_common(10))
            st.bar_chart(proto_data)

with tab3:
    if st.session_state.threats is None:
        st.info("📤 Upload and analyze a PCAP file to view threats")
    else:
        threats = st.session_state.threats
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Threats", threats['summary']['total'])
        with col2:
            st.metric("🔴 High", threats['summary']['high'])
        with col3:
            st.metric("🟠 Medium", threats['summary']['medium'])
        with col4:
            st.metric("🟡 Low", threats['summary']['low'])

        if threats['high_severity']:
            st.markdown("### 🔴 High Severity Threats")
            for t in threats['high_severity']:
                st.markdown(f"**{t['type']}** — {t.get('confidence','')}: {t.get('description','')}")

with tab4:
    if st.session_state.report_dir is None:
        st.info("📤 Upload and analyze a PCAP file to generate reports")
    else:
        report_dir = Path(st.session_state.report_dir)
        st.markdown("### 📄 Download Analysis Reports")
        json_file = report_dir / "detailed_analysis.json"
        html_file = report_dir / "forensics_report.html"
        txt_file = report_dir / "executive_summary.txt"

        cols = st.columns(3)
        if json_file.exists():
            with open(json_file, 'rb') as f:
                cols[0].download_button("📊 JSON Report", data=f.read(), file_name=json_file.name, mime='application/json')
        if html_file.exists():
            with open(html_file, 'rb') as f:
                cols[1].download_button("🌐 HTML Report", data=f.read(), file_name=html_file.name, mime='text/html')
        if txt_file.exists():
            with open(txt_file, 'r') as f:
                cols[2].download_button("📋 Executive Summary", data=f.read(), file_name=txt_file.name, mime='text/plain')

st.markdown("---")
st.write(f"Advanced Network Forensics Pipeline v1.0 | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")