#!/usr/bin/env python3
"""
Advanced Network Forensics Pipeline - Streamlit UI
Professional cybersecurity dashboard for PCAP analysis
"""

import streamlit as st
import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path
import json
import asyncio
import threading

def setup_async():
    """Setup async event loop for Streamlit"""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop

# In your Streamlit app, call this before using any async code
setup_async()

# Import forensics modules
sys.path.insert(0, os.path.dirname(__file__))
from core.analyzer import PacketAnalyzer
from core.detector import ThreatDetector
from core.reporter import ReportGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Streamlit page config
st.set_page_config(
    page_title="Network Forensics Pipeline",
    page_icon="🔍",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Custom CSS for cybersecurity theme
st.markdown("""
<style>
    :root {
        --primary: #1a1a2e;
        --secondary: #16213e;
        --accent: #0f3460;
        --danger: #e74c3c;
        --warning: #f39c12;
        --success: #27ae60;
    }
    
    .main {
        background-color: #0f0f1e;
        color: #ecf0f1;
    }
    
    .stTabs [data-baseweb="tab-list"] button {
        background-color: #16213e;
        border-radius: 8px;
        margin-right: 5px;
    }
    
    .stTabs [aria-selected="true"] {
        background-color: #0f3460 !important;
        border-bottom: 3px solid #00d4ff !important;
    }
    
    .threat-high {
        background-color: rgba(231, 76, 60, 0.1);
        border-left: 4px solid #e74c3c;
        padding: 12px;
        border-radius: 4px;
        margin: 8px 0;
    }
    
    .threat-medium {
        background-color: rgba(243, 156, 18, 0.1);
        border-left: 4px solid #f39c12;
        padding: 12px;
        border-radius: 4px;
        margin: 8px 0;
    }
    
    .threat-low {
        background-color: rgba(39, 174, 96, 0.1);
        border-left: 4px solid #27ae60;
        padding: 12px;
        border-radius: 4px;
        margin: 8px 0;
    }
    
    .header-banner {
        background: linear-gradient(135deg, #0f3460 0%, #1a1a2e 100%);
        padding: 20px;
        border-radius: 8px;
        border-left: 4px solid #00d4ff;
        margin-bottom: 20px;
    }
    
    .metric-card {
        background-color: #16213e;
        padding: 15px;
        border-radius: 8px;
        border-left: 4px solid #00d4ff;
    }
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'packet_data' not in st.session_state:
    st.session_state.packet_data = None
if 'threats' not in st.session_state:
    st.session_state.threats = None
if 'report_dir' not in st.session_state:
    st.session_state.report_dir = None

# Header
st.markdown("""
<div class="header-banner">
    <h3>🔍 Advanced Network Forensics Pipeline</h3>
    <p style="margin: 0; color: #00d4ff;">Professional-grade PCAP analysis & threat detection</p>
</div>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.markdown("### ⚙️ Settings")
    max_packets = st.slider("Max Packets to Analyze", 1000, 50000, 50000, step=5000)
    quick_mode = st.checkbox("Quick Analysis Mode", value=False)
    
    st.markdown("---")
    st.markdown("### 📋 About")
    st.info("""
    **Version:** 1.0  
    **Analysis Phases:**
    1. Packet Analysis
    2. Threat Detection
    3. Report Generation
    
    **Output Formats:** TXT, JSON, HTML
    """)

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["📤 Upload & Analyze", "📊 Results", "🚨 Threats", "📑 Reports"])

# ==================== TAB 1: UPLOAD & ANALYZE ====================
with tab1:
    st.markdown("### Step 1: Upload PCAP File")
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        uploaded_file = st.file_uploader(
            "Select a PCAP file for analysis",
            type=['pcap', 'pcapng'],
            help="Upload network traffic capture file"
        )
    
    with col2:
        st.metric("Max Packets", f"{max_packets:,}")
    
    if uploaded_file is not None:
        # Save uploaded file
        temp_dir = Path("temp_uploads")
        temp_dir.mkdir(exist_ok=True)
        temp_file = temp_dir / uploaded_file.name
        
        with open(temp_file, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        st.success(f"✅ File uploaded: `{uploaded_file.name}` ({uploaded_file.size / 1024:.2f} KB)")
        
        # Analysis trigger
        col1, col2, col3 = st.columns(3)
        
        with col1:
            if st.button("🚀 Start Analysis", use_container_width=True, type="primary"):
                with st.spinner("🔄 Analyzing PCAP file..."):
                    try:
                        progress_bar = st.progress(0)
                        status_text = st.empty()
                        
                        # Phase 1: Packet Analysis
                        status_text.text("📊 Phase 1: Analyzing packets...")
                        progress_bar.progress(33)
                        time.sleep(0.5)
                        
                        analyzer = PacketAnalyzer()
                        packet_data = analyzer.analyze(str(temp_file), max_packets=max_packets)
                        st.session_state.packet_data = packet_data
                        
                        # Phase 2: Threat Detection
                        status_text.text("🚨 Phase 2: Detecting threats...")
                        progress_bar.progress(66)
                        time.sleep(0.5)
                        
                        detector = ThreatDetector()
                        threats = detector.analyze(packet_data)
                        st.session_state.threats = threats
                        
                        # Phase 3: Report Generation
                        status_text.text("📄 Phase 3: Generating reports...")
                        progress_bar.progress(90)
                        time.sleep(0.5)
                        
                        reports_dir = Path("reports")
                        reports_dir.mkdir(exist_ok=True)
                        reporter = ReportGenerator()
                        report_dir = reporter.generate(packet_data, threats, str(reports_dir))
                        st.session_state.report_dir = report_dir
                        
                        progress_bar.progress(100)
                        status_text.text("✅ Analysis complete!")
                        time.sleep(1)
                        progress_bar.empty()
                        status_text.empty()
                        
                        st.success("✅ Analysis Complete!")
                        
                        
                    except Exception as e:
                        st.error(f"❌ Analysis failed: {str(e)}")
                        logger.error(f"Analysis error: {str(e)}")
        
        with col2:
            if st.button("📋 Load Sample Data", use_container_width=True):
                st.info("Sample data feature - use for testing without PCAP")
        
        with col3:
            if st.button("🔄 Clear", use_container_width=True):
                st.session_state.analysis_results = None
                st.session_state.packet_data = None
                st.session_state.threats = None
                st.session_state.report_dir = None
                st.rerun()

# ==================== TAB 2: RESULTS ====================
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
        
        # Protocol Distribution
        if packet_data['protocols']:
            st.markdown("### 📈 Protocol Distribution")
            proto_data = dict(packet_data['protocols'].most_common(10))
            st.bar_chart(proto_data)
        
        # Top Ports
        if packet_data['ports']:
            st.markdown("### 🔌 Top Ports")
            port_data = dict(packet_data['ports'].most_common(10))
            st.bar_chart(port_data)
        
        # Top Conversations
        if packet_data['conversations']:
            st.markdown("### 🔗 Top Conversations")
            conv_data = dict(packet_data['conversations'].most_common(10))
            
            col1, col2 = st.columns([2, 1])
            with col1:
                st.bar_chart(conv_data)
            with col2:
                st.metric("Total Conversations", len(packet_data['conversations']))

# ==================== TAB 3: THREATS ====================
with tab3:
    if st.session_state.threats is None:
        st.info("📤 Upload and analyze a PCAP file to view threats")
    else:
        threats = st.session_state.threats
        
        # Threat Summary
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Threats", threats['summary']['total'], 
                     delta_color="inverse" if threats['summary']['total'] > 0 else "off")
        with col2:
            st.metric("🔴 High", threats['summary']['high'], 
                     delta_color="inverse" if threats['summary']['high'] > 0 else "off")
        with col3:
            st.metric("🟠 Medium", threats['summary']['medium'])
        with col4:
            st.metric("🟡 Low", threats['summary']['low'])
        
        # Threat Distribution Pie
        if threats['summary']['total'] > 0:
            st.markdown("### 📊 Threat Severity Distribution")
            threat_dist = {
                'High': threats['summary']['high'],
                'Medium': threats['summary']['medium'],
                'Low': threats['summary']['low']
            }
            st.bar_chart(threat_dist)
        
        # High Severity Threats
        if threats['high_severity']:
            st.markdown("### 🔴 High Severity Threats")
            for threat in threats['high_severity']:
                st.markdown(f"""
<div class="threat-high">
    <strong>{threat['type']}</strong> — {threat['confidence']}  
    <br>{threat['description']}
</div>
""", unsafe_allow_html=True)
        
        # Medium Severity Threats
        if threats['medium_severity']:
            st.markdown("### 🟠 Medium Severity Threats")
            for threat in threats['medium_severity']:
                st.markdown(f"""
<div class="threat-medium">
    <strong>{threat['type']}</strong> — {threat['confidence']}  
    <br>{threat['description']}
</div>
""", unsafe_allow_html=True)
        
        # Low Severity Threats
        if threats['low_severity']:
            with st.expander("🟡 Low Severity Threats"):
                for threat in threats['low_severity']:
                    st.markdown(f"""
<div class="threat-low">
    <strong>{threat['type']}</strong> — {threat['confidence']}  
    <br>{threat['description']}
</div>
""", unsafe_allow_html=True)

# ==================== TAB 4: REPORTS ====================
with tab4:
    if st.session_state.report_dir is None:
        st.info("📤 Upload and analyze a PCAP file to generate reports")
    else:
        report_dir = Path(st.session_state.report_dir)
        
        st.markdown("### 📄 Download Analysis Reports")
        
        col1, col2, col3 = st.columns(3)
        
        # JSON Report
        json_file = report_dir / "detailed_analysis.json"
        if json_file.exists():
            with open(json_file, "rb") as f:
                with col1:
                    st.download_button(
                        label="📊 JSON Report",
                        data=f.read(),
                        file_name=f"forensics_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True
                    )
        
        # HTML Report
        html_file = report_dir / "forensics_report.html"
        if html_file.exists():
            with open(html_file, "rb") as f:
                with col2:
                    st.download_button(
                        label="🌐 HTML Report",
                        data=f.read(),
                        file_name=f"forensics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                        mime="text/html",
                        use_container_width=True
                    )
        
        # Executive Summary
        txt_file = report_dir / "executive_summary.txt"
        if txt_file.exists():
            with open(txt_file, "r") as f:
                with col3:
                    st.download_button(
                        label="📋 Executive Summary",
                        data=f.read(),
                        file_name=f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                        mime="text/plain",
                        use_container_width=True
                    )
        
        # Preview Executive Summary
        st.markdown("### 📋 Executive Summary Preview")
        if txt_file.exists():
            with open(txt_file, "r") as f:
                summary_text = f.read()
                st.text(summary_text)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #7f8c8d; font-size: 12px;">
    Advanced Network Forensics Pipeline v1.0 | Professional Cybersecurity Analysis  
    <br>Generated: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
</div>
""", unsafe_allow_html=True)