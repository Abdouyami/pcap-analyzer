import streamlit as st
import os
from pathlib import Path
import asyncio
from datetime import datetime
import warnings

# Import core analyzer
from core.analyzer import EnhancedPCAPAnalyzer

# Import UI components
from ui.settings import render_settings_panel
from ui.tabs import render_main_interface

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning, module="scapy.*")

# Page configuration
st.set_page_config(
    page_title="Enhanced PCAP Network Analyzer",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
.main-header {
    font-size: 2.5rem;
    font-weight: bold;
    color: #1f77b4;
    text-align: center;
    margin-bottom: 2rem;
}
.metric-card {
    background-color: #f0f2f6;
    padding: 1rem;
    border-radius: 0.5rem;
    border-left: 4px solid #1f77b4;
}
.alert-high { border-left-color: #ff4444 !important; background-color: #fff0f0; }
.alert-medium { border-left-color: #ff8800 !important; background-color: #fff8f0; }
.alert-low { border-left-color: #44ff44 !important; background-color: #f0fff0; }
.intel-enabled { color: #28a745; font-weight: bold; }
.intel-disabled { color: #dc3545; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

def initialize_session_state():
    """Initialize session state variables"""
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = None
    if 'analysis_complete' not in st.session_state:
        st.session_state.analysis_complete = False
    if 'settings' not in st.session_state:
        st.session_state.settings = {}

def main():
    """Main application entry point"""
    initialize_session_state()
    
    # Main title
    st.markdown('<h1 class="main-header">🔍 Enhanced PCAP Network Analyzer</h1>', unsafe_allow_html=True)
    
    # Sidebar for settings and file upload
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        # Render settings panel
        settings = render_settings_panel()
        st.session_state.settings = settings
        
        st.divider()
        
        # File upload section
        st.header("📁 PCAP File Upload")
        uploaded_file = st.file_uploader(
            "Choose a PCAP file",
            type=['pcap', 'pcapng'],
            help="Upload a PCAP/PCAPNG file for analysis"
        )
        
        # Analysis options
        st.subheader("Analysis Options")
        max_packets = st.number_input(
            "Maximum packets to analyze",
            min_value=1000,
            max_value=1000000,
            value=100000,
            step=1000,
            help="Limit analysis to prevent memory issues with large files"
        )
        
        enable_enrichment = st.checkbox(
            "Enable Threat Intelligence Enrichment",
            value=bool(settings.get('vt_api_key') or settings.get('abuseipdb_api_key')),
            help="Requires API keys to be configured"
        )
        
        enable_deep_parsing = st.checkbox(
            "Enable Deep Protocol Parsing",
            value=True,
            help="Enhanced HTTP, TLS, and DNS analysis"
        )
        
        # Analysis button
        if uploaded_file and st.button("🔍 Analyze PCAP", type="primary"):
            analyze_pcap_file(uploaded_file, max_packets, enable_enrichment, enable_deep_parsing)
        
        # Sidebar for file upload and controls
        st.sidebar.header("📁 Load PCAP File")

        # Enhanced PCAP resources with ISAKMP info
        st.sidebar.markdown("### 📂 Sample PCAP Resources")
        st.sidebar.markdown("**Note**: This analyzer handles ISAKMP/VPN traffic robustly")

        st.sidebar.markdown("Click a resource below to explore and download PCAP datasets:")
        if st.sidebar.button("🌐 Wireshark Sample Captures"):
            st.sidebar.markdown(
                "<a href='https://wiki.wireshark.org/SampleCaptures' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
                "<span style='font-size:12px;color:gray;'>Official Wireshark collection — VoIP, HTTP, DNS, wireless, etc.</span>",
                unsafe_allow_html=True
            )

        if st.sidebar.button("🦠 Malware-Traffic-Analysis.net"):
            st.sidebar.markdown(
                "<a href='https://www.malware-traffic-analysis.net/' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
                "<span style='font-size:12px;color:gray;'>Real-world malware & C2 traffic — SOC practice.</span>",
                unsafe_allow_html=True
            )

        if st.sidebar.button("📊 NETRESEC PCAP Files"):
            st.sidebar.markdown(
                "<a href='https://www.netresec.com/?page=PcapFiles' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
                "<span style='font-size:12px;color:gray;'>Intrusion attempts, botnets, exploits.</span>",
                unsafe_allow_html=True
            )

        if st.sidebar.button("🤖 Stratosphere IPS Dataset"):
            st.sidebar.markdown(
                "<a href='https://www.stratosphereips.org/datasets-malware/' style='color:#28a745;text-decoration:none;' target='_blank'>Open Link</a>  \n"
                "<span style='font-size:12px;color:gray;'>Labeled benign + malicious traffic — ML/AI detection.</span>",
                unsafe_allow_html=True
            )

    # Main content area
    if st.session_state.analysis_complete and st.session_state.analyzer:
        render_main_interface(st.session_state.analyzer)
    else:
        # Welcome screen
        st.info("👆 Upload a PCAP file from the sidebar to begin analysis")
        
        # Feature overview
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown("""
            ### 🔒 Threat Intelligence
            - VirusTotal integration
            - AbuseIPDB lookups
            - Geolocation enrichment
            - Risk scoring engine
            """)
        
        with col2:
            st.markdown("""
            ### 🔍 Advanced Analytics
            - Deep protocol inspection
            - MITRE ATT&CK mapping
            - Enhanced anomaly detection
            - Multi-stage correlation
            """)
        
        with col3:
            st.markdown("""
            ### 📊 Enhanced Visualizations
            - Geographic attack mapping
            - Advanced network graphs
            - Timeline visualizations
            - Interactive dashboards
            """)

def analyze_pcap_file(uploaded_file, max_packets, enable_enrichment, enable_deep_parsing):
    """Analyze uploaded PCAP file"""
    try:
        # Save uploaded file temporarily with proper path handling
        import tempfile
        import os
        
        # Create a proper temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_file:
            temp_file.write(uploaded_file.getbuffer())
            temp_path = temp_file.name
        
        # Initialize analyzer
        analyzer = EnhancedPCAPAnalyzer(
            settings=st.session_state.settings,
            enable_enrichment=enable_enrichment,
            enable_deep_parsing=enable_deep_parsing
        )
        
        # Show progress
        with st.spinner("🔍 Analyzing PCAP file..."):
            success = analyzer.load_pcap(temp_path, max_packets=max_packets)
        
        if success:
            st.session_state.analyzer = analyzer
            st.session_state.analysis_complete = True
            st.success(f"✅ Analysis complete! Processed {len(analyzer.packets):,} packets")
            
            # Run enrichment if enabled
            if enable_enrichment and analyzer.has_intel_capabilities():
                with st.spinner("🌐 Enriching with threat intelligence..."):
                    asyncio.run(analyzer.enrich_indicators())
                st.success("✅ Threat intelligence enrichment complete!")
            
            st.rerun()
        else:
            st.error("❌ Failed to analyze PCAP file. Please check the file format.")
        
        # Clean up temp file
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass  # File already deleted
            
    except Exception as e:
        st.error(f"❌ Error analyzing PCAP file: {str(e)}")

if __name__ == "__main__":
    main()
