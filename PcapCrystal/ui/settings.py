"""
Settings panel for API keys and configuration management
"""

import streamlit as st
import os
from typing import Dict, Any, List
from pathlib import Path
import yaml
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

def render_settings_panel() -> Dict[str, Any]:
    """Render the settings panel in the sidebar"""
    
    st.subheader("🔧 API Configuration")
    
    # Check for .env file and show info
    env_file_exists = Path('.env').exists()
    if env_file_exists:
        st.info("✅ Found .env file - API keys will be loaded automatically")
    else:
        st.info("💡 Create a .env file to auto-load API keys")
    
    # Load existing settings from environment or session state
    settings = {}
    
    # Threat Intelligence APIs
    with st.expander("🔒 Threat Intelligence APIs", expanded=True):
        vt_env_value = os.getenv('VT_API_KEY', '')
        settings['vt_api_key'] = st.text_input(
            "VirusTotal API Key" + (" 🔑" if vt_env_value else ""),
            value=vt_env_value,
            type='password',
            help="Get your free API key from https://www.virustotal.com/gui/join-us" + ("\n✅ Loaded from environment" if vt_env_value else "")
        )
        
        abuse_env_value = os.getenv('ABUSEIPDB_API_KEY', '')
        settings['abuseipdb_api_key'] = st.text_input(
            "AbuseIPDB API Key" + (" 🔑" if abuse_env_value else ""), 
            value=abuse_env_value,
            type='password',
            help="Get your free API key from https://www.abuseipdb.com/register" + ("\n✅ Loaded from environment" if abuse_env_value else "")
        )
        
        ipinfo_env_value = os.getenv('IPINFO_TOKEN', '')
        settings['ipinfo_token'] = st.text_input(
            "IPinfo Token (Optional)" + (" 🔑" if ipinfo_env_value else ""),
            value=ipinfo_env_value,
            type='password',
            help="Enhanced geolocation data from https://ipinfo.io/signup" + ("\n✅ Loaded from environment" if ipinfo_env_value else "")
        )
    
    # MISP Integration (Optional)
    with st.expander("🔍 MISP Integration (Optional)"):
        misp_url_env_value = os.getenv('MISP_URL', '')
        settings['misp_url'] = st.text_input(
            "MISP Instance URL" + (" 🔑" if misp_url_env_value else ""),
            value=misp_url_env_value,
            help="URL of your MISP threat intelligence platform" + ("\n✅ Loaded from environment" if misp_url_env_value else "")
        )
        
        misp_key_env_value = os.getenv('MISP_API_KEY', '')
        settings['misp_api_key'] = st.text_input(
            "MISP API Key" + (" 🔑" if misp_key_env_value else ""),
            value=misp_key_env_value,
            type='password',
            help="API key for MISP instance" + ("\n✅ Loaded from environment" if misp_key_env_value else "")
        )
    
    # Analysis Configuration
    with st.expander("⚙️ Analysis Settings"):
        settings['cache_ttl_hours'] = st.slider(
            "Cache TTL (hours)",
            min_value=1,
            max_value=168,
            value=24,
            help="How long to cache threat intelligence results"
        )
        
        settings['max_enrichment_concurrent'] = st.slider(
            "Max Concurrent API Calls",
            min_value=1,
            max_value=10,
            value=3,
            help="Maximum concurrent threat intelligence API calls"
        )
        
        settings['enable_geo_enrichment'] = st.checkbox(
            "Enable Geographic Enrichment",
            value=True,
            help="Enrich IP addresses with geographic information"
        )
        
        settings['enable_ml_anomalies'] = st.checkbox(
            "Enable ML-based Anomaly Detection",
            value=True,
            help="Use machine learning for advanced anomaly detection"
        )
    
    # Risk Scoring Configuration
    with st.expander("📊 Risk Scoring Weights"):
        st.write("Configure risk scoring factor weights (must sum to 1.0)")
        
        col1, col2 = st.columns(2)
        
        with col1:
            settings['weight_threat_intel'] = st.slider(
                "Threat Intelligence",
                min_value=0.0,
                max_value=1.0,
                value=0.3,
                step=0.05
            )
            
            settings['weight_protocol_anomalies'] = st.slider(
                "Protocol Anomalies", 
                min_value=0.0,
                max_value=1.0,
                value=0.2,
                step=0.05
            )
            
            settings['weight_traffic_volume'] = st.slider(
                "Traffic Volume",
                min_value=0.0,
                max_value=1.0,
                value=0.15,
                step=0.05
            )
        
        with col2:
            settings['weight_geographic'] = st.slider(
                "Geographic Risk",
                min_value=0.0,
                max_value=1.0,
                value=0.15,
                step=0.05
            )
            
            settings['weight_port_scanning'] = st.slider(
                "Port Scanning",
                min_value=0.0,
                max_value=1.0,
                value=0.1,
                step=0.05
            )
            
            settings['weight_timing'] = st.slider(
                "Timing Anomalies",
                min_value=0.0,
                max_value=1.0,
                value=0.1,
                step=0.05
            )
        
        # Show weight total
        total_weight = (settings['weight_threat_intel'] + settings['weight_protocol_anomalies'] + 
                       settings['weight_traffic_volume'] + settings['weight_geographic'] + 
                       settings['weight_port_scanning'] + settings['weight_timing'])
        
        if abs(total_weight - 1.0) > 0.01:
            st.warning(f"⚠️ Weights sum to {total_weight:.2f}, should be 1.0")
        else:
            st.success(f"✅ Weights sum to {total_weight:.2f}")
    
    # Export/Import Settings
    with st.expander("💾 Settings Management"):
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("Export Settings"):
                _export_settings(settings)
        
        with col2:
            uploaded_settings = st.file_uploader(
                "Import Settings",
                type=['yaml', 'yml'],
                help="Upload a settings YAML file"
            )
            
            if uploaded_settings:
                imported_settings = _import_settings(uploaded_settings)
                if imported_settings:
                    st.success("Settings imported successfully!")
                    settings.update(imported_settings)
    
    # API Status Indicators
    st.divider()
    st.subheader("🔌 API Status")
    
    # Check API key availability
    vt_status = "🟢 Enabled" if settings.get('vt_api_key') else "🔴 Disabled"
    abuse_status = "🟢 Enabled" if settings.get('abuseipdb_api_key') else "🔴 Disabled"
    ipinfo_status = "🟢 Enabled" if settings.get('ipinfo_token') else "⚪ Optional"
    misp_status = "🟢 Enabled" if settings.get('misp_url') and settings.get('misp_api_key') else "⚪ Optional"
    
    st.markdown(f"""
    - **VirusTotal:** {vt_status}
    - **AbuseIPDB:** {abuse_status}
    - **IPinfo:** {ipinfo_status}
    - **MISP:** {misp_status}
    """)
    
    # Show cache information if available
    if 'cache_stats' in st.session_state:
        st.divider()
        st.subheader("📦 Cache Status")
        cache_stats = st.session_state.cache_stats
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Intel Cache Size", f"{cache_stats.get('intel_cache', {}).get('size', 0)} entries")
            st.metric("Geo Cache Size", f"{cache_stats.get('geo_cache', {}).get('size', 0)} entries")
        
        with col2:
            st.metric("Domain Cache Size", f"{cache_stats.get('domain_cache', {}).get('size', 0)} entries")
            st.metric("Total Cache Size", f"{cache_stats.get('total_volume_mb', 0):.1f} MB")
        
        if st.button("Clear All Caches"):
            st.session_state.clear_cache = True
            st.success("Cache clear requested")
    
    return settings

def _export_settings(settings: Dict[str, Any]):
    """Export settings to YAML file"""
    try:
        # Remove sensitive data for export
        export_settings = {k: v for k, v in settings.items() 
                          if not any(sensitive in k.lower() for sensitive in ['key', 'token', 'password'])}
        
        yaml_content = yaml.dump(export_settings, default_flow_style=False)
        
        st.download_button(
            label="Download Settings YAML",
            data=yaml_content,
            file_name=f"pcap_analyzer_settings_{int(datetime.now().timestamp())}.yaml",
            mime="application/x-yaml"
        )
        
    except Exception as e:
        st.error(f"Error exporting settings: {e}")

def _import_settings(uploaded_file) -> Dict[str, Any]:
    """Import settings from YAML file"""
    try:
        settings_data = yaml.safe_load(uploaded_file)
        return settings_data
    except Exception as e:
        st.error(f"Error importing settings: {e}")
        return {}

def show_intel_capabilities(settings: Dict[str, Any]) -> Dict[str, bool]:
    """Show which intelligence capabilities are enabled"""
    capabilities = {
        'virustotal': bool(settings.get('vt_api_key')),
        'abuseipdb': bool(settings.get('abuseipdb_api_key')),
        'ipinfo': bool(settings.get('ipinfo_token')),
        'misp': bool(settings.get('misp_url') and settings.get('misp_api_key')),
        'geolocation': settings.get('enable_geo_enrichment', True),
        'ml_anomalies': settings.get('enable_ml_anomalies', True)
    }
    
    return capabilities

def validate_settings(settings: Dict[str, Any]) -> List[str]:
    """Validate settings and return list of issues"""
    issues = []
    
    # Check weight totals
    weight_keys = [k for k in settings.keys() if k.startswith('weight_')]
    if weight_keys:
        total_weight = sum(settings.get(k, 0) for k in weight_keys)
        if abs(total_weight - 1.0) > 0.01:
            issues.append(f"Risk scoring weights sum to {total_weight:.2f}, should be 1.0")
    
    # Check API key formats (basic validation)
    if settings.get('vt_api_key') and len(settings['vt_api_key']) < 64:
        issues.append("VirusTotal API key appears to be invalid (too short)")
    
    if settings.get('misp_url') and not settings['misp_url'].startswith(('http://', 'https://')):
        issues.append("MISP URL should start with http:// or https://")
    
    return issues
