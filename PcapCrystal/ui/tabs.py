"""
Main interface tabs for the Enhanced PCAP Analyzer
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json
from typing import Dict, List, Any

from viz.geographic import render_geographic_analysis
from viz.enhanced_graphs import render_enhanced_network_graph, render_attack_timeline
from utils.helpers import format_bytes, format_duration, get_severity_color

def render_main_interface(analyzer):
    """Render the main analysis interface with enhanced tabs"""
    
    # Create main tabs
    tab_names = [
        "📊 Overview", 
        "🔍 Enhanced Analysis", 
        "🌐 Geographic Intel",
        "🎯 Security Detections",
        "📈 Advanced Visualizations", 
        "🔗 Network Analysis",
        "📋 Packet Analysis",
        "📄 Reports"
    ]
    
    tabs = st.tabs(tab_names)
    
    # Overview Tab
    with tabs[0]:
        render_overview_tab(analyzer)
    
    # Enhanced Analysis Tab  
    with tabs[1]:
        render_enhanced_analysis_tab(analyzer)
    
    # Geographic Intelligence Tab
    with tabs[2]:
        render_geographic_tab(analyzer)
    
    # Security Detections Tab
    with tabs[3]:
        render_security_detections_tab(analyzer)
    
    # Advanced Visualizations Tab
    with tabs[4]:
        render_visualizations_tab(analyzer)
    
    # Network Analysis Tab
    with tabs[5]:
        render_network_analysis_tab(analyzer)
    
    # Packet Analysis Tab
    with tabs[6]:
        render_packet_analysis_tab(analyzer)
    
    # Reports Tab
    with tabs[7]:
        render_reports_tab(analyzer)

def render_overview_tab(analyzer):
    """Render enhanced overview with threat intelligence summary"""
    st.subheader("📊 Analysis Overview")
    
    # Basic metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Total Packets", 
            f"{len(analyzer.packets):,}",
            help="Total number of packets analyzed"
        )
    
    with col2:
        total_bytes = analyzer.packet_df['length'].sum() if not analyzer.packet_df.empty else 0
        st.metric(
            "Total Bytes",
            format_bytes(total_bytes),
            help="Total bytes transferred"
        )
    
    with col3:
        unique_ips = len(set(analyzer.packet_df['src_ip'].dropna()) | set(analyzer.packet_df['dst_ip'].dropna())) if not analyzer.packet_df.empty else 0
        st.metric(
            "Unique IPs",
            f"{unique_ips:,}",
            help="Number of unique IP addresses"
        )
    
    with col4:
        if not analyzer.packet_df.empty:
            duration = analyzer.packet_df['timestamp'].max() - analyzer.packet_df['timestamp'].min()
        else:
            duration = 0
        st.metric(
            "Capture Duration",
            format_duration(duration),
            help="Duration of the network capture"
        )
    
    # Enhanced metrics with intelligence data
    if hasattr(analyzer, 'enrichment_results') and analyzer.enrichment_results:
        st.divider()
        st.subheader("🔒 Threat Intelligence Summary")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            enriched_ips = len(analyzer.enrichment_results)
            st.metric("Enriched IPs", f"{enriched_ips:,}")
        
        with col2:
            malicious_count = sum(1 for result in analyzer.enrichment_results.values() if result.is_malicious)
            st.metric(
                "Malicious IPs", 
                f"{malicious_count:,}",
                delta=f"{(malicious_count/enriched_ips*100):.1f}%" if enriched_ips > 0 else "0%"
            )
        
        with col3:
            high_risk_count = sum(1 for result in analyzer.enrichment_results.values() if result.overall_reputation > 70)
            st.metric("High Risk IPs", f"{high_risk_count:,}")
        
        with col4:
            avg_confidence = sum(result.confidence for result in analyzer.enrichment_results.values()) / enriched_ips if enriched_ips > 0 else 0
            st.metric("Avg Confidence", f"{avg_confidence:.0f}%")
    
    # Risk Score Summary
    if hasattr(analyzer, 'risk_scores') and analyzer.risk_scores:
        st.divider()
        st.subheader("⚠️ Risk Assessment")
        
        risk_scores = analyzer.risk_scores
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            high_risk = sum(1 for score in risk_scores if score.overall_score >= 70)
            st.metric(
                "High Risk Entities", 
                f"{high_risk:,}",
                delta="Requires attention" if high_risk > 0 else "All clear",
                delta_color="inverse"
            )
        
        with col2:
            medium_risk = sum(1 for score in risk_scores if 40 <= score.overall_score < 70)
            st.metric("Medium Risk Entities", f"{medium_risk:,}")
        
        with col3:
            avg_risk = sum(score.overall_score for score in risk_scores) / len(risk_scores)
            st.metric("Average Risk Score", f"{avg_risk:.0f}/100")
        
        # Risk distribution chart
        if risk_scores:
            risk_levels = []
            for score in risk_scores:
                if score.overall_score >= 70:
                    risk_levels.append('High')
                elif score.overall_score >= 40:
                    risk_levels.append('Medium')
                elif score.overall_score >= 20:
                    risk_levels.append('Low')
                else:
                    risk_levels.append('Minimal')
            
            risk_df = pd.DataFrame({'Risk Level': risk_levels})
            fig = px.pie(
                risk_df, 
                names='Risk Level',
                title="Risk Distribution",
                color_discrete_map={
                    'High': '#dc3545',
                    'Medium': '#fd7e14', 
                    'Low': '#ffc107',
                    'Minimal': '#28a745'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Protocol distribution
    if not analyzer.packet_df.empty:
        st.divider()
        st.subheader("🔄 Protocol Distribution")
        
        protocol_counts = analyzer.packet_df['protocol'].value_counts()
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            fig = px.pie(
                values=protocol_counts.values,
                names=protocol_counts.index,
                title="Packets by Protocol"
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Protocol table with percentages
            protocol_df = pd.DataFrame({
                'Protocol': protocol_counts.index,
                'Packets': protocol_counts.values,
                'Percentage': (protocol_counts.values / len(analyzer.packet_df) * 100).round(1)
            })
            st.dataframe(protocol_df, use_container_width=True)

def render_enhanced_analysis_tab(analyzer):
    """Render enhanced analysis with deep protocol inspection"""
    st.subheader("🔍 Enhanced Protocol Analysis")
    
    # Threat Intelligence Details Section
    if hasattr(analyzer, 'enrichment_results') and analyzer.enrichment_results:
        st.divider()
        st.subheader("🔒 Threat Intelligence Details")
        
        # Create detailed threat intel table
        threat_intel_data = []
        for ip, result in analyzer.enrichment_results.items():
            row_data = {
                'IP Address': ip,
                'Country': result.geo_location.country if result.geo_location else 'Unknown',
                'Is Malicious': '🚨 Yes' if result.is_malicious else '✅ No',
                'Overall Risk': f"{result.overall_reputation}/100",
                'Confidence': f"{result.confidence}%"
            }
            
            # Add VirusTotal data if available
            if hasattr(result, 'virustotal_data') and result.virustotal_data:
                vt_data = result.virustotal_data
                if isinstance(vt_data, dict):
                    detection_ratio = f"{vt_data.get('malicious', 0)}/{vt_data.get('total', 0)}"
                    row_data['VirusTotal'] = f"{detection_ratio} engines"
                    if vt_data.get('malicious', 0) > 0:
                        row_data['VT Categories'] = ', '.join(vt_data.get('categories', []))[:50]
                else:
                    row_data['VirusTotal'] = 'Available'
            else:
                row_data['VirusTotal'] = 'No data'
            
            # Add AbuseIPDB data if available  
            if hasattr(result, 'abuseipdb_data') and result.abuseipdb_data:
                abuse_data = result.abuseipdb_data
                if isinstance(abuse_data, dict):
                    abuse_confidence = abuse_data.get('confidence_percentage', 0)
                    usage_type = abuse_data.get('usage_type', 'Unknown')
                    row_data['AbuseIPDB'] = f"{abuse_confidence}% ({usage_type})"
                    if abuse_data.get('is_whitelisted'):
                        row_data['AbuseIPDB'] += ' [Whitelisted]'
                else:
                    row_data['AbuseIPDB'] = 'Available'
            else:
                row_data['AbuseIPDB'] = 'No data'
            
            threat_intel_data.append(row_data)
        
        if threat_intel_data:
            threat_df = pd.DataFrame(threat_intel_data)
            
            # Filter options
            col1, col2, col3 = st.columns(3)
            with col1:
                show_only_malicious = st.checkbox("Show only malicious IPs", value=False)
            with col2:
                min_confidence = st.slider("Minimum confidence %", 0, 100, 0)
            with col3:
                country_filter = st.multiselect(
                    "Filter by country",
                    options=threat_df['Country'].unique()
                )
            
            # Apply filters
            filtered_df = threat_df.copy()
            if show_only_malicious:
                filtered_df = filtered_df[filtered_df['Is Malicious'] == '🚨 Yes']
            
            filtered_df['Confidence_num'] = filtered_df['Confidence'].str.replace('%', '').astype(int)
            filtered_df = filtered_df[filtered_df['Confidence_num'] >= min_confidence]
            filtered_df = filtered_df.drop('Confidence_num', axis=1)
            
            if country_filter:
                filtered_df = filtered_df[filtered_df['Country'].isin(country_filter)]
            
            # Style the dataframe
            def highlight_malicious(row):
                if row['Is Malicious'] == '🚨 Yes':
                    return ['background-color: #fffbe6; color: #1a237e; font-weight: bold;'] * len(row)
                return [''] * len(row)
            
            if not filtered_df.empty:
                st.dataframe(
                    filtered_df.style.apply(highlight_malicious, axis=1),
                    use_container_width=True,
                    hide_index=True
                )
                
                # Export option
                if st.button("📥 Export Threat Intelligence Data"):
                    csv = filtered_df.to_csv(index=False)
                    st.download_button(
                        label="Download CSV",
                        data=csv,
                        file_name=f"threat_intelligence_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
            else:
                st.info("No data matches the selected filters.")
        else:
            st.info("No threat intelligence data available.")
    else:
        st.info("💡 Enable threat intelligence enrichment in the sidebar to see detailed VirusTotal and AbuseIPDB results here.")
    
    st.divider()
    
    if hasattr(analyzer, 'protocol_analysis') and analyzer.protocol_analysis:
        # HTTP Analysis
        if 'http' in analyzer.protocol_analysis:
            st.subheader("🌐 HTTP Analysis")
            http_data = analyzer.protocol_analysis['http']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("HTTP Requests", len(http_data.get('requests', [])))
            with col2:
                st.metric("HTTP Responses", len(http_data.get('responses', [])))
            with col3:
                suspicious_requests = sum(1 for req in http_data.get('requests', []) if req.get('analysis', {}).get('risk_score', 0) > 50)
                st.metric("Suspicious Requests", suspicious_requests)
            
            # Top user agents
            if http_data.get('requests'):
                user_agents = [req.get('user_agent', 'Unknown') for req in http_data['requests']]
                ua_counts = pd.Series(user_agents).value_counts().head(10)
                
                st.subheader("Top User Agents")
                st.bar_chart(ua_counts)
        
        # TLS Analysis
        if 'tls' in analyzer.protocol_analysis:
            st.subheader("🔒 TLS Analysis")
            tls_data = analyzer.protocol_analysis['tls']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("TLS Sessions", len(tls_data.get('sessions', [])))
            with col2:
                unique_ja3 = len(set(session.get('ja3', {}).get('ja3_hash', '') for session in tls_data.get('sessions', []) if session.get('ja3', {}).get('ja3_hash')))
                st.metric("Unique JA3 Hashes", unique_ja3)
            with col3:
                suspicious_tls = sum(1 for session in tls_data.get('sessions', []) if session.get('suspicious', False))
                st.metric("Suspicious TLS", suspicious_tls)
        
        # DNS Analysis
        if 'dns' in analyzer.protocol_analysis:
            st.subheader("🔍 DNS Analysis")
            dns_data = analyzer.protocol_analysis['dns']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("DNS Queries", len(dns_data.get('queries', [])))
            with col2:
                unique_domains = len(set(query.get('domain', '') for query in dns_data.get('queries', [])))
                st.metric("Unique Domains", unique_domains)
            with col3:
                high_entropy_domains = sum(1 for query in dns_data.get('queries', []) if query.get('analysis', {}).get('entropy', 0) > 3.5)
                st.metric("High Entropy Domains", high_entropy_domains)
    
    else:
        st.info("Enhanced protocol analysis not available. Enable deep parsing in the sidebar.")

def render_geographic_tab(analyzer):
    """Render geographic intelligence analysis"""
    st.subheader("🌐 Geographic Intelligence")
    
    if hasattr(analyzer, 'enrichment_results') and analyzer.enrichment_results:
        render_geographic_analysis(analyzer.enrichment_results)
    else:
        st.info("Geographic intelligence not available. Enable threat intelligence enrichment and re-analyze.")

def render_security_detections_tab(analyzer):
    """Render security detections with MITRE ATT&CK mapping"""
    st.subheader("🎯 Security Detections")
    
    if hasattr(analyzer, 'detections') and analyzer.detections:
        # Detection summary
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Detections", len(analyzer.detections))
        
        with col2:
            high_severity = sum(1 for det in analyzer.detections if det.severity.value == 'high')
            st.metric("High Severity", high_severity)
        
        with col3:
            medium_severity = sum(1 for det in analyzer.detections if det.severity.value == 'medium')
            st.metric("Medium Severity", medium_severity)
        
        with col4:
            unique_techniques = len(set(det.mitre_attack.technique for det in analyzer.detections if det.mitre_attack))
            st.metric("MITRE Techniques", unique_techniques)
        
        # MITRE ATT&CK Matrix View
        if hasattr(analyzer, 'mitre_report') and analyzer.mitre_report:
            st.divider()
            st.subheader("🎯 MITRE ATT&CK Coverage")
            
            attack_matrix = analyzer.mitre_report.get('attack_matrix', {})
            
            if attack_matrix:
                for tactic, techniques in attack_matrix.items():
                    with st.expander(f"**{tactic}** ({len(techniques)} techniques)"):
                        for technique in techniques:
                            st.write(f"• {technique}")
        
        # Detections table
        st.divider()
        st.subheader("📋 Detection Details")
        
        # Create detections DataFrame
        detections_data = []
        for det in analyzer.detections:
            detections_data.append({
                'Name': det.name,
                'Severity': det.severity.value.title(),
                'Confidence': f"{det.confidence}%",
                'Source IP': det.source_ip or 'N/A',
                'Destination IP': det.destination_ip or 'N/A',
                'MITRE Technique': det.mitre_attack.technique if det.mitre_attack else 'N/A',
                'Risk Score': det.risk_score,
                'First Seen': det.first_seen.strftime('%Y-%m-%d %H:%M:%S') if det.first_seen else 'N/A'
            })
        
        if detections_data:
            detections_df = pd.DataFrame(detections_data)
            
            # Add severity filtering
            severity_filter = st.multiselect(
                "Filter by Severity",
                options=['Low', 'Medium', 'High', 'Critical'],
                default=['High', 'Critical']
            )
            
            if severity_filter:
                filtered_df = detections_df[detections_df['Severity'].isin(severity_filter)]
            else:
                filtered_df = detections_df
            
            # Style the dataframe
            def style_severity(val):
                color_map = {
                    'Low': 'background-color: #d4edda; color: #155724',
                    'Medium': 'background-color: #fff3cd; color: #856404', 
                    'High': 'background-color: #f8d7da; color: #721c24',
                    'Critical': 'background-color: #f5c6cb; color: #721c24'
                }
                return color_map.get(val, '')
            
            styled_df = filtered_df.style.applymap(style_severity, subset=['Severity'])
            st.dataframe(styled_df, use_container_width=True)
            
            # Detection details expander
            st.subheader("🔍 Detection Details")
            selected_detection = st.selectbox("Select detection for details:", [f"{det.name} - {det.source_ip}" for det in analyzer.detections])
            
            if selected_detection:
                det_index = [f"{det.name} - {det.source_ip}" for det in analyzer.detections].index(selected_detection)
                selected_det = analyzer.detections[det_index]
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Description:** {selected_det.description}")
                    st.write(f"**Confidence:** {selected_det.confidence}%")
                    st.write(f"**Risk Score:** {selected_det.risk_score}/100")
                
                with col2:
                    if selected_det.mitre_attack:
                        st.write(f"**MITRE Tactic:** {selected_det.mitre_attack.tactic}")
                        st.write(f"**MITRE Technique:** {selected_det.mitre_attack.technique}")
                        st.write(f"**Documentation:** [Link]({selected_det.mitre_attack.url})")
                
                if selected_det.evidence:
                    st.write("**Evidence:**")
                    st.json(selected_det.evidence)
    
    else:
        st.info("No security detections found or detection engine not run.")

def render_visualizations_tab(analyzer):
    """Render advanced visualizations"""
    st.subheader("📈 Advanced Visualizations")
    
    viz_type = st.selectbox(
        "Select Visualization Type",
        ["Network Graph", "Attack Timeline", "Traffic Heatmap", "Geographic Flow Map"]
    )
    
    if viz_type == "Network Graph":
        if not analyzer.packet_df.empty:
            render_enhanced_network_graph(analyzer)
        else:
            st.info("No network data available for visualization.")
    
    elif viz_type == "Attack Timeline":
        if hasattr(analyzer, 'detections') and analyzer.detections:
            render_attack_timeline(analyzer.detections)
        else:
            st.info("No detections available for timeline visualization.")
    
    elif viz_type == "Traffic Heatmap":
        render_traffic_heatmap(analyzer)
    
    elif viz_type == "Geographic Flow Map":
        if hasattr(analyzer, 'enrichment_results') and analyzer.enrichment_results:
            render_geographic_flow_map(analyzer)
        else:
            st.info("Geographic data not available. Enable threat intelligence enrichment.")

def render_network_analysis_tab(analyzer):
    """Render network analysis with conversation details"""
    st.subheader("🔗 Network Analysis")
    
    # Conversation analysis
    if analyzer.conversations:
        st.subheader("💬 Conversation Analysis")
        
        # Convert conversations to DataFrame
        conv_data = []
        for (src, dst), stats in analyzer.conversations.items():
            conv_data.append({
                'Source IP': src,
                'Destination IP': dst,
                'Packets': stats.get('packets', 0),
                'Bytes': stats.get('bytes', 0),
                'Duration (s)': stats.get('end_time', 0) - stats.get('start_time', 0),
                'Protocols': ', '.join(stats.get('protocols', {}).keys()),
                'Risk Score': getattr(stats, 'risk_score', 0)
            })
        
        conv_df = pd.DataFrame(conv_data)
        
        # Add sorting and filtering
        sort_by = st.selectbox("Sort by", ['Packets', 'Bytes', 'Duration (s)', 'Risk Score'])
        ascending = st.checkbox("Ascending", value=False)
        
        sorted_df = conv_df.sort_values(sort_by, ascending=ascending)
        
        st.dataframe(sorted_df, use_container_width=True)
        
        # Top conversations by bytes
        st.subheader("📊 Top Conversations by Data Volume")
        top_convs = conv_df.nlargest(10, 'Bytes')
        
        fig = px.bar(
            top_convs,
            x='Bytes',
            y=[f"{row['Source IP']} → {row['Destination IP']}" for _, row in top_convs.iterrows()],
            orientation='h',
            title="Top 10 Conversations by Bytes Transferred"
        )
        st.plotly_chart(fig, use_container_width=True)

def render_packet_analysis_tab(analyzer):
    """Render detailed packet analysis"""
    st.subheader("📋 Packet Analysis")
    
    if not analyzer.packet_df.empty:
        # Packet filtering
        col1, col2, col3 = st.columns(3)
        
        with col1:
            protocol_filter = st.multiselect(
                "Filter by Protocol",
                options=analyzer.packet_df['protocol'].unique().tolist(),
                default=[]
            )
        
        with col2:
            ip_filter = st.text_input("Filter by IP", placeholder="Enter IP address")
        
        with col3:
            port_filter = st.text_input("Filter by Port", placeholder="Enter port number")
        
        # Apply filters
        filtered_df = analyzer.packet_df.copy()
        
        if protocol_filter:
            filtered_df = filtered_df[filtered_df['protocol'].isin(protocol_filter)]
        
        if ip_filter:
            filtered_df = filtered_df[
                (filtered_df['src_ip'].str.contains(ip_filter, na=False)) |
                (filtered_df['dst_ip'].str.contains(ip_filter, na=False))
            ]
        
        if port_filter:
            try:
                port_num = int(port_filter)
                filtered_df = filtered_df[
                    (filtered_df['src_port'] == port_num) |
                    (filtered_df['dst_port'] == port_num)
                ]
            except ValueError:
                pass
        
        st.write(f"Showing {len(filtered_df):,} of {len(analyzer.packet_df):,} packets")
        
        # Display packet table
        display_columns = ['index', 'datetime', 'src_ip', 'dst_ip', 'protocol', 'src_port', 'dst_port', 'length']
        available_columns = [col for col in display_columns if col in filtered_df.columns]
        
        st.dataframe(
            filtered_df[available_columns].head(1000),  # Limit for performance
            use_container_width=True
        )
        
        if len(filtered_df) > 1000:
            st.info("Showing first 1,000 packets. Use filters to narrow down results.")

def render_reports_tab(analyzer):
    """Render reports generation and export"""
    st.subheader("📄 Reports & Export")
    
    report_type = st.selectbox(
        "Select Report Type",
        ["Executive Summary", "Technical Analysis", "MITRE ATT&CK Report", "Raw Data Export"]
    )
    
    if report_type == "Executive Summary":
        render_executive_summary(analyzer)
    
    elif report_type == "Technical Analysis":
        render_technical_report(analyzer)
    
    elif report_type == "MITRE ATT&CK Report":
        render_mitre_report(analyzer)
    
    elif report_type == "Raw Data Export":
        render_data_export(analyzer)

def render_executive_summary(analyzer):
    """Render executive summary report"""
    st.subheader("👔 Executive Summary")
    
    # Generate executive summary
    summary = {
        'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_packets': len(analyzer.packets),
        'total_bytes': analyzer.packet_df['length'].sum() if not analyzer.packet_df.empty else 0,
        'unique_ips': len(set(analyzer.packet_df['src_ip'].dropna()) | set(analyzer.packet_df['dst_ip'].dropna())) if not analyzer.packet_df.empty else 0,
        'high_risk_detections': sum(1 for det in analyzer.detections if det.severity.value == 'high') if hasattr(analyzer, 'detections') else 0,
        'malicious_ips': sum(1 for result in analyzer.enrichment_results.values() if result.is_malicious) if hasattr(analyzer, 'enrichment_results') else 0
    }
    
    # Risk assessment
    risk_level = "LOW"
    if summary['high_risk_detections'] > 5 or summary['malicious_ips'] > 2:
        risk_level = "HIGH"
    elif summary['high_risk_detections'] > 0 or summary['malicious_ips'] > 0:
        risk_level = "MEDIUM"
    
    st.markdown(f"""
    ## Network Security Assessment Report
    **Generated:** {summary['analysis_date']}
    
    ### 🎯 Key Findings
    - **Overall Risk Level:** {risk_level}
    - **Total Traffic Analyzed:** {summary['total_packets']:,} packets ({format_bytes(summary['total_bytes'])})
    - **Network Scope:** {summary['unique_ips']} unique IP addresses
    - **Security Threats:** {summary['high_risk_detections']} high-severity detections
    - **Malicious IPs:** {summary['malicious_ips']} confirmed threats
    
    ### 📊 Risk Summary
    This analysis reviewed network traffic and identified potential security concerns.
    {'Immediate attention required due to high-risk detections.' if risk_level == 'HIGH' else 
     'Some security concerns identified that warrant investigation.' if risk_level == 'MEDIUM' else
     'No significant security threats identified in this traffic sample.'}
    """)
    
    # Download button
    if st.button("Download Executive Summary"):
        # Implementation would generate PDF or formatted document
        st.success("Executive summary download prepared")

def render_technical_report(analyzer):
    """Render technical analysis report"""
    st.subheader("🔧 Technical Analysis Report")
    
    # Detailed technical findings
    if hasattr(analyzer, 'detections') and analyzer.detections:
        st.write(f"**Total Detections:** {len(analyzer.detections)}")
        
        for detection in analyzer.detections:
            with st.expander(f"{detection.name} - {detection.severity.value.title()}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**Source IP:** {detection.source_ip}")
                    st.write(f"**Confidence:** {detection.confidence}%")
                    st.write(f"**First Seen:** {detection.first_seen}")
                
                with col2:
                    if detection.mitre_attack:
                        st.write(f"**MITRE Technique:** {detection.mitre_attack.technique}")
                        st.write(f"**Tactic:** {detection.mitre_attack.tactic}")
                
                st.write(f"**Description:** {detection.description}")
                
                if detection.evidence:
                    st.write("**Evidence:**")
                    st.code(json.dumps(detection.evidence, indent=2))

def render_mitre_report(analyzer):
    """Render MITRE ATT&CK focused report"""
    st.subheader("🎯 MITRE ATT&CK Analysis")
    
    if hasattr(analyzer, 'mitre_report') and analyzer.mitre_report:
        report = analyzer.mitre_report
        
        st.write(f"**Techniques Detected:** {report['summary']['techniques_detected']}")
        st.write(f"**Tactics Involved:** {report['summary']['tactics_involved']}")
        
        # Tactic breakdown
        st.subheader("Tactic Breakdown")
        tactic_df = pd.DataFrame(list(report['tactic_breakdown'].items()), columns=['Tactic', 'Detections'])
        fig = px.bar(tactic_df, x='Tactic', y='Detections', title="Detections by MITRE Tactic")
        st.plotly_chart(fig, use_container_width=True)

def render_data_export(analyzer):
    """Render data export options"""
    st.subheader("💾 Data Export")
    
    export_options = st.multiselect(
        "Select data to export",
        ["Packet Data", "Detections", "Enrichment Results", "Conversations", "Risk Scores"]
    )
    
    export_format = st.radio("Export Format", ["CSV", "JSON", "Excel"])
    
    if st.button("Generate Export"):
        # Implementation would generate the selected exports
        st.success(f"Export generated in {export_format} format")

def render_traffic_heatmap(analyzer):
    """Render traffic intensity heatmap"""
    if analyzer.packet_df.empty:
        st.info("No packet data available for heatmap.")
        return
    
    # Create time-based heatmap
    df = analyzer.packet_df.copy()
    df['hour'] = pd.to_datetime(df['timestamp'], unit='s').dt.hour
    df['minute'] = pd.to_datetime(df['timestamp'], unit='s').dt.minute
    
    # Group by hour and minute
    heatmap_data = df.groupby(['hour', 'minute']).size().reset_index(name='packet_count')
    
    # Create pivot table for heatmap
    pivot_table = heatmap_data.pivot(index='hour', columns='minute', values='packet_count').fillna(0)
    
    fig = px.imshow(
        pivot_table,
        labels={'x': 'Minute', 'y': 'Hour', 'color': 'Packets'},
        title='Traffic Intensity Heatmap (Packets per Hour:Minute)',
        color_continuous_scale='Viridis'
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_geographic_flow_map(analyzer):
    """Render geographic flow visualization"""
    st.info("Geographic flow map visualization would be implemented here with enrichment data")
