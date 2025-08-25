"""
Enhanced graph visualizations for network analysis
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from datetime import datetime, timedelta
from typing import List, Dict, Any
import math

from models.detection import Detection

def render_enhanced_network_graph(analyzer):
    """Render enhanced network graph with threat intelligence overlay"""
    st.subheader("🕸️ Enhanced Network Graph")
    
    if analyzer.packet_df.empty:
        st.info("No network data available for graph visualization.")
        return
    
    # Graph configuration options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        layout_type = st.selectbox(
            "Graph Layout",
            ["spring", "circular", "kamada_kawai", "shell"],
            index=0
        )
    
    with col2:
        node_size_metric = st.selectbox(
            "Node Size Based On",
            ["packet_count", "byte_count", "risk_score", "connection_count"],
            index=0
        )
    
    with col3:
        max_nodes = st.slider("Max Nodes", 10, 100, 50)
    
    # Build network graph
    G = nx.Graph()
    
    # Aggregate connection data
    connections = {}
    ip_stats = {}
    
    # Process packet data to build graph
    for _, row in analyzer.packet_df.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        
        if pd.isna(src_ip) or pd.isna(dst_ip):
            continue
        
        # Update IP statistics
        for ip in [src_ip, dst_ip]:
            if ip not in ip_stats:
                ip_stats[ip] = {
                    'packet_count': 0,
                    'byte_count': 0,
                    'connection_count': 0,
                    'risk_score': 0,
                    'is_malicious': False,
                    'protocols': set()
                }
            
            ip_stats[ip]['packet_count'] += 1
            ip_stats[ip]['byte_count'] += row['length']
            ip_stats[ip]['protocols'].add(row['protocol'])
        
        # Update connection statistics
        edge_key = tuple(sorted([src_ip, dst_ip]))
        if edge_key not in connections:
            connections[edge_key] = {
                'packet_count': 0,
                'byte_count': 0,
                'protocols': set()
            }
        
        connections[edge_key]['packet_count'] += 1
        connections[edge_key]['byte_count'] += row['length']
        connections[edge_key]['protocols'].add(row['protocol'])
    
    # Update with threat intelligence if available
    if hasattr(analyzer, 'enrichment_results'):
        for ip, enrichment in analyzer.enrichment_results.items():
            if ip in ip_stats:
                ip_stats[ip]['risk_score'] = enrichment.overall_reputation
                ip_stats[ip]['is_malicious'] = enrichment.is_malicious
                ip_stats[ip]['country'] = enrichment.geo_location.country if enrichment.geo_location else 'Unknown'
    
    # Count connections for each IP
    for (src, dst), conn_data in connections.items():
        ip_stats[src]['connection_count'] += 1
        ip_stats[dst]['connection_count'] += 1
    
    # Sort IPs by the selected metric and limit nodes
    if node_size_metric == "risk_score":
        top_ips = sorted(ip_stats.items(), key=lambda x: x[1]['risk_score'], reverse=True)[:max_nodes]
    else:
        top_ips = sorted(ip_stats.items(), key=lambda x: x[1][node_size_metric], reverse=True)[:max_nodes]
    
    selected_ips = set(ip for ip, _ in top_ips)
    
    # Add nodes to graph
    for ip, stats in top_ips:
        G.add_node(ip, **stats)
    
    # Add edges for selected nodes
    for (src, dst), conn_data in connections.items():
        if src in selected_ips and dst in selected_ips:
            G.add_edge(src, dst, **conn_data)
    
    if len(G.nodes) == 0:
        st.warning("No nodes to display. Try adjusting the maximum nodes setting.")
        return
    
    # Calculate layout
    layout_functions = {
        'spring': nx.spring_layout,
        'circular': nx.circular_layout,
        'kamada_kawai': nx.kamada_kawai_layout,
        'shell': nx.shell_layout
    }
    
    try:
        pos = layout_functions[layout_type](G, k=3, iterations=50) if layout_type == 'spring' else layout_functions[layout_type](G)
    except:
        pos = nx.spring_layout(G)
    
    # Create plotly graph
    edge_x = []
    edge_y = []
    edge_info = []
    
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
        edge_data = G.edges[edge]
        edge_info.append(f"Connection: {edge[0]} ↔ {edge[1]}<br>" +
                        f"Packets: {edge_data.get('packet_count', 0):,}<br>" +
                        f"Bytes: {_format_bytes(edge_data.get('byte_count', 0))}<br>" +
                        f"Protocols: {', '.join(edge_data.get('protocols', []))}")
    
    # Create edge trace
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=0.5, color='#888'),
        hoverinfo='none',
        mode='lines'
    )
    
    # Create node trace
    node_x = []
    node_y = []
    node_text = []
    node_colors = []
    node_sizes = []
    node_symbols = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        node_data = G.nodes[node]
        
        # Determine node color based on threat level
        if node_data.get('is_malicious', False):
            node_colors.append('red')
            node_symbols.append('x')
        elif node_data.get('risk_score', 0) > 70:
            node_colors.append('orange')
            node_symbols.append('triangle-up')
        elif node_data.get('risk_score', 0) > 40:
            node_colors.append('yellow')
            node_symbols.append('diamond')
        else:
            node_colors.append('lightblue')
            node_symbols.append('circle')
        
        # Determine node size based on selected metric
        metric_value = node_data.get(node_size_metric, 0)
        if node_size_metric == 'risk_score':
            size = max(10, min(50, metric_value / 2))
        else:
            max_value = max(stats[node_size_metric] for _, stats in top_ips)
            size = max(10, min(50, 30 * metric_value / max_value)) if max_value > 0 else 10
        
        node_sizes.append(size)
        
        # Create hover text
        protocols = ', '.join(node_data.get('protocols', []))
        country = node_data.get('country', 'Unknown')
        
        hover_text = (f"IP: {node}<br>" +
                     f"Packets: {node_data.get('packet_count', 0):,}<br>" +
                     f"Bytes: {_format_bytes(node_data.get('byte_count', 0))}<br>" +
                     f"Connections: {node_data.get('connection_count', 0)}<br>" +
                     f"Risk Score: {node_data.get('risk_score', 0)}/100<br>" +
                     f"Country: {country}<br>" +
                     f"Protocols: {protocols}")
        
        node_text.append(hover_text)
    
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[ip.split('.')[-1] for ip in G.nodes()],  # Show last octet as label
        textposition="middle center",
        hovertext=node_text,
        marker=dict(
            size=node_sizes,
            color=node_colors,
            symbol=node_symbols,
            line=dict(width=2, color='black'),
            opacity=0.8
        )
    )
    
    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace],
                   layout=go.Layout(
                       title=dict(
                           text=f'Network Graph - {len(G.nodes())} nodes, {len(G.edges())} connections',
                           font=dict(size=16)
                       ),
                       showlegend=False,
                       hovermode='closest',
                       margin=dict(b=20,l=5,r=5,t=40),
                       annotations=[ dict(
                           text="Node size: " + node_size_metric.replace('_', ' ').title() + 
                                "<br>Color: Red=Malicious, Orange=High Risk, Yellow=Medium Risk, Blue=Low Risk",
                           showarrow=False,
                           xref="paper", yref="paper",
                           x=0.005, y=-0.002,
                           xanchor='left', yanchor='bottom',
                           font=dict(size=10)
                       )],
                       xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                       yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                       height=600
                   ))
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Network statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Nodes", len(G.nodes()))
    
    with col2:
        st.metric("Connections", len(G.edges()))
    
    with col3:
        avg_degree = sum(dict(G.degree()).values()) / len(G.nodes()) if len(G.nodes()) > 0 else 0
        st.metric("Avg Connections/Node", f"{avg_degree:.1f}")
    
    with col4:
        density = nx.density(G) if len(G.nodes()) > 1 else 0
        st.metric("Network Density", f"{density:.3f}")

def render_attack_timeline(detections: List[Detection]):
    """Render attack timeline visualization"""
    st.subheader("⏰ Attack Timeline")
    
    if not detections:
        st.info("No detections available for timeline visualization.")
        return
    
    # Convert detections to timeline data
    timeline_data = []
    
    for detection in detections:
        timeline_data.append({
            'name': detection.name,
            'start': detection.first_seen,
            'end': detection.last_seen or detection.first_seen,
            'severity': detection.severity.value,
            'confidence': detection.confidence,
            'source_ip': detection.source_ip or 'Unknown',
            'destination_ip': detection.destination_ip or 'Unknown',
            'mitre_technique': detection.mitre_attack.technique if detection.mitre_attack else 'N/A',
            'mitre_tactic': detection.mitre_attack.tactic if detection.mitre_attack else 'N/A',
            'risk_score': detection.risk_score
        })
    
    if not timeline_data:
        st.info("No timeline data available.")
        return
    
    df = pd.DataFrame(timeline_data)
    
    # Sort by start time
    df = df.sort_values('start')
    
    # Create Gantt-style timeline
    fig = go.Figure()
    
    # Color mapping for severity
    severity_colors = {
        'low': '#28a745',
        'medium': '#ffc107',
        'high': '#fd7e14', 
        'critical': '#dc3545'
    }
    
    # Create timeline bars
    for i, row in df.iterrows():
        start_time = row['start']
        end_time = row['end']
        
        # If end time is same as start time, make it a small duration for visibility
        if start_time == end_time:
            end_time = start_time + timedelta(minutes=1)
        
        duration = (end_time - start_time).total_seconds()
        
        fig.add_trace(go.Scatter(
            x=[start_time, end_time],
            y=[i, i],
            mode='lines+markers',
            line=dict(
                color=severity_colors.get(row['severity'], '#gray'),
                width=8
            ),
            marker=dict(
                size=10,
                symbol=['circle', 'square']
            ),
            name=row['name'],
            hovertemplate=(
                f"<b>{row['name']}</b><br>" +
                f"Severity: {row['severity'].title()}<br>" +
                f"Confidence: {row['confidence']}%<br>" +
                f"Source: {row['source_ip']}<br>" +
                f"Destination: {row['destination_ip']}<br>" +
                f"MITRE: {row['mitre_technique']}<br>" +
                f"Start: {start_time}<br>" +
                f"Duration: {duration:.0f}s<br>" +
                f"Risk Score: {row['risk_score']}/100" +
                "<extra></extra>"
            ),
            showlegend=False
        ))
    
    # Update layout
    fig.update_layout(
        title="Security Detection Timeline",
        xaxis_title="Time",
        yaxis_title="Detection Events",
        yaxis=dict(
            tickmode='array',
            tickvals=list(range(len(df))),
            ticktext=[f"{row['name'][:30]}..." if len(row['name']) > 30 else row['name'] 
                     for _, row in df.iterrows()],
            autorange='reversed'
        ),
        height=max(400, len(df) * 30),
        hovermode='closest'
    )
    
    st.plotly_chart(fig, use_container_width=True)
    
    # Timeline statistics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Events", len(df))
    
    with col2:
        duration = (df['start'].max() - df['start'].min()).total_seconds() / 3600
        st.metric("Timeline Duration", f"{duration:.1f}h")
    
    with col3:
        high_severity = len(df[df['severity'].isin(['high', 'critical'])])
        st.metric("High Severity Events", high_severity)
    
    with col4:
        avg_confidence = df['confidence'].mean()
        st.metric("Avg Confidence", f"{avg_confidence:.0f}%")
    
    # MITRE technique timeline
    if df['mitre_technique'].notna().any():
        st.subheader("🎯 MITRE ATT&CK Technique Timeline")
        
        # Group by MITRE technique
        mitre_timeline = df[df['mitre_technique'] != 'N/A'].copy()
        
        if not mitre_timeline.empty:
            fig_mitre = px.scatter(
                mitre_timeline,
                x='start',
                y='mitre_technique',
                color='severity',
                size='confidence',
                hover_data=['name', 'source_ip', 'mitre_tactic'],
                color_discrete_map=severity_colors,
                title="MITRE ATT&CK Techniques Over Time"
            )
            
            fig_mitre.update_layout(
                height=400,
                yaxis_title="MITRE Technique"
            )
            
            st.plotly_chart(fig_mitre, use_container_width=True)

def render_traffic_flow_sankey(analyzer):
    """Render traffic flow Sankey diagram"""
    st.subheader("🌊 Traffic Flow Analysis")
    
    if not analyzer.conversations:
        st.info("No conversation data available for flow analysis.")
        return
    
    # Prepare data for Sankey diagram
    sources = []
    targets = []
    values = []
    labels = set()
    
    # Get top conversations by bytes
    sorted_convs = sorted(
        analyzer.conversations.items(),
        key=lambda x: x[1].get('bytes', 0),
        reverse=True
    )[:20]  # Top 20 conversations
    
    for (src_ip, dst_ip), stats in sorted_convs:
        labels.add(src_ip)
        labels.add(dst_ip)
    
    # Create label mapping
    label_list = list(labels)
    label_map = {label: i for i, label in enumerate(label_list)}
    
    for (src_ip, dst_ip), stats in sorted_convs:
        sources.append(label_map[src_ip])
        targets.append(label_map[dst_ip])
        values.append(stats.get('bytes', 0))
    
    # Create Sankey diagram
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=label_list,
            color="lightblue"
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values
        )
    )])
    
    fig.update_layout(title_text="Network Traffic Flow (Top 20 Conversations)", font_size=10)
    st.plotly_chart(fig, use_container_width=True)

def _format_bytes(bytes_value):
    """Format bytes value for display"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} TB"

def render_risk_distribution_heatmap(risk_scores):
    """Render risk distribution heatmap"""
    st.subheader("🔥 Risk Distribution Heatmap")
    
    if not risk_scores:
        st.info("No risk scores available for heatmap.")
        return
    
    # Create risk matrix based on entity types and risk levels
    risk_data = []
    
    for risk_score in risk_scores:
        risk_data.append({
            'entity_type': risk_score.entity_type,
            'risk_level': risk_score.get_risk_level(),
            'risk_score': risk_score.overall_score,
            'entity': risk_score.entity
        })
    
    if not risk_data:
        return
    
    df = pd.DataFrame(risk_data)
    
    # Create heatmap matrix
    heatmap_matrix = df.groupby(['entity_type', 'risk_level']).size().unstack(fill_value=0)
    
    fig = px.imshow(
        heatmap_matrix.values,
        labels=dict(x="Risk Level", y="Entity Type", color="Count"),
        x=heatmap_matrix.columns,
        y=heatmap_matrix.index,
        color_continuous_scale="Reds",
        title="Risk Distribution by Entity Type and Risk Level"
    )
    
    st.plotly_chart(fig, use_container_width=True)

