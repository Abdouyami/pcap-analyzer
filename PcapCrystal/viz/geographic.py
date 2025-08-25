"""
Geographic visualization and analysis for threat intelligence
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, List, Optional
from collections import Counter, defaultdict

from models.enrichment import EnrichmentResult

def render_geographic_analysis(enrichment_results: Dict[str, EnrichmentResult]):
    """Render comprehensive geographic analysis of enriched IPs"""
    
    if not enrichment_results:
        st.info("No geographic data available. Enable geographic enrichment in settings.")
        return
    
    # Extract geographic data
    geo_data = []
    for ip, result in enrichment_results.items():
        if result.geo_location:
            geo = result.geo_location
            geo_data.append({
                'ip': ip,
                'country': geo.country or 'Unknown',
                'country_code': geo.country_code or 'XX',
                'region': geo.region or 'Unknown',
                'city': geo.city or 'Unknown',
                'latitude': geo.latitude,
                'longitude': geo.longitude,
                'asn': geo.asn,
                'org': geo.org or 'Unknown',
                'is_malicious': geo.is_malicious,
                'risk_score': geo.risk_score,
                'reputation': result.overall_reputation
            })
    
    if not geo_data:
        st.info("No geographic location data found in enrichment results.")
        return
    
    geo_df = pd.DataFrame(geo_data)
    
    # Geographic summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Unique Countries", geo_df['country'].nunique())
    
    with col2:
        malicious_countries = geo_df[geo_df['is_malicious']]['country'].nunique()
        st.metric("Countries with Threats", malicious_countries)
    
    with col3:
        high_risk_geos = len(geo_df[geo_df['risk_score'] >= 50])
        st.metric("High Risk Locations", high_risk_geos)
    
    with col4:
        unique_asns = geo_df['asn'].nunique()
        st.metric("Unique ASNs", unique_asns)
    
    # World map visualization
    st.subheader("🌍 Global Threat Distribution")
    
    if geo_df['latitude'].notna().any() and geo_df['longitude'].notna().any():
        # Create world map with threat indicators
        valid_coords = geo_df.dropna(subset=['latitude', 'longitude'])
        
        if not valid_coords.empty:
            fig = go.Figure()
            
            # Add markers for each location
            for threat_level, color in [('Malicious', 'red'), ('High Risk', 'orange'), ('Medium Risk', 'yellow'), ('Low Risk', 'green')]:
                if threat_level == 'Malicious':
                    df_subset = valid_coords[valid_coords['is_malicious'] == True]
                elif threat_level == 'High Risk':
                    df_subset = valid_coords[(valid_coords['is_malicious'] == False) & (valid_coords['risk_score'] >= 70)]
                elif threat_level == 'Medium Risk':
                    df_subset = valid_coords[(valid_coords['is_malicious'] == False) & (valid_coords['risk_score'] >= 40) & (valid_coords['risk_score'] < 70)]
                else:
                    df_subset = valid_coords[(valid_coords['is_malicious'] == False) & (valid_coords['risk_score'] < 40)]
                
                if not df_subset.empty:
                    fig.add_trace(go.Scattermapbox(
                        lat=df_subset['latitude'],
                        lon=df_subset['longitude'],
                        mode='markers',
                        marker=dict(
                            size=10,
                            color=color,
                            opacity=0.7
                        ),
                        name=threat_level,
                        text=[f"{row['ip']}<br>{row['city']}, {row['country']}<br>Risk: {row['risk_score']}/100" 
                              for _, row in df_subset.iterrows()],
                        hovertemplate='<b>%{text}</b><extra></extra>'
                    ))
            
            fig.update_layout(
                mapbox=dict(
                    style="open-street-map",
                    center=dict(lat=20, lon=0),
                    zoom=1
                ),
                showlegend=True,
                height=500,
                margin={"r": 0, "t": 0, "l": 0, "b": 0}
            )
            
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No valid coordinates found for mapping.")
    else:
        st.info("Geographic coordinates not available for mapping.")
    
    # Country-based analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Top Countries by IP Count")
        country_counts = geo_df['country'].value_counts().head(10)
        fig = px.bar(
            x=country_counts.index,
            y=country_counts.values,
            labels={'x': 'Country', 'y': 'IP Count'},
            title="IP Distribution by Country"
        )
        fig.update_xaxes(tickangle=45)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("⚠️ High Risk Countries")
        high_risk_by_country = geo_df[geo_df['risk_score'] >= 50]['country'].value_counts().head(10)
        if not high_risk_by_country.empty:
            fig = px.bar(
                x=high_risk_by_country.index,
                y=high_risk_by_country.values,
                labels={'x': 'Country', 'y': 'High Risk IPs'},
                title="High Risk IPs by Country",
                color=high_risk_by_country.values,
                color_continuous_scale='Reds'
            )
            fig.update_xaxes(tickangle=45)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No high-risk countries identified.")
    
    # ASN Analysis
    st.subheader("🏢 ASN Analysis")
    
    asn_analysis = geo_df.dropna(subset=['asn']).copy()
    if not asn_analysis.empty:
        # Top ASNs by IP count
        asn_counts = asn_analysis.groupby(['asn', 'org']).size().reset_index(name='ip_count')
        asn_counts = asn_counts.sort_values('ip_count', ascending=False).head(15)
        
        # Add risk statistics
        asn_risk = asn_analysis.groupby(['asn', 'org']).agg({
            'risk_score': 'mean',
            'is_malicious': 'sum'
        }).reset_index()
        
        asn_combined = asn_counts.merge(asn_risk, on=['asn', 'org'])
        asn_combined['display_name'] = asn_combined['asn'].astype(str) + ' - ' + asn_combined['org'].str[:30]
        
        col1, col2 = st.columns(2)
        
        with col1:
            fig = px.bar(
                asn_combined,
                x='ip_count',
                y='display_name',
                orientation='h',
                title="Top ASNs by IP Count",
                labels={'ip_count': 'Number of IPs', 'display_name': 'ASN - Organization'}
            )
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # ASN risk heatmap
            fig = px.scatter(
                asn_combined,
                x='ip_count',
                y='risk_score',
                size='is_malicious',
                hover_data=['asn', 'org'],
                title="ASN Risk vs IP Count",
                labels={'risk_score': 'Average Risk Score', 'ip_count': 'IP Count', 'is_malicious': 'Malicious IPs'}
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # Detailed geographic table
    st.subheader("📋 Geographic Details")
    
    # Add risk level categorization
    def categorize_risk(score):
        if score >= 70:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    display_df = geo_df.copy()
    display_df['Risk Level'] = display_df['risk_score'].apply(categorize_risk)
    display_df['Malicious'] = display_df['is_malicious'].map({True: '⚠️ Yes', False: '✅ No'})
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    
    with col1:
        country_filter = st.multiselect(
            "Filter by Country",
            options=display_df['country'].unique().tolist(),
            default=[]
        )
    
    with col2:
        risk_filter = st.multiselect(
            "Filter by Risk Level",
            options=['High', 'Medium', 'Low', 'Minimal'],
            default=[]
        )
    
    with col3:
        malicious_filter = st.selectbox(
            "Show Malicious Only",
            options=['All', 'Malicious Only', 'Clean Only'],
            index=0
        )
    
    # Apply filters
    filtered_df = display_df.copy()
    
    if country_filter:
        filtered_df = filtered_df[filtered_df['country'].isin(country_filter)]
    
    if risk_filter:
        filtered_df = filtered_df[filtered_df['Risk Level'].isin(risk_filter)]
    
    if malicious_filter == 'Malicious Only':
        filtered_df = filtered_df[filtered_df['is_malicious'] == True]
    elif malicious_filter == 'Clean Only':
        filtered_df = filtered_df[filtered_df['is_malicious'] == False]
    
    # Display table
    display_columns = ['ip', 'country', 'city', 'org', 'Risk Level', 'risk_score', 'reputation', 'Malicious']
    st.dataframe(
        filtered_df[display_columns].rename(columns={
            'ip': 'IP Address',
            'country': 'Country',
            'city': 'City',
            'org': 'Organization',
            'risk_score': 'Risk Score',
            'reputation': 'Reputation'
        }),
        use_container_width=True
    )
    
    # Export option
    if st.button("Export Geographic Data"):
        csv_data = display_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv_data,
            file_name=f"geographic_analysis_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

def render_threat_map_by_time(enrichment_results: Dict[str, EnrichmentResult], packet_df):
    """Render time-based threat evolution map"""
    st.subheader("⏰ Threat Evolution Over Time")
    
    # This would show how threats appeared over the capture timeline
    # Implementation would require timestamp correlation with enrichment data
    st.info("Time-based threat mapping feature - to be implemented with timeline correlation")

def render_connection_flows(geo_data: List[Dict], conversations: Dict):
    """Render geographic connection flow visualization"""
    st.subheader("🌐 Connection Flows")
    
    # This would show connection flows between geographic locations
    # Implementation would require conversation data with geographic enrichment
    st.info("Geographic connection flow visualization - to be implemented")

def get_country_threat_summary(geo_df: pd.DataFrame) -> Dict:
    """Generate country-level threat summary"""
    if geo_df.empty:
        return {}
    
    country_summary = {}
    
    for country in geo_df['country'].unique():
        country_data = geo_df[geo_df['country'] == country]
        
        country_summary[country] = {
            'total_ips': len(country_data),
            'malicious_ips': len(country_data[country_data['is_malicious'] == True]),
            'avg_risk_score': country_data['risk_score'].mean(),
            'max_risk_score': country_data['risk_score'].max(),
            'unique_asns': country_data['asn'].nunique(),
            'top_org': country_data['org'].mode().iloc[0] if not country_data['org'].mode().empty else 'Unknown'
        }
    
    return country_summary
