"""
AI-Driven Cyber Security Threat Intelligence Dashboard
Main Streamlit Application
"""

import streamlit as st
from datetime import datetime
import json

# Import services
from services.classifier_service import classify_threat
from services.ioc_extractor import extract_iocs
from services.report_service import generate_threat_report
from services.feed_service import get_live_threats
from services.vector_service import generate_embeddings
from utils.formatter import format_classification_result, format_ioc_result
from utils.logger import log_activity

# Page configuration
st.set_page_config(
    page_title="AI Threat Intel Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        padding: 1rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .threat-high {
        color: #d32f2f;
        font-weight: bold;
    }
    .threat-medium {
        color: #ff9800;
        font-weight: bold;
    }
    .threat-low {
        color: #4caf50;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/security-shield-green.png", width=80)
    st.title("🛡️ Threat Intel")
    st.markdown("---")
    st.info("**Powered by Groq LLMs**\n\nllama-3.3-70b-versatile")
    st.markdown("---")
    
    # Statistics
    st.subheader("📊 System Stats")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Active Threats", "47")
        st.metric("IOCs Tracked", "1,234")
    with col2:
        st.metric("Reports", "89")
        st.metric("Vectors", "3,456")

# Main header
st.markdown('<div class="main-header">🛡️ AI Threat Intelligence Dashboard</div>', unsafe_allow_html=True)
st.markdown("**Real-time threat analysis powered by Groq LLMs**")
st.markdown("---")

# Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🔴 Live Feed",
    "🔍 Threat Classification",
    "🎯 IOC Extractor",
    "📄 Threat Report",
    "🧬 Embedding Generator"
])

# ============================================
# TAB 1: LIVE THREAT FEED
# ============================================
with tab1:
    st.header("🔴 Live Threat Feed")
    st.markdown("**Real-time monitoring of emerging cyber threats**")
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        if st.button("🔄 Refresh Feed", use_container_width=True):
            st.rerun()
    
    try:
        threats = get_live_threats()
        
        for threat in threats:
            severity_class = f"threat-{str(threat['severity'])}"

            
            with st.container():
                col1, col2, col3 = st.columns([2, 3, 1])
                
                with col1:
                    st.markdown(f"**{threat['timestamp']}**")
                    st.markdown(f"<span class='{severity_class}'>{threat['severity']} SEVERITY</span>", 
                              unsafe_allow_html=True)
                
                with col2:
                    st.markdown(f"**{threat['title']}**")
                    st.caption(threat['description'])
                
                with col3:
                    st.markdown(f"**Source:** {threat['source']}")
                
                st.markdown("---")
    
    except Exception as e:
        st.error(f"Error loading threat feed: {str(e)}")
        log_activity("error", f"Feed loading error: {str(e)}")

# ============================================
# TAB 2: THREAT CLASSIFICATION
# ============================================
with tab2:
    st.header("🔍 Threat Classification")
    st.markdown("**Classify security threats using AI-powered analysis**")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        threat_text = st.text_area(
            "Enter threat description or security alert:",
            height=200,
            placeholder="Paste suspicious activity, security logs, or threat descriptions here..."
        )
    
    with col2:
        st.info("**Classification Categories:**\n\n"
                "• Malware\n"
                "• Phishing\n"
                "• Ransomware\n"
                "• DDoS\n"
                "• Data Breach\n"
                "• Insider Threat\n"
                "• APT\n"
                "• Other")
    
    if st.button("🔍 Classify Threat", type="primary", use_container_width=True):
        if threat_text.strip():
            with st.spinner("Analyzing threat with Groq AI..."):
                try:
                    result = classify_threat(threat_text)
                    
                    st.success("✅ Classification Complete!")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Threat Type", result['threat_type'])
                    
                    with col2:
                        severity_color = {
                            "CRITICAL": "🔴",
                            "HIGH": "🟠",
                            "MEDIUM": "🟡",
                            "LOW": "🟢"
                        }.get(result['severity'], "⚪")
                        st.metric("Severity", f"{severity_color} {result['severity']}")
                    
                    with col3:
                        st.metric("Confidence", f"{result['confidence']:.1%}")
                    
                    st.markdown("---")
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("📋 Analysis Summary")
                        st.write(result['summary'])
                    
                    with col2:
                        st.subheader("🎯 Key Indicators")
                        for indicator in result['indicators']:
                            st.markdown(f"• {indicator}")
                    
                    st.markdown("---")
                    st.subheader("💡 Prevention Steps")
                    for i, rec in enumerate(result['recommendations'], 1):
                        st.markdown(f"{i}. {rec}")
                    
                    # Log activity
                    log_activity("classification", f"Classified as {result['threat_type']}")
                    
                except Exception as e:
                    st.error(f"❌ Classification failed: {str(e)}")
                    log_activity("error", f"Classification error: {str(e)}")
        else:
            st.warning("⚠️ Please enter threat description to classify.")

# ============================================
# TAB 3: IOC EXTRACTOR
# ============================================
with tab3:
    st.header("🎯 Indicators of Compromise (IOC) Extractor")
    st.markdown("**Extract and validate IOCs using hybrid Regex + AI approach**")
    
    ioc_text = st.text_area(
        "Paste threat intelligence, logs, or security reports:",
        height=250,
        placeholder="Example:\nSuspicious activity from 192.168.1.100\nMalicious URL: http://evil-site.com/malware.exe\nFile hash: 5d41402abc4b2a76b9719d911017c592"
    )
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        extract_method = st.radio(
            "Extraction Method:",
            ["Hybrid (Regex + AI)", "Regex Only", "AI Only"],
            index=0
        )
    
    if st.button("🎯 Extract IOCs", type="primary", use_container_width=True):
        if ioc_text.strip():
            with st.spinner("Extracting IOCs..."):
                try:
                    result = extract_iocs(ioc_text, method=extract_method.lower().replace(" ", "_"))
                    
                    st.success("✅ IOC Extraction Complete!")
                    
                    # Summary metrics
                    col1, col2, col3, col4, col5 = st.columns(5)
                    
                    with col1:
                        st.metric("IPs", len(result['ips']))
                    with col2:
                        st.metric("URLs", len(result['urls']))
                    with col3:
                        st.metric("Hashes", len(result['hashes']))
                    with col4:
                        st.metric("Emails", len(result['emails']))
                    with col5:
                        st.metric("Files", len(result['filenames']))
                    
                    st.markdown("---")
                    
                    # Display IOCs
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if result['ips']:
                            st.subheader("🌐 IP Addresses")
                            for ip in result['ips']:
                                st.code(ip)
                        
                        if result['urls']:
                            st.subheader("🔗 URLs")
                            for url in result['urls']:
                                st.code(url)
                        
                        if result['emails']:
                            st.subheader("📧 Email Addresses")
                            for email in result['emails']:
                                st.code(email)
                    
                    with col2:
                        if result['hashes']:
                            st.subheader("🔐 File Hashes")
                            for hash_val in result['hashes']:
                                st.code(hash_val)
                        
                        if result['filenames']:
                            st.subheader("📁 Suspicious Files")
                            for filename in result['filenames']:
                                st.code(filename)
                    
                    # Export options
                    st.markdown("---")
                    st.subheader("📥 Export IOCs")
                    
                    export_format = st.selectbox("Format:", ["JSON", "CSV", "Text"])
                    
                    if export_format == "JSON":
                        st.download_button(
                            "⬇️ Download JSON",
                            data=json.dumps(result, indent=2),
                            file_name=f"iocs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                            mime="application/json"
                        )
                    
                    log_activity("ioc_extraction", f"Extracted {sum(len(v) for v in result.values())} IOCs")
                    
                except Exception as e:
                    st.error(f"❌ IOC extraction failed: {str(e)}")
                    log_activity("error", f"IOC extraction error: {str(e)}")
        else:
            st.warning("⚠️ Please enter text to extract IOCs from.")

# ============================================
# TAB 4: THREAT REPORT GENERATOR
# ============================================
with tab4:
    st.header("📄 Comprehensive Threat Report Generator")
    st.markdown("**Generate detailed threat intelligence reports using AI**")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        report_input = st.text_area(
            "Enter threat data or incident details:",
            height=200,
            placeholder="Describe the security incident, attack patterns, or threat intelligence..."
        )
        
        report_title = st.text_input("Report Title:", "Security Threat Analysis Report")
    
    with col2:
        report_type = st.selectbox(
            "Report Type:",
            ["Executive Summary", "Technical Analysis", "Incident Response", "Full Report"]
        )
        
        include_iocs = st.checkbox("Include IOC Analysis", value=True)
        include_recommendations = st.checkbox("Include Recommendations", value=True)
    
    if st.button("📄 Generate Report", type="primary", use_container_width=True):
        if report_input.strip():
            with st.spinner("Generating comprehensive threat report..."):
                try:
                    report = generate_threat_report(
                        report_input,
                        report_type=report_type,
                        include_iocs=include_iocs,
                        include_recommendations=include_recommendations
                    )
                    
                    st.success("✅ Report Generated Successfully!")
                    
                    # Report header
                    st.markdown("---")
                    st.markdown(f"# {report_title}")
                    st.markdown(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    st.markdown(f"**Report Type:** {report_type}")
                    st.markdown("---")
                    
                    # Executive Summary
                    st.subheader("📊 Executive Summary")
                    st.write(report['executive_summary'])
                    
                    # Threat Details
                    st.markdown("---")
                    st.subheader("🔍 Threat Analysis")
                    st.write(report['threat_analysis'])
                    
                    # Impact Assessment
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("### 💥 Impact Assessment")
                        st.write(report['impact_assessment'])
                    
                    with col2:
                        st.markdown("### 📈 Risk Level")
                        risk_color = {
                            "CRITICAL": "🔴",
                            "HIGH": "🟠",
                            "MEDIUM": "🟡",
                            "LOW": "🟢"
                        }.get(report['risk_level'], "⚪")
                        st.markdown(f"## {risk_color} {report['risk_level']}")
                    
                    # Recommendations
                    if include_recommendations and 'recommendations' in report:
                        st.markdown("---")
                        st.subheader("💡 Recommended Actions")
                        for i, rec in enumerate(report['recommendations'], 1):
                            st.markdown(f"{i}. {rec}")
                    
                    # Download report
                    st.markdown("---")
                    st.download_button(
                        "⬇️ Download Report (JSON)",
                        data=json.dumps(report, indent=2),
                        file_name=f"threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                    
                    log_activity("report_generation", f"Generated {report_type} report")
                    
                except Exception as e:
                    st.error(f"❌ Report generation failed: {str(e)}")
                    log_activity("error", f"Report generation error: {str(e)}")
        else:
            st.warning("⚠️ Please enter threat data to generate a report.")

# ============================================
# TAB 5: EMBEDDING GENERATOR
# ============================================
with tab5:
    st.header("🧬 Threat Intelligence Embedding Generator")
    st.markdown("**Generate vector embeddings for threat data using Groq's llama3-8b-embed model**")
    
    embedding_text = st.text_area(
        "Enter threat intelligence text:",
        height=200,
        placeholder="Enter security logs, threat descriptions, or IOCs for embedding generation..."
    )
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        embedding_purpose = st.selectbox(
            "Purpose:",
            ["Similarity Search", "Clustering", "Classification", "General"]
        )
    
    with col2:
        st.info("**Use Cases:**\n\n"
                "• Find similar threats\n"
                "• Cluster related incidents\n"
                "• Build threat databases\n"
                "• Semantic search")
    
    if st.button("🧬 Generate Embeddings", type="primary", use_container_width=True):
        if embedding_text.strip():
            with st.spinner("Generating embeddings with Groq..."):
                try:
                    result = generate_embeddings(embedding_text)
                    
                    st.success("✅ Embeddings Generated!")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.metric("Vector Dimensions", result['dimensions'])
                    with col2:
                        st.metric("Model", result['model'])
                    with col3:
                        st.metric("Token Count", result['token_count'])
                    
                    st.markdown("---")
                    
                    # Display embedding preview
                    st.subheader("📊 Embedding Preview")
                    st.caption(f"First 10 dimensions of {result['dimensions']}-dimensional vector:")
                    
                    embedding_preview = result['embedding'][:10]
                    st.code(f"[{', '.join(f'{x:.6f}' for x in embedding_preview)}...]")
                    
                    # Visualization
                    st.markdown("---")
                    st.subheader("📈 Vector Statistics")
                    
                    import numpy as np
                    embedding_array = np.array(result['embedding'])
                    
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Mean", f"{embedding_array.mean():.6f}")
                    with col2:
                        st.metric("Std Dev", f"{embedding_array.std():.6f}")
                    with col3:
                        st.metric("Min", f"{embedding_array.min():.6f}")
                    with col4:
                        st.metric("Max", f"{embedding_array.max():.6f}")
                    
                    # Download options
                    st.markdown("---")
                    st.download_button(
                        "⬇️ Download Embedding (JSON)",
                        data=json.dumps(result, indent=2),
                        file_name=f"embedding_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json"
                    )
                    
                    log_activity("embedding_generation", f"Generated {result['dimensions']}-dim embedding")
                    
                except Exception as e:
                    st.error(f"❌ Embedding generation failed: {str(e)}")
                    log_activity("error", f"Embedding generation error: {str(e)}")
        else:
            st.warning("⚠️ Please enter text to generate embeddings.")

# Footer
st.markdown("---")
st.markdown(
    "<div style='text-align: center; color: #666;'>"
    "🛡️ AI Threat Intelligence Dashboard | Powered by Groq LLMs | "
    f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    "</div>",
    unsafe_allow_html=True
)