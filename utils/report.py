import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF
import io
import os
from datetime import datetime

def generate_pdf_report(df, threat_results, summary_stats, output_path='security_report.pdf'):
    """Generate a PDF security report."""
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Manufacturing Network Security Report", ln=1, align='C')
    pdf.ln(10)
    
    # Summary
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
    pdf.cell(200, 10, txt=f"Total Logs: {summary_stats['total_logs']}", ln=1)
    pdf.cell(200, 10, txt=f"Suspicious Events: {summary_stats['suspicious_events']}", ln=1)
    pdf.cell(200, 10, txt=f"Critical Threats: {summary_stats['critical_threats']}", ln=1)
    pdf.cell(200, 10, txt=f"Peak Traffic Time: {summary_stats['peak_traffic_time']}", ln=1)
    pdf.ln(5)
    
    # Threat log table (top 20)
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(40, 10, "Timestamp", 1)
    pdf.cell(40, 10, "Alert", 1)
    pdf.cell(30, 10, "Threat Score", 1)
    pdf.cell(40, 10, "Threat Level", 1)
    pdf.ln()
    pdf.set_font("Arial", size=8)
    for idx, row in threat_results.head(20).iterrows():
        ts = df.loc[idx, 'timestamp'].strftime('%H:%M:%S') if 'timestamp' in df else ''
        pdf.cell(40, 8, ts, 1)
        pdf.cell(40, 8, row['rule_alerts'][:30], 1)
        pdf.cell(30, 8, str(int(row['threat_score'])), 1)
        pdf.cell(40, 8, row['threat_level'], 1)
        pdf.ln()
    
    pdf.output(output_path)
    return output_path

def export_csv_threats(threat_results, output_path='threat_logs.csv'):
    """Export threat logs to CSV."""
    threat_results.to_csv(output_path, index=False)
    return output_path

def save_figure(fig, filename):
    """Save matplotlib figure to PNG."""
    fig.savefig(filename, dpi=150, bbox_inches='tight')
    plt.close(fig)
    return filename