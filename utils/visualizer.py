import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from matplotlib import dates as mdates
import io
import base64

def set_style():
    plt.style.use('seaborn-v0_8-darkgrid')
    sns.set_palette("coolwarm")
    plt.rcParams['figure.facecolor'] = '#1e1e2f'
    plt.rcParams['axes.facecolor'] = '#1e1e2f'
    plt.rcParams['text.color'] = 'white'
    plt.rcParams['axes.labelcolor'] = 'white'
    plt.rcParams['xtick.color'] = 'white'
    plt.rcParams['ytick.color'] = 'white'

def plot_traffic_over_time(df, title="Network Traffic Over Time"):
    set_style()
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(df['timestamp'], df['bytes_sent'], label='Bytes Sent', linewidth=1, alpha=0.7)
    ax.plot(df['timestamp'], df['bytes_received'], label='Bytes Received', linewidth=1, alpha=0.7)
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Bytes')
    ax.set_title(title)
    ax.legend()
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M'))
    plt.xticks(rotation=45)
    plt.tight_layout()
    return fig

def plot_spike_detection(df, spike_threshold):
    set_style()
    fig, ax = plt.subplots(figsize=(12, 5))
    ax.plot(df['timestamp'], df['bytes_sent'], label='Bytes Sent', color='blue', alpha=0.6)
    spikes = df[df['bytes_sent'] > spike_threshold]
    ax.scatter(spikes['timestamp'], spikes['bytes_sent'], color='red', label='Spike Detected', s=50, zorder=5)
    ax.axhline(y=spike_threshold, color='orange', linestyle='--', label=f'Threshold ({spike_threshold:.0f} bytes)')
    ax.set_xlabel('Timestamp')
    ax.set_ylabel('Bytes Sent')
    ax.set_title('Spike Detection Chart')
    ax.legend()
    plt.xticks(rotation=45)
    plt.tight_layout()
    return fig

def plot_heatmap(df):
    set_style()
    # Pivot table: hour vs day_of_week for total bytes
    heat_data = df.pivot_table(index='hour', columns='day_of_week', values='total_bytes', aggfunc='mean').fillna(0)
    fig, ax = plt.subplots(figsize=(10, 6))
    sns.heatmap(heat_data, annot=False, cmap='Reds', fmt='.0f', ax=ax, cbar_kws={'label': 'Avg Total Bytes'})
    ax.set_title('Heatmap of Suspicious Hours (Hour vs Day of Week)')
    ax.set_xlabel('Day of Week (0=Monday, 6=Sunday)')
    ax.set_ylabel('Hour of Day')
    plt.tight_layout()
    return fig

def plot_bytes_sent_vs_received(df):
    set_style()
    fig, ax = plt.subplots(figsize=(8, 6))
    ax.scatter(df['bytes_sent'], df['bytes_received'], alpha=0.5, c=df['connections'], cmap='viridis')
    ax.set_xlabel('Bytes Sent')
    ax.set_ylabel('Bytes Received')
    ax.set_title('Bytes Sent vs Received (colored by Connections)')
    plt.colorbar(ax.collections[0], ax=ax, label='Connections')
    plt.tight_layout()
    return fig

def plot_daily_attack_trend(df):
    set_style()
    # Count suspicious events per day
    df['date'] = df['timestamp'].dt.date
    daily_attacks = df[df['status'] == 'Suspicious'].groupby('date').size()
    fig, ax = plt.subplots(figsize=(12, 5))
    daily_attacks.plot(kind='bar', ax=ax, color='crimson')
    ax.set_title('Daily Attack Trend')
    ax.set_xlabel('Date')
    ax.set_ylabel('Number of Suspicious Events')
    plt.xticks(rotation=45)
    plt.tight_layout()
    return fig

def plot_protocol_distribution(df):
    set_style()
    fig, ax = plt.subplots(figsize=(7, 7))
    protocol_counts = df['protocol'].value_counts()
    ax.pie(protocol_counts, labels=protocol_counts.index, autopct='%1.1f%%', startangle=90)
    ax.set_title('Protocol Distribution')
    plt.tight_layout()
    return fig

def plot_anomaly_clusters(df, threat_results):
    set_style()
    fig, ax = plt.subplots(figsize=(10, 6))
    # Use threat score as color
    scatter = ax.scatter(df['bytes_sent'], df['connections'], c=threat_results['threat_score'], cmap='RdYlGn_r', alpha=0.6)
    ax.set_xlabel('Bytes Sent')
    ax.set_ylabel('Connections')
    ax.set_title('Anomaly Clusters (Threat Score Heat)')
    plt.colorbar(scatter, ax=ax, label='Threat Score')
    plt.tight_layout()
    return fig