import pandas as pd
import numpy as np
from datetime import datetime

def load_and_clean_dataset(file_path):
    """
    Load CSV, auto-clean missing values, auto-detect columns,
    and prepare features for ML models.
    """
    df = pd.read_csv(file_path)
    
    # Standardize column names (lowercase, strip spaces)
    df.columns = df.columns.str.lower().str.strip()
    
    # Required columns: timestamp, device_ip, protocol, bytes_sent, bytes_received, connections, status
    expected_cols = ['timestamp', 'device_ip', 'protocol', 'bytes_sent', 'bytes_received', 'connections', 'status']
    for col in expected_cols:
        if col not in df.columns:
            raise ValueError(f"Missing required column: {col}. Found: {df.columns.tolist()}")
    
    # Convert timestamp to datetime
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    
    # Drop rows with invalid timestamp
    df = df.dropna(subset=['timestamp'])
    
    # Fill missing numeric values with median
    numeric_cols = ['bytes_sent', 'bytes_received', 'connections']
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        df[col].fillna(df[col].median(), inplace=True)
    
    # Fill missing status with 'Normal'
    df['status'].fillna('Normal', inplace=True)
    
    # Feature engineering: extract hour, day of week
    df['hour'] = df['timestamp'].dt.hour
    df['day_of_week'] = df['timestamp'].dt.dayofweek
    
    # Total bytes
    df['total_bytes'] = df['bytes_sent'] + df['bytes_received']
    
    # Protocol encoding for ML
    protocol_map = {'TCP': 0, 'UDP': 1, 'ICMP': 2, 'HTTP': 3, 'HTTPS': 4}
    df['protocol_encoded'] = df['protocol'].map(protocol_map).fillna(0).astype(int)
    
    # Drop rows with extreme outliers (optional)
    for col in numeric_cols:
        q99 = df[col].quantile(0.99)
        df[col] = df[col].clip(upper=q99)
    
    return df

def get_feature_columns(df):
    """Return feature columns for ML models."""
    return ['bytes_sent', 'bytes_received', 'connections', 'total_bytes', 'hour', 'protocol_encoded']

def generate_sample_dataset(n_rows=1200, output_path='data/sample_network_logs.csv'):
    """Generate realistic network traffic dataset with anomalies."""
    np.random.seed(42)
    timestamps = pd.date_range(start='2025-01-01 00:00:00', periods=n_rows, freq='min')
    devices = [f'192.168.1.{i}' for i in range(2, 50)]
    protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    
    data = []
    for i, ts in enumerate(timestamps):
        device = np.random.choice(devices)
        protocol = np.random.choice(protocols, p=[0.5, 0.2, 0.05, 0.15, 0.1])
        
        # Normal traffic patterns
        bytes_sent = np.random.exponential(500)
        bytes_received = np.random.exponential(300)
        connections = np.random.poisson(5)
        
        # Inject anomalies (10% of data)
        if i % 10 == 0:  # every 10th record could be anomalous
            attack_type = np.random.choice(['DDoS', 'DataExfil', 'Spike', 'Burst'], p=[0.4, 0.3, 0.2, 0.1])
            if attack_type == 'DDoS':
                bytes_sent = np.random.uniform(9000, 50000)
                connections = np.random.poisson(150)
                status = 'Suspicious'
            elif attack_type == 'DataExfil':
                bytes_sent = np.random.uniform(10000, 80000)
                bytes_received = np.random.uniform(100, 500)
                connections = np.random.poisson(10)
                status = 'Suspicious'
            elif attack_type == 'Spike':
                bytes_sent = np.random.uniform(5000, 20000)
                connections = np.random.poisson(30)
                status = 'Suspicious'
            else:  # Burst
                connections = np.random.poisson(120)
                bytes_sent = np.random.uniform(3000, 8000)
                status = 'Suspicious'
        else:
            status = 'Normal'
        
        data.append([ts, device, protocol, int(bytes_sent), int(bytes_received), connections, status])
    
    df = pd.DataFrame(data, columns=['timestamp', 'device_ip', 'protocol', 'bytes_sent', 'bytes_received', 'connections', 'status'])
    df.to_csv(output_path, index=False)
    return df