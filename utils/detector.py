import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import joblib
import os

class ThreatDetector:
    def __init__(self, model_dir='models/'):
        self.model_dir = model_dir
        os.makedirs(model_dir, exist_ok=True)
        self.isolation_forest = None
        self.kmeans = None
        self.lof = None
        self.random_forest = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        
    def train_models(self, df, feature_cols):
        """Train all four ML models on the dataset."""
        self.feature_columns = feature_cols
        X = df[feature_cols].values
        X_scaled = self.scaler.fit_transform(X)
        
        # Isolation Forest
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.isolation_forest.fit(X_scaled)
        
        # KMeans (for clustering)
        n_clusters = min(5, len(df)//10)
        self.kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        self.kmeans.fit(X_scaled)
        
        # Local Outlier Factor (novelty=True for prediction)
        self.lof = LocalOutlierFactor(contamination=0.1, novelty=True)
        self.lof.fit(X_scaled)
        
        # Random Forest: train on rule-based labels (simulate supervised learning)
        # Create synthetic labels based on rule violations and anomaly scores
        rule_labels = self._generate_rule_labels(df)
        if len(np.unique(rule_labels)) > 1:
            self.random_forest = RandomForestClassifier(n_estimators=100, random_state=42)
            self.random_forest.fit(X_scaled, rule_labels)
        else:
            # Fallback
            self.random_forest = None
            
        # Save models
        joblib.dump(self.isolation_forest, os.path.join(self.model_dir, 'isolation_forest.pkl'))
        joblib.dump(self.kmeans, os.path.join(self.model_dir, 'kmeans.pkl'))
        joblib.dump(self.lof, os.path.join(self.model_dir, 'lof.pkl'))
        joblib.dump(self.scaler, os.path.join(self.model_dir, 'scaler.pkl'))
        if self.random_forest:
            joblib.dump(self.random_forest, os.path.join(self.model_dir, 'random_forest.pkl'))
    
    def _generate_rule_labels(self, df):
        """Generate pseudo-labels based on rule-based heuristics for RF training."""
        labels = np.zeros(len(df))
        # Rule: high bytes_sent (>8000) or high connections (>100)
        high_traffic = (df['bytes_sent'] > 8000) | (df['connections'] > 100)
        labels[high_traffic] = 1
        # Also flag data exfiltration like patterns
        exfil = (df['bytes_sent'] > 5000) & (df['bytes_received'] < 500)
        labels[exfil] = 1
        return labels.astype(int)
    
    def detect_threats(self, df):
        """Apply all models to detect anomalies and threats."""
        X = df[self.feature_columns].values
        X_scaled = self.scaler.transform(X)
        
        # Model predictions
        iforest_pred = self.isolation_forest.predict(X_scaled)  # -1 anomaly, 1 normal
        lof_pred = self.lof.predict(X_scaled)
        kmeans_distances = np.min(self.kmeans.transform(X_scaled), axis=1)
        kmeans_anomaly = (kmeans_distances > np.percentile(kmeans_distances, 90)).astype(int)
        
        rf_pred = np.zeros(len(df))
        if self.random_forest:
            rf_pred = self.random_forest.predict(X_scaled)
        
        # Combine: anomaly if any model flags
        anomaly_flag = (iforest_pred == -1) | (lof_pred == -1) | (kmeans_anomaly == 1) | (rf_pred == 1)
        
        # Rule-based detection
        rules = self.apply_rule_engine(df)
        
        # Final threat score (0-100)
        threat_score = self.compute_threat_score(df, anomaly_flag, rules)
        
        # Threat levels
        threat_level = []
        for score in threat_score:
            if score >= 75:
                threat_level.append('Critical 🚨')
            elif score >= 50:
                threat_level.append('High 🔴')
            elif score >= 25:
                threat_level.append('Medium 🟡')
            else:
                threat_level.append('Low 🟢')
        
        results = pd.DataFrame({
            'anomaly_ml': anomaly_flag,
            'iforest_anomaly': (iforest_pred == -1),
            'lof_anomaly': (lof_pred == -1),
            'kmeans_anomaly': (kmeans_anomaly == 1),
            'rf_anomaly': (rf_pred == 1),
            'rule_alerts': rules['alert'],
            'threat_score': threat_score,
            'threat_level': threat_level
        })
        return results
    
    def apply_rule_engine(self, df):
        """Rule-based security engine."""
        alerts = []
        for idx, row in df.iterrows():
            alert = "Normal"
            # DDoS detection
            if row['bytes_sent'] > 10000 and row['connections'] > 100:
                alert = "Possible DDoS Attack"
            elif row['bytes_sent'] > 8000:
                alert = "Suspicious Traffic Spike"
            elif row['connections'] > 100:
                alert = "Repeated Connection Burst (Brute Force)"
            elif row['bytes_sent'] > 5000 and row['bytes_received'] < 500:
                alert = "Data Exfiltration Detected"
            elif row['total_bytes'] > 15000:
                alert = "Unusual Bandwidth Usage"
            alerts.append(alert)
        return pd.DataFrame({'alert': alerts})
    
    def compute_threat_score(self, df, anomaly_flag, rules_df):
        """Compute threat score based on volume, frequency, pattern, time."""
        scores = np.zeros(len(df))
        # Volume factor
        vol_norm = (df['bytes_sent'] / df['bytes_sent'].max()) * 30
        # Connection frequency factor
        conn_norm = (df['connections'] / df['connections'].max()) * 20
        # ML anomaly factor
        ml_factor = anomaly_flag.astype(int) * 30
        # Rule severity scaling
        rule_score = rules_df['alert'].apply(lambda x: 0 if x == 'Normal' else (40 if 'DDoS' in x or 'Exfiltration' in x else 25))
        
        scores = vol_norm + conn_norm + ml_factor + rule_score
        scores = np.clip(scores, 0, 100)
        return scores
    
    def predict_next_spike(self, df, forecast_hours=1):
        """Predict next traffic spike using Linear Regression on bytes_sent over time."""
        from sklearn.linear_model import LinearRegression
        # Aggregate by hour
        df_hourly = df.set_index('timestamp').resample('h')['bytes_sent'].sum().reset_index()
        df_hourly['hour_index'] = np.arange(len(df_hourly))
        X = df_hourly[['hour_index']].values
        y = df_hourly['bytes_sent'].values
        model = LinearRegression()
        model.fit(X, y)
        next_hours = np.arange(len(df_hourly), len(df_hourly) + forecast_hours).reshape(-1,1)
        pred = model.predict(next_hours)
        spike_threshold = np.percentile(y, 95)
        next_spike = pred[-1] > spike_threshold
        return {
            'predicted_bytes': pred.tolist(),
            'next_hour_spike': bool(next_spike),
            'spike_threshold': spike_threshold
        }