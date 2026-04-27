# 🛡️ Manufacturing Threat Hunter

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.31+-FF4B4B.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Manufacturing Threat Hunter** is an AI-powered cybersecurity dashboard designed to detect, analyze, and visualize network threats in industrial manufacturing environments. By leveraging multiple machine learning models and a heuristic rule engine, it identifies anomalies such as DDoS attacks, data exfiltration, and suspicious traffic spikes in real-time.

---

## 🚀 Key Features

- **🤖 Multi-Model AI Detection**: Utilizes four distinct ML models for robust anomaly detection:
  - **Isolation Forest**: Identifies outliers in high-dimensional traffic data.
  - **Local Outlier Factor (LOF)**: Detects local density deviations.
  - **K-Means Clustering**: Clusters traffic patterns to find unusual groups.
  - **Random Forest**: Supervised classification for known threat patterns.
- **📡 Real-Time Monitoring**: Simulate live network traffic streams with dynamic threat scoring and instant UI updates.
- **📈 Advanced Security Analytics**:
  - Traffic volume trends over time.
  - Spike detection with configurable thresholds.
  - Heatmaps for identifying high-risk time windows.
  - Protocol distribution and connection analysis.
- **🔮 Predictive Forecasting**: Predicts potential traffic spikes in the next hour using Linear Regression.
- **📥 Professional Reporting**:
  - Export comprehensive **PDF Security Reports** with findings and summaries.
  - Download detailed **CSV Threat Logs** for external forensic analysis.
- **🎨 Premium UI/UX**: Dark-themed, responsive dashboard built with Streamlit and custom CSS.

---

## 🛠️ Technology Stack

| Component | Technology |
| :--- | :--- |
| **Frontend** | [Streamlit](https://streamlit.io/) |
| **Data Processing** | [Pandas](https://pandas.pydata.org/), [NumPy](https://numpy.org/) |
| **Machine Learning** | [Scikit-learn](https://scikit-learn.org/), [Joblib](https://joblib.readthedocs.io/) |
| **Visualization** | [Matplotlib](https://matplotlib.org/), [Seaborn](https://seaborn.pydata.org/), [Plotly](https://plotly.com/python/) |
| **PDF Generation** | [FPDF](http://www.fpdf.org/) |

---

## 📦 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/manufacturing-threat-hunter.git
   cd manufacturing-threat-hunter
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🎮 Usage

1. **Run the Application**:
   ```bash
   streamlit run app.py
   ```

2. **Upload Data**: The application starts with a welcome screen. Use the sidebar to upload a CSV file containing network logs.
   * *Tip: If you don't have a file, you can check the "Expected Data Format" section in the app for guidance.*

3. **Analyze**: Click **Analyze Traffic** to train the AI models and generate insights.
4. **Live Mode**: Toggle "Enable Live Monitoring" to see the system process simulated incoming traffic in real-time.
5. **Export**: Click "Generate Security Report" to compile findings into downloadable PDF and CSV formats.

---

## 📂 Project Structure

```text
manufacturing-threat-hunter/
├── app.py              # Main Streamlit application entry point
├── requirements.txt    # Project dependencies
├── data/               # Directory for sample/uploaded datasets
├── models/             # Serialized ML models (.pkl files)
├── utils/              # Core logic modules
│   ├── detector.py     # ML models and ThreatDetector class
│   ├── preprocessing.py# Data cleaning and feature engineering
│   ├── visualizer.py   # Matplotlib/Seaborn charting logic
│   ├── report.py       # PDF and CSV export utilities
└── assets/             # Images and UI assets
```

---

## 🛡️ Detection Logic

The system computes a **Threat Score (0-100)** based on a weighted combination of:
1. **Volume Factor**: Normalized traffic size.
2. **Connection Frequency**: Rate of connection attempts.
3. **ML Anomaly Factor**: Combined flags from all four AI models.
4. **Heuristic Rules**: Predefined patterns for DDoS, Brute Force, and Exfiltration.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

---
*Developed with ❤️ for industrial cybersecurity.*
