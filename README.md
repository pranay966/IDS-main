# Intrusion Detection System (IDS) - Real-Time Packet Monitor

A full-stack, real-time Machine Learning and Transfer Learning (ML/TL) Intrusion Detection System built with React, Vite, Flask, and Scapy. This system captures raw network packets from your active interfaces, analyzes them using trained ML models, and displays live metrics and breach alerts on a sleek dashboard.

## System Architecture Flow

Here is exactly how the entire system works from end-to-end:

1. **Packet Capture (Backend)**
   - The Python Flask backend uses `Scapy` to hook into the host machine's network interfaces (via Npcap on Windows).
   - Once a capture session starts, a background thread sniffs packets in real-time.
   - It extracts Layer 3 and Layer 4 details such as Protocol (TCP/UDP/ICMP/IPv6), IPs, Ports, Packet Lengths, and TCP Flags.
   - It maintains a sliding window of the last 500 packets in memory.

2. **Real-time Feed (Server-Sent Events)**
   - The backend pushes these packet summaries instantly to the frontend using a Server-Sent Events (SSE) stream.
   - The React frontend receives this stream and populates the **Live Packet Feed** table dynamically without polling.

3. **Rule-Based Safety Filter (Heuristics)**
   - When the user clicks **Analyze**, the backend sweeps the captured packets.
   - **Safe Traffic Bypass:** Before running heavy ML models, the backend checks for known safe traffic patterns. Standard web browsing (Ports 80 HTTP, 443 HTTPS/QUIC) and DNS queries (Port 53) are instantly categorized as `NORMAL / SAFE`.
   - The system separates the "Normal" traffic from the "Suspicious" traffic.

4. **Machine Learning Analysis**
   - Packets deemed "Suspicious" are passed into the ML pipeline.
   - The model mathematically converts these raw packets into a 41-feature (or 64 for CNN) statistical array (simulating standard IDS datasets like NSL-KDD/CICIDS).
   - The chosen model (Random Forest, SVM, ANN, or CNN) predicts if the batch contains an attack, outputting a specific attack type (e.g. DoS, Probe, R2L) or `SAFE`.

5. **Dashboard Visualization**
   - The frontend combines the ML result and the safe packet metrics to present a unified health report. 
   - It displays the Total Packets, Safe Packet counts, Suspicious Packet counts, and whether an overall threat was detected, along with ML confidence scores.

## Requirements

- **Node.js** v18+
- **Python** 3.8+
- **Npcap** (Required for Windows packet capture) - [Download Here](https://npcap.com/).

## Quick Start (For Friends/Teammates)

We've provided a simple batch script to automate the entire startup process.

1. **Install Npcap** on your Windows machine if you haven't already.
2. Ensure you have Node and Python installed.
3. **Right-click** `start.bat` and select **"Run as Administrator"**.
   *(Administrator privileges are strictly required to capture network packets)*

The script will automatically:
- Check and install Python dependencies into the backend environment.
- Install React frontend dependencies.
- Open the Flask API server.
- Open the Vite configuration server.
- Launch the application in your browser at `http://localhost:5173/live`.

## Project Structure

```
├── backend/                  # Python Flask API & Machine Learning
│   ├── app.py                # Core API, Route Handlers, Rule-based Engine
│   ├── packet_capture.py     # Scapy Threading & Network Sniffing
│   ├── feature_extractor.py  # Converts raw packets -> dataset arrays for ML
│   ├── model_utils.py        # ML Prediction Handlers & Pad/Format Logic
│   └── *.pkl / *.pth         # Pre-trained ML Models
│
├── src/                      # React Frontend
│   ├── pages/
│   │   ├── LiveMonitor.tsx   # The main Dashboard & SSE Feed
│   │   ├── Detection.tsx     # Manual legacy detection view
│   ├── context/              # App state for historical tracking
│   └── App.tsx               # Routing
│
├── start.bat                 # One-click startup script (Run as Admin)
└── README.md                 # This file
```

## Available Models
- **Random Forest (RF)**: Fast, highly accurate ensemble learning tree model. Default choice.
- **Support Vector Machine (SVM)**: Effective in high dimensional spaces for margin-based classification.
- **Artificial Neural Network (ANN/MLP)**: Multi-layer perceptron for deep pattern recognition.
- **Convolutional Neural Network (CNN)**: Deep transfer learning model utilizing PyTorch.
