# IDS - Intrusion Detection System Setup Guide

A complete guide to run your IDS project locally with the ML backend connected to the React frontend.

---

## Prerequisites

Install these first if you haven't already:
- [Python 3.8+](https://python.org/downloads/) — check: `python --version`
- [Node.js 18+](https://nodejs.org/) — check: `node --version`
- [Git](https://git-scm.com/) — check: `git --version`

---

## Quick Start (One Click)

Simply double-click **`start.bat`** in the project root.

It will:
1. Install Python + Node.js dependencies
2. Start the Flask backend on port 5000
3. Start the Vite frontend on port 5173
4. Open your browser automatically

---

## Manual Setup

### 1. Backend

```bash
cd backend
pip install -r requirements.txt
```

**Option A** — Train model locally (downloads NSL-KDD dataset, ~5 min):
```bash
python train_model.py
```

**Option B** — Use your Colab model:
See `backend/COLAB_EXPORT_GUIDE.md` for step-by-step instructions.

Then start the Flask server:
```bash
python app.py
```

Verify it's working: http://localhost:5000/api/health

### 2. Frontend

```bash
# In the project root (IDS/)
npm install
npm run dev
```

Open: http://localhost:5173

---

## Project Structure

```
IDS/
├── src/                        ← React frontend source
│   ├── components/             ← Layout, sidebar
│   ├── pages/                  ← Home, Detection, Dashboard, History
│   ├── services/api.ts         ← API client (calls /api/detect)
│   └── context/AppContext.tsx  ← App state + history
├── backend/
│   ├── app.py                  ← Flask server (main API)
│   ├── model_utils.py          ← Feature parsing + prediction
│   ├── train_model.py          ← Train models locally
│   ├── requirements.txt        ← Python dependencies
│   ├── ml_model.pkl            ← [generated] Random Forest model
│   ├── tl_model.pkl            ← [generated] Gradient Boosting model
│   └── COLAB_EXPORT_GUIDE.md  ← How to plug in your Colab model
├── .env                        ← VITE_API_URL=/api
├── vite.config.ts              ← Proxy: /api → localhost:5000
├── start.bat                   ← One-click launcher
└── SETUP.md                    ← This file
```

---

## How It Works

```
Browser → Vite Dev Server → (proxy /api/*) → Flask Backend → ML Model
                                                               ↓
                                               { prediction, confidence, attackType }
```

The Vite dev server automatically proxies any `/api` request to Flask.
No CORS issues. No manual URL configuration needed.

---

## Using the Detection Page

1. Go to **Detection** in the sidebar
2. Choose model type: **ML** (Random Forest) or **TL** (Gradient Boosting)
3. Enter packet data — you can use:
   - A **CSV row** of 41 features (NSL-KDD format)
   - Any text (keywords like "dos", "attack", "probe" will trigger malicious prediction in demo mode)
4. Click **Analyze** — result appears instantly

---

## API Reference

### POST `/api/detect`
```json
{
  "packetData": "0,tcp,http,SF,181,5450,0,...",
  "modelType": "ml",
  "features": {}
}
```

Response:
```json
{
  "prediction": "malicious",
  "confidence": 0.96,
  "attackType": "DoS"
}
```

### GET `/api/health`
Returns model load status.

---

## Connecting Your Colab Model

See `backend/COLAB_EXPORT_GUIDE.md` for full instructions.

**TL;DR** — add this to the end of your Colab notebook:
```python
import joblib
joblib.dump(your_model, 'ml_model.pkl')
from google.colab import files
files.download('ml_model.pkl')
```
Then place `ml_model.pkl` in the `backend/` folder and restart the server.
