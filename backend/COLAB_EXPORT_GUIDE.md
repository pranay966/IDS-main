# How to Export Your Colab Model and Use It Here

This guide explains how to take your trained model from Google Colab and plug it into this project.

---

## Step 1 — Add export code in Colab

At the end of your training code in Google Colab, add this:

```python
import joblib

# Replace `model` with your actual trained model variable name
joblib.dump(model, 'ml_model.pkl')

# If you have a label encoder, save it too
# joblib.dump(label_encoder, 'ml_label_encoder.pkl')

# If you trained a second (Transfer Learning) model:
# joblib.dump(tl_model, 'tl_model.pkl')
# joblib.dump(tl_label_encoder, 'tl_label_encoder.pkl')
```

---

## Step 2 — Download from Colab

In Colab, run:
```python
from google.colab import files
files.download('ml_model.pkl')
# files.download('ml_label_encoder.pkl')
# files.download('tl_model.pkl')
```

---

## Step 3 — Place files in backend/

Copy the downloaded `.pkl` files into:
```
IDS/
└── backend/
    ├── ml_model.pkl           ← your ML model
    ├── ml_label_encoder.pkl   ← label encoder (if used)
    ├── tl_model.pkl           ← TL model (if trained)
    └── tl_label_encoder.pkl   ← TL label encoder (if used)
```

---

## Step 4 — Match the feature columns (if needed)

Open `backend/model_utils.py` and check the `FEATURE_COLUMNS` list.

If your Colab model was trained on **different features**, update
`FEATURE_COLUMNS` to match exactly what your model expects.

For example, if your model only uses 10 features:
```python
FEATURE_COLUMNS = ['duration', 'src_bytes', 'dst_bytes', ...]  # your 10 features
```

---

## Step 5 — Restart the backend

```bash
cd backend
python app.py
```

The server will print `✓ Loaded model: ml_model.pkl` if it finds your file.

---

## No model yet? Use Demo Mode

If no `.pkl` files are found, the backend runs in **intelligent demo mode**:
- Keywords like `attack`, `dos`, `probe` in packet data → predicts `malicious`
- Other inputs → predicts `safe`

This lets you see the full UI working immediately.

---

## Train a local model instead

If you want to train locally without Colab:
```bash
cd backend
python train_model.py
```
This downloads the NSL-KDD dataset and trains two models (Random Forest + Gradient Boosting).
Training takes ~3–5 minutes on a typical laptop.
