import numpy as np
import re


FEATURE_COLUMNS = [
    'duration','protocol_type','service','flag',
    'src_bytes','dst_bytes','land','wrong_fragment',
    'urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted',
    'num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate',
    'srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate',
    'dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate',
    'dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate',
]


def parse_features(packet_data: str, features: dict = None, expected_features: int = 41):
    vec = np.zeros(expected_features, dtype=float)

    if features:
        for i, col in enumerate(FEATURE_COLUMNS):
            if col in features and i < expected_features:
                vec[i] = float(features[col])
        return vec.reshape(1, -1)

    if packet_data:
        parts = re.split(r"[,\s]+", packet_data.strip())
        nums = []
        for p in parts:
            try:
                nums.append(float(p))
            except ValueError:
                continue

        n = min(len(nums), expected_features)
        vec[:n] = nums[:n]

    return vec.reshape(1, -1)


# -------- Pad to expected feature size --------
def _pad_to_expected(model, X):
    if hasattr(model, "n_features_in_"):
        expected = model.n_features_in_
        if X.shape[1] < expected:
            pad = expected - X.shape[1]
            X = np.hstack([X, np.zeros((X.shape[0], pad))])
    return X


def predict_sklearn(model, label_encoder, X):
    X = _pad_to_expected(model, X)

    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        class_idx = int(np.argmax(proba))
        confidence = float(np.max(proba))
    elif hasattr(model, "decision_function"):
        # Some sklearn models (e.g. SVC with probability=False) only expose
        # decision_function. Convert decision scores -> pseudo-probabilities so
        # confidence is input-dependent (useful for “real time” UI feedback).
        scores = model.decision_function(X)

        scores_arr = np.asarray(scores)
        if scores_arr.ndim == 1:
            s = float(scores_arr[0])
            prob_pos = 1.0 / (1.0 + np.exp(-s))  # sigmoid
            proba = np.array([1.0 - prob_pos, prob_pos], dtype=float)
        else:
            # Binary SVC sometimes returns shape (n_samples, 1)
            if scores_arr.ndim == 2 and scores_arr.shape[1] == 1:
                s = float(scores_arr[0, 0])
                prob_pos = 1.0 / (1.0 + np.exp(-s))
                proba = np.array([1.0 - prob_pos, prob_pos], dtype=float)
            else:
                # Multiclass: softmax over decision scores
                scores_row = scores_arr[0]
                scores_row = scores_row - np.max(scores_row)
                exp_scores = np.exp(scores_row)
                proba = exp_scores / np.sum(exp_scores)

        class_idx = int(np.argmax(proba))
        confidence = float(np.max(proba))
    else:
        class_idx = int(model.predict(X)[0])
        confidence = 0.5

    raw_label = (
        label_encoder.inverse_transform([class_idx])[0]
        if label_encoder is not None
        else str(class_idx)
    )

    return build_result(raw_label, confidence)


def predict_cnn(model, label_encoder, X):
    import torch

    if X.shape[1] < 64:
        pad = 64 - X.shape[1]
        X = np.hstack([X, np.zeros((X.shape[0], pad))])

    x_tensor = torch.tensor(X, dtype=torch.float32)

    model.eval()
    with torch.no_grad():
        output = model(x_tensor)
        proba = torch.softmax(output, dim=1).numpy()[0]
        class_idx = int(np.argmax(proba))
        confidence = float(np.max(proba))

    raw_label = (
        label_encoder.inverse_transform([class_idx])[0]
        if label_encoder is not None
        else str(class_idx)
    )

    return build_result(raw_label, confidence)


def build_result(raw_label, confidence):
    label_str = str(raw_label).lower().strip()
    # 0 = Normal, 1 = Malicious mapping, along with text labels
    if label_str in ("0", "normal", "safe", "benign", "0.0"):
        return {
            "prediction": "safe",
            "confidence": round(confidence, 4),
            "attackType": None
        }
    else:
        # Handle '1' or specific attack names
        attack_type = "MALICIOUS" if label_str in ("1", "1.0") else raw_label.upper()
        return {
            "prediction": "malicious",
            "confidence": round(confidence, 4),
            "attackType": attack_type
        }