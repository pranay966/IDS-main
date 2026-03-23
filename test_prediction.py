import sys
sys.path.append('backend')
from model_utils import parse_features, predict_sklearn
import joblib

try:
    pca = joblib.load('backend/pca_transformer.pkl')
    encoder = joblib.load('backend/label_encoder.pkl')
    svm = joblib.load('backend/svm_model.pkl')
    X = parse_features("foo", {})
    print("X shape:", X.shape)
    print("X:", X)
    result = predict_sklearn(svm, pca, encoder, X)
    print("Result:", result)
except Exception as e:
    import traceback
    traceback.print_exc()
