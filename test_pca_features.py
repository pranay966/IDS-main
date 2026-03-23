import joblib
try:
    pca = joblib.load('backend/pca_transformer.pkl')
    print(list(pca.feature_names_in_))
except Exception as e:
    print(e, "or no feature_names_in_ attribute")
