import joblib
vectorizer = joblib.load('models/vectorizer.pkl')
print("Vectorizer loaded successfully!")
model = joblib.load('models/model.pkl')
print("Model loaded successfully!")