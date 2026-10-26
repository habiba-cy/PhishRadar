import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

# Load dataset
data = pd.read_csv("../dataset/dataset_phishing.csv")

# Convert labels
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

# Features and target
X = data.drop(columns=['status','url'])
y = data['status']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train best model (XGBoost)
model = xgb.XGBClassifier()

model.fit(X_train, y_train)

# Save model
joblib.dump(model, "../backend_api/phishing_model.pkl")

print("Model saved successfully!")