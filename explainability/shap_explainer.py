import pandas as pd
import shap
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

# Load dataset
data = pd.read_csv("../dataset/dataset_phishing.csv")

# Convert labels
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

# Separate features and labels
X = data.drop(columns=['status','url'])
y = data['status']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Load trained model
model = joblib.load("../backend_api/phishing_model.pkl")

# Create SHAP explainer
explainer = shap.TreeExplainer(model)

# Calculate SHAP values
shap_values = explainer.shap_values(X_test)

# Show summary plot
shap.summary_plot(shap_values, X_test)