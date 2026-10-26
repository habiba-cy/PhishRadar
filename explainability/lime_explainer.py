import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from lime.lime_tabular import LimeTabularExplainer

# Load dataset
data = pd.read_csv("../dataset/dataset_phishing.csv")

# Encode labels
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

# Separate features and labels
X = data.drop(columns=['status','url'])
y = data['status']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Load trained model
model = joblib.load("../backend_api/phishing_model.pkl")

# Create LIME explainer
explainer = LimeTabularExplainer(
    training_data=X_train.values,
    feature_names=X_train.columns,
    class_names=["Legitimate", "Phishing"],
    mode="classification"
)

# Pick one example URL
example = X_test.iloc[0]

# Generate explanation
exp = explainer.explain_instance(
    example.values,
    model.predict_proba
)

# Save explanation as HTML
exp.save_to_file("lime_explanation.html")

print("LIME explanation saved as lime_explanation.html")