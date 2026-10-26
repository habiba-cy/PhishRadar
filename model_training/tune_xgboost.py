import pandas as pd
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb
import joblib

# Load dataset
data = pd.read_csv("../dataset/dataset_phishing.csv")

# Encode labels
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

# Features and target
X = data.drop(columns=['status', 'url'])
y = data['status']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Base model
model = xgb.XGBClassifier()

# Hyperparameter grid
param_dist = {
    'n_estimators': [100, 200, 300, 400],
    'max_depth': [3, 4, 5, 6, 7],
    'learning_rate': [0.01, 0.05, 0.1, 0.2],
    'subsample': [0.6, 0.7, 0.8, 1.0],
    'colsample_bytree': [0.6, 0.7, 0.8, 1.0],
    'gamma': [0, 1, 5],
    'min_child_weight': [1, 3, 5]
}

# Randomized search
random_search = RandomizedSearchCV(
    estimator=model,
    param_distributions=param_dist,
    n_iter=20,
    scoring='f1',
    cv=3,
    verbose=2,
    random_state=42,
    n_jobs=-1
)

# Run search
random_search.fit(X_train, y_train)

print("Best Parameters:", random_search.best_params_)

# Train final model with best parameters
best_model = random_search.best_estimator_

# Save model
joblib.dump(best_model, "../backend_api/phishing_model.pkl")

print("Tuned XGBoost model saved successfully!")