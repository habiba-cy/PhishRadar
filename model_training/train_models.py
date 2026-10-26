import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.ensemble import RandomForestClassifier
import xgboost as xgb

# Load dataset
data = pd.read_csv("../dataset/dataset_phishing.csv")


# Convert labels to numbers
label_encoder = LabelEncoder()
data['status'] = label_encoder.fit_transform(data['status'])

# Separate features and target
X = data.drop(columns=['status','url'])
y = data['status']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Models to test
models = {
    "Logistic Regression": LogisticRegression(max_iter=2000),
    "SVM": SVC(),
    "Random Forest": RandomForestClassifier(),
    "XGBoost": xgb.XGBClassifier()
}

# ============================
# CROSS VALIDATION (5-FOLD)
# ============================

from sklearn.model_selection import cross_validate, StratifiedKFold

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

scoring = {
    'accuracy': 'accuracy',
    'precision': 'precision',
    'recall': 'recall',
    'f1': 'f1'
}

print("\n===== CROSS VALIDATION RESULTS =====")

for name, model in models.items():
    print(f"\nModel: {name}")

    cv_results = cross_validate(
        model,
        X,
        y,
        cv=cv,
        scoring=scoring,
        n_jobs=-1
    )

    print("Accuracy:", cv_results['test_accuracy'].mean())
    print("Precision:", cv_results['test_precision'].mean())
    print("Recall:", cv_results['test_recall'].mean())
    print("F1 Score:", cv_results['test_f1'].mean())

# Train and evaluate models
for name, model in models.items():

    print("\nTraining:", name)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    acc = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions)
    recall = recall_score(y_test, predictions)
    f1 = f1_score(y_test, predictions)

    print("Accuracy:", acc)
    print("Precision:", precision)
    print("Recall:", recall)
    print("F1 Score:", f1)