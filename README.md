PhishRadar: Dynamic Phishing URL Detection

PhishRadar is a cybersecurity project developed as part of my BSc (Hons) Cybersecurity final-year project. It detects potentially malicious URLs using machine learning, real-time security checks, and explainable AI techniques.

Features

Machine Learning Detection: Uses a trained
XGBoost model to classify potentially phishing URLs.

URL Feature Analysis: Examines URL characteristics and relevant domain information.

Real-Time Security Checks: Integrates external threat intelligence services, including Google Safe Browsing and VirusTotal.

Web Interface: Provides a user interface for URL analysis.

Browser Extension: Includes a Chrome extension for URL checking.

Explainable AI: Includes SHAP and LIME components to help interpret model predictions.

Model Evaluation: Includes scripts for training, tuning, and evaluating machine learning models.

Technologies Used

Python

Flask

XGBoost and scikit-learn

SHAP and LIME

HTML, CSS, and JavaScript

Chrome Extension Manifest V3

Google Safe Browsing and VirusTotal APIs

Project Structure

phishing-detection-system/
├── backend_api/       # Flask backend and trained model
├── browser_extension/ # Chrome browser extension
├── dataset/           # Dataset used for model development
├── demo_site/         # Demonstration login page
├── explainability/    # SHAP and LIME components
├── model_training/    # Training and evaluation scripts
├── requirements.txt   # Python dependencies
└── README.md

Setup

Clone the repository:

git clone https://github.com/habiba-cy/PhishRadar.git
cd PhishRadar

Create and activate a Python virtual environment.

On Windows:

python -m venv .venv
.venv\Scripts\Activate.ps1

Install the dependencies:

pip install -r requirements.txt

Configure any required API keys using environment variables or a local .env file. Never commit API keys, passwords, or other credentials to GitHub.

Start the Flask application using the entry point and instructions defined in the backend code.

Security and Limitations

PhishRadar is an academic project intended for educational and research purposes. Its predictions and external security checks should not be treated as a guarantee that a URL is safe or malicious.

Only test the system and its demonstration pages in authorised environments. Do not enter real credentials into demonstration login pages.

Author

Umu Habiba
BSc (Hons) Cybersecurity — First-Class Honours
University of West London

GitHub: @habiba-cy