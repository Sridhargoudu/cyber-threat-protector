import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import joblib
import re
from urllib.parse import urlparse
import numpy as np

# Load dataset
data = pd.read_csv("phishing_dataset.csv")

# Check the column names
print("Columns in the dataset:", data.columns)

# Drop non-numeric or irrelevant columns
data = data.drop([
    'FILENAME', 'URL', 'Domain', 'Title', 'HasFavicon', 'Robots', 
    'HasTitle', 'HasDescription', 'HasCopyrightInfo', 'TLD'
], axis=1)

# Check data types and handle non-numeric columns
print("Data types before conversion:\n", data.dtypes)
# Example: Convert a column to numeric (if needed)
# data['ColumnName'] = pd.to_numeric(data['ColumnName'], errors='coerce')

# Drop remaining non-numeric columns (if any)
data = data.select_dtypes(include=['number'])

# Handle missing values
data = data.dropna()

# Define the target column
target_column = "label"

# Split data into features and target
X = data.drop(target_column, axis=1)
y = data[target_column]

# Convert labels to numerical values (if needed)
y = y.replace({'bad': 0, 'good': 1})

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Normalize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Handle class imbalance
classes = np.unique(y_train)
class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
class_weights_dict = {0: class_weights[0], 1: class_weights[1]}

# Train the model
model = RandomForestClassifier(random_state=42, class_weight=class_weights_dict)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
print("Classification Report:\n", classification_report(y_test, y_pred))

# Save the model and scaler
joblib.dump(model, "phishing_model.pkl")
joblib.dump(scaler, "scaler.pkl")
print("Model and scaler saved!")