from flask import Flask, request, jsonify
import joblib
import numpy as np
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Feature extraction function
def extract_features(url):
    features = []
    # Feature 1: URL length
    features.append(len(url))
    # Feature 2: Number of special characters
    features.append(len(re.findall(r'[^\w\s]', url)))
    # Feature 3: Presence of HTTPS
    features.append(1 if "https" in url else 0)
    # Feature 4: Domain length
    domain = urlparse(url).netloc
    features.append(len(domain))
    # Feature 5: Number of subdomains
    features.append(domain.count('.'))
    # Feature 6: Presence of IP address
    features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)
    # Feature 7: Presence of suspicious keywords
    suspicious_keywords = ['login', 'verify', 'secure', 'account', 'update']
    features.append(sum(1 for keyword in suspicious_keywords if keyword in url.lower()))
    # Feature 8: Number of digits in the URL
    features.append(len(re.findall(r'\d', url)))
    # Feature 9: Number of letters in the URL
    features.append(len(re.findall(r'[a-zA-Z]', url)))
    # Feature 10: Number of equals signs in the URL
    features.append(url.count('='))
    # Feature 11: Number of question marks in the URL
    features.append(url.count('?'))
    # Feature 12: Number of ampersands in the URL
    features.append(url.count('&'))
    # Feature 13: Number of other special characters in the URL
    features.append(len(re.findall(r'[^\w\s?=&]', url)))
    # Feature 14: Special character ratio in the URL
    features.append(len(re.findall(r'[^\w\s]', url)) / len(url) if len(url) > 0 else 0)
    # Feature 15: Presence of a bank-related keyword
    bank_keywords = ['bank', 'pay', 'crypto']
    features.append(sum(1 for keyword in bank_keywords if keyword in url.lower()))
    # Feature 16: Number of slashes in the URL
    features.append(url.count('/'))
    # Feature 17: Number of dots in the URL
    features.append(url.count('.'))
    # Feature 18: Number of hyphens in the URL
    features.append(url.count('-'))
    # Feature 19: Number of underscores in the URL
    features.append(url.count('_'))
    # Feature 20: Number of colons in the URL
    features.append(url.count(':'))
    # Feature 21: Number of semicolons in the URL
    features.append(url.count(';'))
    # Feature 22: Number of commas in the URL
    features.append(url.count(','))
    # Feature 23: Number of exclamation marks in the URL
    features.append(url.count('!'))
    # Feature 24: Number of at symbols in the URL
    features.append(url.count('@'))
    # Feature 25: Number of hash symbols in the URL
    features.append(url.count('#'))
    # Feature 26: Number of dollar signs in the URL
    features.append(url.count('$'))
    # Feature 27: Number of percent signs in the URL
    features.append(url.count('%'))
    # Feature 28: Number of caret symbols in the URL
    features.append(url.count('^'))
    # Feature 29: Number of ampersands in the URL
    features.append(url.count('&'))
    # Feature 30: Number of asterisks in the URL
    features.append(url.count('*'))
    # Feature 31: Number of parentheses in the URL
    features.append(url.count('(') + url.count(')'))
    # Feature 32: Number of plus signs in the URL
    features.append(url.count('+'))
    # Feature 33: Number of equal signs in the URL
    features.append(url.count('='))
    # Feature 34: Number of question marks in the URL
    features.append(url.count('?'))
    # Feature 35: Number of backslashes in the URL
    features.append(url.count('\\'))
    # Feature 36: Number of pipe symbols in the URL
    features.append(url.count('|'))
    # Feature 37: Number of tilde symbols in the URL
    features.append(url.count('~'))
    # Feature 38: Number of brackets in the URL
    features.append(url.count('[') + url.count(']'))
    # Feature 39: Number of curly braces in the URL
    features.append(url.count('{') + url.count('}'))
    # Feature 40: Number of angle brackets in the URL
    features.append(url.count('<') + url.count('>'))
    # Feature 41: Number of double quotes in the URL
    features.append(url.count('"'))
    # Feature 42: Number of single quotes in the URL
    features.append(url.count("'"))
    # Feature 43: Number of spaces in the URL
    features.append(url.count(' '))
    # Feature 44: Number of tabs in the URL
    features.append(url.count('\t'))
    # Feature 45: Number of newlines in the URL
    features.append(url.count('\n'))

    # Ensure the number of features matches the model's expectations
    if len(features) != 45:
        raise ValueError(f"Expected 45 features, but got {len(features)} features.")
    
    return features
    # Example: Extract 45 features (replace with actual logic)
    
    features.append(len(url))  # Feature 1: URL length
    features.append(len(re.findall(r'[^\w\s]', url)))  # Feature 2: Number of special characters
    features.append(1 if "https" in url else 0)  # Feature 3: Presence of HTTPS
    # Add more features here to match the 45 features used during training
    # Example:
    domain = urlparse(url).netloc
    features.append(len(domain))  # Feature 4: Domain length
    features.append(domain.count('.'))  # Feature 5: Number of subdomains
    features.append(1 if re.match(r'\d+\.\d+\.\d+\.\d+', domain) else 0)  # Feature 6: Presence of IP address
    # Continue adding features until you have 45 features
    # ...

    # Ensure the number of features matches the model's expectations
    if len(features) != 45:
        raise ValueError(f"Expected 45 features, but got {len(features)} features.")
    
    return features

# Load the model and scaler
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("scaler.pkl")

@app.route('/detect', methods=['POST'])
def detect():
    # Get URL from the request
    data = request.json
    url = data['url']
    
    # Extract features
    features = extract_features(url)
    
    # Preprocess the features
    features = np.array(features).reshape(1, -1)
    features = scaler.transform(features)
    
    # Make a prediction
    prediction = model.predict(features)
    result = "Phishing" if prediction == 1 else "Legitimate"
    
    # Return the result
    return jsonify({"result": result})

if __name__ == '__main__':
    app.run(debug=True)