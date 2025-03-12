import requests

# Test a phishing URL
response = requests.post(
    "http://127.0.0.1:5000/detect",
    json={"url": "http://fake-login-page.com/login"}
)
print("Phishing URL Result:", response.json())

# Test a legitimate URL
response = requests.post(
    "http://127.0.0.1:5000/detect",
    json={"url": "https://www.google.com"}
)
print("Legitimate URL Result:", response.json())