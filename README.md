# **OIDC Token Validation in Flask API**

## **Overview**
This guide explains how to integrate **OpenID Connect (OIDC) token validation** into a **Flask API** using `Flask-JWT-Extended` and `PyJWT`. It ensures **secure authentication** by validating JWT tokens issued by an **OIDC provider** (such as **Microsoft Entra ID (formerly Azure AD), Auth0, Okta, or Keycloak**).

## **Prerequisites**
✅ Python 3.8+ installed  
✅ `pip install flask flask-jwt-extended pyjwt requests`  
✅ An OIDC provider issuing JWT tokens (`https://your-oidc-provider.com`)  

---

## **Step 1: Install Dependencies**
```bash
pip install flask flask-jwt-extended pyjwt requests
```

---

## **Step 2: Create a Flask App**
### **Initialize Flask & JWT Configuration**
Create `app.py`:
```python
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, verify_jwt_in_request
import requests
import jwt  # PyJWT

app = Flask(__name__)

# OIDC Provider Configuration
OIDC_ISSUER = "https://your-oidc-provider.com"
OIDC_JWKS_URL = f"{OIDC_ISSUER}/.well-known/jwks.json"
OIDC_AUDIENCE = "your-api-client-id"

# Function to fetch JWKS (Public Keys for Token Verification)
def get_jwks():
    response = requests.get(OIDC_JWKS_URL)
    return response.json()["keys"]

# Function to verify JWT token
def validate_jwt(token):
    unverified_header = jwt.get_unverified_header(token)
    jwks = get_jwks()
    public_key = None

    for key in jwks:
        if key["kid"] == unverified_header["kid"]:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

    if not public_key:
        return None

    try:
        decoded_token = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER
        )
        return decoded_token
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Middleware to validate token before request execution
@app.before_request
def check_auth():
    auth_header = request.headers.get("Authorization", "").split(" ")
    if len(auth_header) != 2 or auth_header[0] != "Bearer":
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header[1]
    decoded_token = validate_jwt(token)
    if not decoded_token:
        return jsonify({"error": "Invalid or expired token"}), 401

    request.user = decoded_token

# Protected API Route
@app.route("/secure-data", methods=["GET"])
def secure_data():
    verify_jwt_in_request()
    return jsonify({"message": "This is a protected resource!", "user": request.user})

if __name__ == "__main__":
    app.run(debug=True)
```

---

## **Step 3: Running the Flask API**
```bash
python app.py
```

---

## **Step 4: Testing API with OIDC Token**
### **Call the API with a Valid JWT**
```bash
curl -X GET -H "Authorization: Bearer <ACCESS_TOKEN>" http://127.0.0.1:5000/secure-data
```
Expected Response:
```json
{
    "message": "This is a protected resource!",
    "user": { "sub": "user-id", "email": "user@example.com", ... }
}
```

### **Call API with an Invalid Token**
```bash
curl -X GET -H "Authorization: Bearer invalid_token" http://127.0.0.1:5000/secure-data
```
Expected Response:
```json
{
    "error": "Invalid or expired token"
}
```

---

## **Security Enhancements**
✅ **Uses JWKS for dynamic key validation**  
✅ **Middleware to enforce authentication on requests**  
✅ **Proper error handling for expired or invalid tokens**  
✅ **Supports multiple OIDC providers (Azure, Auth0, Okta, Keycloak, etc.)**  

For more details, check the **Flask JWT documentation**:  
🔗 [https://flask-jwt-extended.readthedocs.io/](https://flask-jwt-extended.readthedocs.io/)

🚀 Happy Securing! Let me know if you need **OIDC integration with OAuth2 flows**!  
```
