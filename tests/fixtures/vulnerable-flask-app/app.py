"""Vulnerable Flask app — intentionally insecure for testing."""

from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text
import os

app = Flask(__name__)
app.secret_key = "super-secret-key-123"

# Hardcoded AWS key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

engine = create_engine("sqlite:///app.db")

# CORS wildcard
from flask_cors import CORS
CORS(app, origins="*")


@app.route("/users", methods=["GET"])
def get_users():
    """No auth, SQL injection via f-string."""
    name = request.args.get("name", "")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    result = engine.execute(text(query))
    return jsonify([dict(row) for row in result])


@app.route("/admin", methods=["POST"])
def admin_panel():
    """eval() on user input."""
    code = request.form.get("code", "")
    result = eval(code)
    return jsonify({"result": str(result)})


@app.route("/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    # Log user data including potential PII
    print(f"User searched for: {query}, email: {request.args.get('email')}")
    return jsonify({"results": []})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
