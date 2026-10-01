"""
Web demonstration interface for the Password & Credential Security Audit Suite.

This web layer exposes safe password-analysis and hash-analysis functionality
for demonstration and educational purposes. The full CLI and controlled
laboratory attack-simulation modules remain available locally through main.py.
"""

from __future__ import annotations

import os

from flask import Flask, render_template, request

from core.hash_utils import (
    get_supported_algorithms,
    hash_password,
    identify_hash_format,
)
from modules.password_strength import analyze_password


APP_NAME = "Password & Credential Security Audit Suite"
VERSION = "0.2.0"

app = Flask(__name__)


@app.get("/")
def index():
    """Render the main demonstration interface."""
    return render_template(
        "index.html",
        app_name=APP_NAME,
        version=VERSION,
        algorithms=get_supported_algorithms(),
        password_result=None,
        hash_result=None,
        hash_value="",
        hash_algorithm="sha256",
    )


@app.post("/analyze-password")
def analyze_password_route():
    """Analyze a laboratory/demo password."""
    password = request.form.get("password", "")

    password_result = None
    error = None

    if not password:
        error = "Please enter a password for analysis."
    else:
        try:
            password_result = analyze_password(password).to_dict()
        except (TypeError, ValueError) as exc:
            error = str(exc)

    return render_template(
        "index.html",
        app_name=APP_NAME,
        version=VERSION,
        algorithms=get_supported_algorithms(),
        password_result=password_result,
        hash_result=None,
        hash_value="",
        hash_algorithm="sha256",
        error=error,
    )


@app.post("/analyze-hash")
def analyze_hash_route():
    """Identify possible formats for a supplied hexadecimal hash."""
    hash_value = request.form.get("hash_value", "").strip()

    hash_result = identify_hash_format(hash_value)

    error = None
    if not hash_value:
        error = "Please enter a hash value."
    elif not hash_result:
        error = (
            "The supplied value is not a supported hexadecimal hash format "
            "or its length does not match a supported format."
        )

    return render_template(
        "index.html",
        app_name=APP_NAME,
        version=VERSION,
        algorithms=get_supported_algorithms(),
        password_result=None,
        hash_result=hash_result,
        hash_value=hash_value,
        hash_algorithm="sha256",
        error=error,
    )


@app.post("/generate-hash")
def generate_hash_route():
    """Generate a hash for an authorized laboratory/demo password."""
    password = request.form.get("hash_password", "")
    algorithm = request.form.get("hash_algorithm", "sha256")

    generated_hash = None
    error = None

    if not password:
        error = "Please enter a password for hash generation."
    else:
        try:
            generated_hash = hash_password(password, algorithm)
        except (TypeError, ValueError) as exc:
            error = str(exc)

    return render_template(
        "index.html",
        app_name=APP_NAME,
        version=VERSION,
        algorithms=get_supported_algorithms(),
        password_result=None,
        hash_result=None,
        hash_value="",
        hash_algorithm=algorithm,
        generated_hash=generated_hash,
        error=error,
    )


@app.get("/health")
def health():
    """Simple health endpoint for deployment monitoring."""
    return {
        "status": "ok",
        "application": APP_NAME,
        "version": VERSION,
    }


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)