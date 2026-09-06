"""
Password Strength Analyzer - Web Application

Run with:
    python app.py
Then open http://127.0.0.1:5000 in your browser.
"""

from flask import Flask, jsonify, render_template, request

import math
import database
from password_analyzer import (
    analyze_password,
    hash_password,
    suggest_passphrase,
    suggest_strong_password,
)

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str) or not password:
        return jsonify({"error": "No password provided."}), 400
    if len(password) > 256:
        return jsonify({"error": "Password must be 256 characters or fewer."}), 400

    result = analyze_password(password)

    # Uniqueness check against the database (hashed comparison)
    reused = database.is_reused(password)

    response = {
        "score": result.score,
        "label": result.label,
        "entropy": result.entropy,
        "crack_time": result.crack_time,
        "checks": result.checks,
        "suggestions": result.suggestions,
        "reused": reused,
        "history_count": database.history_count(),
        "brute_force": result.brute_force,
    }
    return jsonify(response)


@app.route("/api/save", methods=["POST"])
def save():
    """Record the password as 'used' so it can't be reused later."""
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str) or not password:
        return jsonify({"error": "No password provided."}), 400
    if len(password) > 256:
        return jsonify({"error": "Password must be 256 characters or fewer."}), 400
    already_saved = database.is_reused(password)
    if not already_saved:
        database.record_password(password)
    return jsonify({
        "status": "already_saved" if already_saved else "saved",
        "history_count": database.history_count(),
    })


@app.route("/api/stats")
def stats():
    return jsonify({"history_count": database.history_count()})


@app.route("/api/generate", methods=["POST"])
def generate():
    data = request.get_json(silent=True) or {}
    try:
        length = int(data.get("length", 32))
    except (TypeError, ValueError):
        return jsonify({"error": "Length must be a whole number."}), 400
    length = max(12, min(length, 64))
    strong = suggest_strong_password(length)
    passphrase = suggest_passphrase()
    return jsonify({
        "strong": strong,
        "passphrase": passphrase,
        "entropy_estimate": round(len(strong) * math.log2(92), 1),
    })


@app.route("/api/hash", methods=["POST"])
def hashes():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "No password provided."}), 400
    return jsonify(hash_password(password, salt="demo-salt"))


if __name__ == "__main__":
    print("Password Strength Analyzer running at http://127.0.0.1:5000")
    app.run(debug=False, port=5000)
