from flask import Flask, render_template, request, jsonify

from password_checker import (
    calculate_score,
    get_strength,
    calculate_entropy,
    generate_password,
    hash_password,
    verify_password,
    save_hash,
    load_hash,
)


app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def check_password_api():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    password = data["password"]

    if not password:
        return jsonify({
            "success": False,
            "error": "Password cannot be empty."
        }), 400

    score, reasons, checks, common_check = calculate_score(password)

    strength = get_strength(score, common_check)
    entropy = calculate_entropy(password)

    return jsonify({
        "success": True,
        "score": score,
        "strength": strength,
        "entropy": round(entropy, 1),
        "checks": checks,
        "common": common_check,
        "reasons": reasons
    })


@app.route("/api/generate", methods=["POST"])
def generate_password_api():
    data = request.get_json() or {}

    length = data.get("length", 16)

    try:
        length = int(length)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "error": "Invalid password length."
        }), 400

    if length < 12 or length > 64:
        return jsonify({
            "success": False,
            "error": "Password length must be between 12 and 64."
        }), 400

    password = generate_password(length)

    return jsonify({
        "success": True,
        "password": password,
        "length": len(password)
    })


@app.route("/api/hash", methods=["POST"])
def hash_password_api():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    password = data["password"]

    if not password:
        return jsonify({
            "success": False,
            "error": "Password cannot be empty."
        }), 400

    password_hash = hash_password(password)

    save_hash(password_hash)

    return jsonify({
        "success": True,
        "message": "Password hashed and saved successfully."
    })


@app.route("/api/verify", methods=["POST"])
def verify_password_api():
    data = request.get_json()

    if not data or "password" not in data:
        return jsonify({
            "success": False,
            "error": "Password is required."
        }), 400

    password = data["password"]

    password_hash = load_hash()

    if password_hash is None:
        return jsonify({
            "success": False,
            "error": "No saved password hash found."
        }), 404

    try:
        valid = verify_password(password, password_hash)

    except ValueError:
        return jsonify({
            "success": False,
            "error": "Saved hash is invalid."
        }), 500

    return jsonify({
        "success": True,
        "matches": valid
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )