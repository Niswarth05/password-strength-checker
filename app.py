from functools import wraps

from datetime import date

from flask import Flask, Response, jsonify, render_template, request

import breach
import strength
from vault import Vault, VaultError, MIN_MASTER_LENGTH

VERSION = "0.2.2"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # largest request body: 5 MB
vault = Vault()

ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000"}


# ----- safety checks for every request ------------------------------------

@app.before_request
def only_local_requests():
    # Blocks "DNS rebinding": a website tricking your browser into talking
    # to this local app under a different hostname.
    if request.host not in ALLOWED_HOSTS:
        return jsonify(error="Forbidden host."), 403


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "img-src 'self' data:; font-src 'self'; frame-ancestors 'none'"
    )
    return response


def json_body():
    """Require a JSON object body (plain forms from other sites are rejected)."""
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise VaultError("Request must be a JSON object.")
    return data


def require_decent_master(password):
    """Refuse master passwords that are easy to guess (uses the strength checker)."""
    if len(password) < MIN_MASTER_LENGTH:
        return  # the vault itself reports the length problem
    result = strength.analyze(password)
    if result["strength"] in strength.WEAK_LEVELS:
        tip = result["issues"][0] if result["issues"] else ""
        raise VaultError(
            "That master password is too easy to guess. "
            f"{tip} Try a longer phrase of unrelated words.".replace("  ", " ")
        )


def require_unlocked(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not vault.is_unlocked():
            return jsonify(error="Vault is locked.", locked=True), 401
        return view(*args, **kwargs)
    return wrapper


@app.errorhandler(VaultError)
def handle_vault_error(err):
    return jsonify(error=str(err)), 400


@app.errorhandler(breach.BreachCheckError)
def handle_breach_error(err):
    return jsonify(error=str(err)), 502


# ----- pages ---------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html", min_master=MIN_MASTER_LENGTH, version=VERSION)


# ----- vault lifecycle -----------------------------------------------------

@app.route("/api/status")
def status():
    return jsonify(exists=vault.exists(), unlocked=vault.is_unlocked())


@app.route("/api/setup", methods=["POST"])
def setup():
    master = json_body().get("master", "")
    require_decent_master(master)
    vault.create(master)
    return jsonify(ok=True)


@app.route("/api/unlock", methods=["POST"])
def unlock():
    vault.unlock(json_body().get("master", ""))
    return jsonify(ok=True)


@app.route("/api/lock", methods=["POST"])
def lock():
    vault.lock()
    return jsonify(ok=True)


@app.route("/api/change-master", methods=["POST"])
@require_unlocked
def change_master():
    data = json_body()
    new = data.get("new", "")
    if not isinstance(new, str):
        raise VaultError("New master password must be text.")
    require_decent_master(new)
    vault.change_master(data.get("old", ""), new)
    return jsonify(ok=True)


# ----- backups -----------------------------------------------------------------

@app.route("/api/export", methods=["POST"])
@require_unlocked
def export_backup():
    data = json_body()
    text = vault.export_backup(data.get("master", ""), data.get("backup_password", ""))
    filename = f"vault-backup-{date.today().isoformat()}.json"
    return Response(
        text,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/api/import", methods=["POST"])
@require_unlocked
def import_backup():
    data = json_body()
    backup, password = data.get("backup", ""), data.get("password", "")
    if not isinstance(backup, str) or not isinstance(password, str):
        raise VaultError("Choose a backup file and enter its password.")
    return jsonify(vault.import_backup(backup, password))


# ----- entries: add, search, delete (+ view and edit) -----------------------

@app.route("/api/entries")
@require_unlocked
def list_entries():
    return jsonify(entries=vault.list(request.args.get("q", "")))


@app.route("/api/entries", methods=["POST"])
@require_unlocked
def add_entry():
    return jsonify(entry=vault.add(json_body())), 201


@app.route("/api/entries/<entry_id>/password")
@require_unlocked
def reveal_password(entry_id):
    return jsonify(password=vault.get(entry_id)["password"])


@app.route("/api/entries/<entry_id>", methods=["PUT"])
@require_unlocked
def update_entry(entry_id):
    return jsonify(entry=vault.update(entry_id, json_body()))


@app.route("/api/entries/<entry_id>", methods=["DELETE"])
@require_unlocked
def delete_entry(entry_id):
    vault.delete(entry_id)
    return jsonify(ok=True)


# ----- strength checker (side tool; works even while the vault is locked) --

@app.route("/api/check", methods=["POST"])
def check():
    data = json_body()
    password = data.get("password", "")
    if not isinstance(password, str) or not password:
        raise VaultError("Enter a password to check.")
    # Optional words (entry name, username...) that the password should not contain.
    context = data.get("context", [])
    if not isinstance(context, list):
        context = []
    return jsonify(strength.review(password, [c for c in context if isinstance(c, str)]))


# ----- breach check (optional, only when the user presses the button) -----------

@app.route("/api/breach-check", methods=["POST"])
def breach_check():
    password = json_body().get("password", "")
    if not isinstance(password, str) or not password:
        raise VaultError("Enter a password to check.")
    return jsonify(breach.check_password(password))


@app.route("/api/entries/<entry_id>/breach-check", methods=["POST"])
@require_unlocked
def entry_breach_check(entry_id):
    json_body()
    # The stored password is read here, on the server. It is never sent to the browser.
    return jsonify(breach.check_password(vault.get(entry_id)["password"]))


@app.route("/api/generate", methods=["POST"])
def generate():
    return jsonify(password=strength.generate_password(16))


if __name__ == "__main__":
    # debug stays off: Flask's debugger must never run next to a password vault.
    app.run(host="127.0.0.1", port=5000, debug=False)
