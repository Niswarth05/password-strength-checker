# Vault: a local password manager

A small password manager that runs on your own computer. Your logins live in one
encrypted file, and nothing is ever sent over the internet.

**Version 2.0.** This is a rewrite of the v1 password strength checker. The password
manager is now the main feature. The strength checker is a side tool.

## Features

### Password manager (main feature)

- **Add** an entry: name, username or email, password, website and notes
- **Search** across name, username, website and notes (passwords are never searched)
- **Delete** an entry, with a confirmation step
- **View and edit** entries. Passwords stay hidden until you press Show
- **Copy** a username or password. Copied passwords are cleared from the clipboard after 20 seconds
- **Lock** the vault by hand, or it locks itself after 5 idle minutes

### Strength check (side tool)

Open it from the top bar, or from the Add entry form.

1. Enter a password and press Check.
2. You get a rating, the reasons behind it, and a checklist.
3. If the password is weak, you get a stronger password **based on the one you entered**.
   You can copy it, check it again, use it in the entry form, or swap it for a fully random one.

A password counts as weak when it rates **Very weak** or **Weak**. To also get suggestions
for **Medium** passwords, add `"MEDIUM"` to `WEAK_LEVELS` in `strength.py`.

## How your data is protected

| Part | What it does |
| --- | --- |
| Master password | Never saved. It is turned into an encryption key with **scrypt**. |
| Encryption | The whole vault is encrypted with **Fernet** (AES + HMAC). A wrong master password fails to decrypt. |
| Vault file | `vault.enc`, readable only by you (`chmod 600`), written atomically so it can't be left half-saved. |
| Local only | The server listens on `127.0.0.1` and rejects requests for any other hostname. |
| Browser | Strict Content-Security-Policy, no external scripts, fonts or requests. Entry text is never rendered as HTML. |
| Guessing | After 5 wrong master passwords, unlocking waits 30 seconds. |

v1 used **bcrypt**. That is the right tool for *checking* a password, but a password manager
has to get your passwords *back*, so v2 uses encryption (scrypt + Fernet) instead.

### Limits you should know about

- **There is no master password recovery.** If you forget it, the vault cannot be opened.
- The decrypted vault is held in this program's memory while unlocked. Python can't reliably wipe
  memory, so lock the vault when you step away.
- Back up `vault.enc` yourself. It is safe to copy because it is encrypted.
- This is a learning project. It has not been security audited, so don't make it the only home
  for passwords you can't afford to lose.
- The strength rating is rule-based. It catches common words, sequences, repeats and
  "word + number" patterns, but it can still rate some guessable passwords too high.
  Adding the `zxcvbn` library would be a good next step.
- A suggestion built from your password keeps its original shape, which makes it easier to
  remember and a little easier to guess than a fully random one.

## Run it

```bash
make setup      # create the virtual environment (once)
make install    # install Flask, cryptography and pytest (once)
make run        # start the app
```

Then open **http://127.0.0.1:5000** (or `http://localhost:5000`) in your browser.
The first time, you'll be asked to create a master password of at least 12 characters.

Run the tests with `make test`.

To keep the vault somewhere else, set `VAULT_FILE`:

```bash
VAULT_FILE=~/secure/my-vault.enc make run
```

## Project structure

```text
password-manager-v2/
├── app.py              Flask routes and request safety checks
├── vault.py            Encrypted vault: create, unlock, add, search, delete
├── strength.py         Strength checker and "based on yours" suggestions
├── templates/
│   └── index.html
├── static/
│   ├── app.js          Interface logic
│   ├── style.css
│   └── fonts/          Bundled fonts, so nothing loads from the internet
├── tests/              pytest tests for the vault, checker and API
├── Makefile
├── requirements.txt
└── README.md
```

## Technologies

Python 3, Flask, cryptography (scrypt and Fernet), HTML, CSS, JavaScript, pytest.
Fonts: Bricolage Grotesque and JetBrains Mono (SIL Open Font License).

## Ideas for later

- Import and export (encrypted backup)
- Change master password
- Check entries against known breaches
- Tags or folders
- Replace the rule-based rating with `zxcvbn`
