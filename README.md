# Vault: a local password manager

A small password manager that runs on your own computer. Your logins live in one
encrypted file, and nothing is ever sent over the internet.

**Version 2.1.** The password manager is the main feature. The strength checker is a side tool.

## Features

### Password manager (main feature)

- **Add** an entry: name, username or email, password, website and notes
- **Search** across name, username, website and notes (passwords are never searched)
- **Delete** an entry, with a confirmation step
- **View and edit** entries. Passwords stay hidden until you press Show
- **Copy** a username or password. Copied passwords are cleared from the clipboard after 20 seconds
- **Lock** the vault by hand, or it locks itself after 5 idle minutes

### Settings (new in 2.1)

- **Change master password.** Re-encrypts the whole vault with a new password and a fresh salt.
  You must enter the current password first, and the new one must not be easy to guess.
- **Export an encrypted backup.** Downloads every entry as one file, encrypted with a separate
  backup password. You must re-enter your master password to export.
- **Import a backup.** Adds entries from a backup file. An entry is skipped if you already have
  one with the same name and username, and nothing is ever overwritten or removed.

### Strength check (side tool)

Open it from the top bar, or from the Add entry form.

1. Enter a password and press Check.
2. You get a rating, an estimated time to crack, and tips written for that specific password.
3. If the password is weak, you get a stronger password **based on the one you entered**.
   You can copy it, check it again, use it in the entry form, or swap it for a fully random one.

Ratings come from [zxcvbn](https://github.com/dwolfhub/zxcvbn-python), which looks for what attackers
really try first: common passwords, dictionary words, names, dates, keyboard patterns like `qwerty`,
sequences like `1234`, repeats, and swaps like `p@ssw0rd`. From the Add entry form, the entry's name and
username are also treated as guessable words.

A password counts as weak when it rates **Very weak** or **Weak**. To also get suggestions
for **Medium** passwords, add `"MEDIUM"` to `WEAK_LEVELS` in `strength.py`.

## How your data is protected

| Part | What it does |
| --- | --- |
| Master password | Never saved. It is turned into an encryption key with **scrypt**. |
| Encryption | The whole vault is encrypted with **Fernet** (AES + HMAC). A wrong master password fails to decrypt. |
| Vault file | `vault.enc`, readable only by you (`chmod 600`), written atomically so it can't be left half-saved. |
| Backups | Encrypted the same way, with their own password and salt. A backup file shows no names, usernames or passwords. |
| Imported files | Treated as untrusted: encryption settings are bounds-checked and every entry is validated. |
| Local only | The server listens on `127.0.0.1` and rejects requests for any other hostname. |
| Browser | Strict Content-Security-Policy, no external scripts, fonts or requests. Entry text is never rendered as HTML. |
| Guessing | After 5 wrong master passwords (at unlock, export or change), the vault waits 30 seconds. |

### Limits you should know about

- **There is no master password recovery.** If you forget it, the vault cannot be opened.
  The same goes for a backup password.
- The decrypted vault is held in this program's memory while unlocked. Python can't reliably wipe
  memory, so lock the vault when you step away.
- Changing the master password does not change old backups. They stay protected by the backup password
  they were made with.
- This is a learning project. It has not been security audited, so don't make it the only home
  for passwords you can't afford to lose.
- No rating is perfect. zxcvbn is cautious with random-looking text it cannot recognise, and it only
  rates the first 72 characters of very long input.
- A suggestion built from your password keeps its original shape, which makes it easier to
  remember and a little easier to guess than a fully random one.

## Run it

```bash
make setup      # create the virtual environment (once)
make install    # install Flask, cryptography, zxcvbn and pytest (once)
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
├── app.py              Flask routes and request safety checks
├── vault.py            Encrypted vault: entries, change master password, backups
├── strength.py         Strength checker (zxcvbn) and "based on yours" suggestions
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

Python 3, Flask, cryptography (scrypt and Fernet), zxcvbn, HTML, CSS, JavaScript, pytest.
Fonts: Bricolage Grotesque and JetBrains Mono (SIL Open Font License).

## Ideas for later

- Check passwords against known breaches (Have I Been Pwned, k-anonymity)
- Password health report: reused, weak and old passwords
- Two-factor (TOTP) codes
- Tags or folders
- A command-line version that reuses `vault.py`
