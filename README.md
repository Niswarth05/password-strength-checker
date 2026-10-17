# Vault: a local password manager

A small password manager that runs on your own computer. Your logins live in one
encrypted file. Nothing leaves your computer unless you press **Check if leaked**
(see [Breach check](#breach-check-optional)).

**Version 0.2.3.** The password manager is the main feature. The strength checker is a side tool.
The version is shown in Settings and on the unlock screen.

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

### Password health (new in 0.2.3)

Press **Health**, then **Scan vault**. Nothing is scanned until you press the button.

- **Weak:** passwords rated Very weak or Weak by the strength checker. The entry's name and username count as guessable words.
- **Reused:** entries that share the exact same password. Each one lists the others it shares with.
- **Known breached:** filled in only for entries you choose to check. Use **Check for leaks** on one entry, or
  **Check all entries for leaks**, which tells you exactly how many lookups it will send and asks first.
  An entry you haven't checked is never treated as safe: the summary shows "N of M checked".
- **Fix it:** **Open** jumps to the entry. **Generate replacement** opens the edit form with a new random password.
  Change the password on the website first, then press Save entry. Vault cannot change a password on a website for you.
- After you edit, add, delete or import entries, the dashboard tells you the results are out of date. Press **Scan again**.

The scan runs on this computer. Its report holds names and ratings only, never a password, and it is cleared when you lock the vault.
Old passwords are not reported yet, because the vault does not record when a password itself last changed.

### Breach check (optional)

Press **Check if leaked** on an entry, or in the strength check dialog, to see whether a password
has appeared in known data breaches. It uses the
[Have I Been Pwned range API](https://haveibeenpwned.com/API/v3#PwnedPasswords) and keeps your password private:

1. The password is hashed (SHA-1) on your computer.
2. Only the **first 5 characters** of the hash are sent.
3. The service replies with every leaked hash starting with those 5 characters.
4. Your computer looks for the rest of your hash in that list.

The password and its full hash never leave your computer, and nothing is looked up until you press the button.
If you are offline, you get a clear message and nothing else happens. A result of "not found" does not prove
a password is safe. It only means it has not appeared in public leaks.

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
| Local only | The server listens on `127.0.0.1` and rejects requests for any other hostname. The only outside connection is the optional breach check, which sends 5 characters of a hash. |
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

Run the tests with `make test`. To start over with a fresh vault, run `make reset-vault`. It moves
`vault.enc` aside (it never deletes it) and `.gitignore` keeps all `vault.enc*` files out of git.

To keep the vault somewhere else, set `VAULT_FILE`:

```bash
VAULT_FILE=~/secure/my-vault.enc make run
```

## Project structure

```text
├── app.py              Flask routes and request safety checks
├── vault.py            Encrypted vault: entries, change master password, backups
├── strength.py         Strength checker (zxcvbn) and "based on yours" suggestions
├── breach.py           Optional breach check (k-anonymity range lookup)
├── health.py           Password health scan (weak and reused passwords)
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

- Password age: record when each password last changed, then flag old ones
- Passphrase generator
- Import from CSV (Chrome, Firefox, Bitwarden)
- Backup verification
- Tags, folders and favourites
- A command-line version that reuses `vault.py`
- Docker image or pip package for 1.0.0
