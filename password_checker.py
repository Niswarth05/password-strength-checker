import getpass
import math
import secrets
import string
import bcrypt


# Commonly used passwords
COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "iloveyou",
    "password123!",
    "Password123!",
}


HASH_FILE = "password.hash"


def check_length(password):
    return len(password) >= 12


def check_uppercase(password):
    for char in password:
        if char.isupper():
            return True

    return False


def check_lowercase(password):
    for char in password:
        if char.islower():
            return True

    return False


def check_number(password):
    for char in password:
        if char.isdigit():
            return True

    return False


def check_special_character(password):
    for char in password:
        if not char.isalnum():
            return True

    return False


def check_common_password(password):
    return password.lower() in {
        common_password.lower()
        for common_password in COMMON_PASSWORDS
    }


def calculate_entropy(password):
    character_pool = 0

    has_lowercase = False
    has_uppercase = False
    has_number = False
    has_special = False

    for char in password:
        if char.islower():
            has_lowercase = True
        elif char.isupper():
            has_uppercase = True
        elif char.isdigit():
            has_number = True
        else:
            has_special = True

    if has_lowercase:
        character_pool += 26

    if has_uppercase:
        character_pool += 26

    if has_number:
        character_pool += 10

    if has_special:
        character_pool += 32

    if character_pool == 0:
        return 0

    entropy = len(password) * math.log2(character_pool)

    return entropy


def calculate_score(password):
    score = 0
    reasons = []

    length_check = check_length(password)
    uppercase_check = check_uppercase(password)
    lowercase_check = check_lowercase(password)
    number_check = check_number(password)
    special_check = check_special_character(password)
    common_check = check_common_password(password)

    if length_check:
        score += 1
    else:
        reasons.append(
            "Password should be at least 12 characters long."
        )

    if uppercase_check:
        score += 1
    else:
        reasons.append(
            "Add at least one uppercase letter."
        )

    if lowercase_check:
        score += 1
    else:
        reasons.append(
            "Add at least one lowercase letter."
        )

    if number_check:
        score += 1
    else:
        reasons.append(
            "Add at least one number."
        )

    if special_check:
        score += 1
    else:
        reasons.append(
            "Add at least one special character."
        )

    checks = {
        "Length: 12+ characters": length_check,
        "Uppercase letter": uppercase_check,
        "Lowercase letter": lowercase_check,
        "Number": number_check,
        "Special character": special_check,
    }

    return score, reasons, checks, common_check


def get_strength(score, common_check):
    if common_check:
        return "WEAK"

    if score <= 1:
        return "VERY WEAK"
    elif score == 2:
        return "WEAK"
    elif score == 3:
        return "MEDIUM"
    elif score == 4:
        return "STRONG"
    else:
        return "VERY STRONG"


def generate_password(length=16):
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    special = string.punctuation

    password_characters = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(numbers),
        secrets.choice(special),
    ]

    all_characters = lowercase + uppercase + numbers + special

    for _ in range(length - 4):
        password_characters.append(
            secrets.choice(all_characters)
        )

    secrets.SystemRandom().shuffle(password_characters)

    return "".join(password_characters)


def hash_password(password):
    password_bytes = password.encode("utf-8")

    salt = bcrypt.gensalt()

    password_hash = bcrypt.hashpw(
        password_bytes,
        salt
    )

    return password_hash.decode("utf-8")


def verify_password(password, password_hash):
    password_bytes = password.encode("utf-8")
    hash_bytes = password_hash.encode("utf-8")

    return bcrypt.checkpw(
        password_bytes,
        hash_bytes
    )


def save_hash(password_hash):
    with open(HASH_FILE, "w") as file:
        file.write(password_hash)


def load_hash():
    try:
        with open(HASH_FILE, "r") as file:
            return file.read().strip()

    except FileNotFoundError:
        return None


def check_password():
    print("\n" + "=" * 50)
    print("             CHECK PASSWORD")
    print("=" * 50)

    password = getpass.getpass("\nEnter your password: ")

    score, reasons, checks, common_check = calculate_score(password)

    strength = get_strength(score, common_check)

    entropy = calculate_entropy(password)

    print("\n" + "-" * 50)
    print(f"Password Score: {score}/5")
    print(f"Strength: {strength}")
    print(f"Estimated Entropy: {entropy:.1f} bits")
    print("-" * 50)

    print("\nSecurity Checks:")

    for check, passed in checks.items():
        if passed:
            print(f"✓ {check}")
        else:
            print(f"✗ {check}")

    print("\nCommon Password Check:")

    if common_check:
        print("✗ Password is commonly used.")
    else:
        print("✓ Password was not found in our common-password list.")

    if reasons:
        print("\nHow to improve:")

        for reason in reasons:
            print(f"- {reason}")

    if common_check:
        print("\n⚠ Security Warning:")
        print("This password is commonly used and should be avoided.")

    if not reasons and not common_check:
        print("\n✓ Your password passed all checks!")

    print("\n" + "=" * 50)


def password_generator():
    print("\n" + "=" * 50)
    print("           SECURE PASSWORD GENERATOR")
    print("=" * 50)

    while True:
        try:
            length = int(
                input("\nEnter password length (12-64): ")
            )

            if 12 <= length <= 64:
                break

            print("Please enter a length between 12 and 64.")

        except ValueError:
            print("Please enter a valid number.")

    password = generate_password(length)

    print("\nGenerated Password:")
    print(password)

    print("\n" + "=" * 50)


def hash_password_menu():
    print("\n" + "=" * 50)
    print("             PASSWORD HASHING")
    print("=" * 50)

    password = getpass.getpass("\nEnter password to hash: ")

    password_hash = hash_password(password)

    save_hash(password_hash)

    print("\n✓ Password hashed successfully.")
    print(f"✓ Hash saved to: {HASH_FILE}")

    print("\nStored bcrypt hash:")
    print(password_hash)

    print("\n⚠ The original password is not stored.")

    print("=" * 50)


def verify_saved_password():
    print("\n" + "=" * 50)
    print("          VERIFY SAVED PASSWORD")
    print("=" * 50)

    password_hash = load_hash()

    if password_hash is None:
        print("\n✗ No saved password hash found.")
        print("Use 'Hash Password' first.")

        print("=" * 50)
        return

    password = getpass.getpass(
        "\nEnter password to verify: "
    )

    try:
        if verify_password(password, password_hash):
            print("\n✓ Password matches the saved hash.")
        else:
            print("\n✗ Password does not match.")

    except ValueError:
        print("\n✗ Saved hash is invalid.")

    print("=" * 50)


def main():
    while True:
        print("\n" + "=" * 50)
        print("          PASSWORD SECURITY TOOL")
        print("=" * 50)

        print("\n1. Check Password")
        print("2. Generate Password")
        print("3. Hash & Save Password")
        print("4. Verify Saved Password")
        print("5. Exit")

        choice = input("\nChoose an option: ")

        if choice == "1":
            check_password()

        elif choice == "2":
            password_generator()

        elif choice == "3":
            hash_password_menu()

        elif choice == "4":
            verify_saved_password()

        elif choice == "5":
            print("\nGoodbye!")
            break

        else:
            print("\nInvalid option. Please choose 1-5.")


if __name__ == "__main__":
    main()