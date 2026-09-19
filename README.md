# Password Security Tool

A beginner-friendly local cybersecurity web application built with Python and Flask.

The project allows users to analyze password strength, estimate theoretical password entropy, generate secure passwords, and demonstrate bcrypt password hashing and verification.

## Version

Current version: `v1.0.0`

This version is the initial Flask web interface.

## Features

### Password Analyzer

- Checks password length
- Checks for uppercase letters
- Checks for lowercase letters
- Checks for numbers
- Checks for special characters
- Detects common passwords
- Calculates a simplified theoretical entropy estimate
- Provides suggestions for improving weak passwords

### Secure Password Generator

- Generates passwords from 12–64 characters
- Uses Python's `secrets` module
- Includes lowercase letters
- Includes uppercase letters
- Includes numbers
- Includes special characters
- Allows generated passwords to be copied to the clipboard

### Bcrypt Password Hashing

- Hashes passwords using bcrypt
- Generates a unique salt through bcrypt
- Saves the bcrypt hash locally
- Verifies passwords against the stored hash
- Does not store the original password

### Web Interface

- Built with Flask
- Runs locally on the user's computer
- Minimal cybersecurity-focused interface
- Responsive layout
- No external database required

## Technologies Used

- Python 3
- Flask
- bcrypt
- HTML
- CSS
- JavaScript
- Git
- GitHub
- Kali Linux / Linux

## Project Structure

```text
password-strength-checker/
│
├── static/
│   └── style.css
│
├── templates/
│   └── index.html
│
├── .gitignore
├── Makefile
├── README.md
├── app.py
├── password_checker.py
├── requirements.txt
│
└── .venv/