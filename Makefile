VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

.PHONY: setup install run test clean reset-vault

setup:
	python3 -m venv $(VENV)

install:
	$(PIP) install -r requirements.txt

run:
	$(PYTHON) app.py

test:
	$(PYTHON) -m pytest -q

clean:
	rm -rf __pycache__ tests/__pycache__ .pytest_cache

# Moves the vault aside (never deletes it) so you can start a fresh one.
reset-vault:
	@if [ -f vault.enc ]; then \
		mv vault.enc vault.enc.old-$$(date +%Y%m%d-%H%M%S); \
		echo "Old vault moved aside. Run 'make run' to create a new one."; \
	else \
		echo "No vault.enc in this folder."; \
	fi
