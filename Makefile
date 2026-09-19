VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

.PHONY: setup install run clean

setup:
	python3 -m venv $(VENV)

install:
	$(PIP) install -r requirements.txt

run:
	. $(VENV)/bin/activate && $(PYTHON) app.py

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
