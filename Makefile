VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip

.PHONY: setup install run test clean

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
