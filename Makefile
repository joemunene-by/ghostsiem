.PHONY: install dev test lint serve collect detect run clean

install:
	pip install .

dev:
	pip install -e ".[dev]"

test:
	pytest tests/ -v

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

serve:
	ghostsiem serve

collect:
	ghostsiem collect --config examples/config.yaml

detect:
	ghostsiem detect --rules examples/rules/

run:
	ghostsiem run --config examples/config.yaml

clean:
	rm -rf build/ dist/ *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -f ghostsiem.db ghostsiem.db-wal ghostsiem.db-shm
