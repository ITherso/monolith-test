.PHONY: run test worker db-upgrade db-current db-revision update-badge

run:
	python3 cyber.py

test:
	pytest

lint:
	ruff check .

format:
	ruff format .

typecheck:
	mypy .

precommit:
	pre-commit install

worker:
	MONOLITH_QUEUE=rq ./run_rq_worker.sh

db-upgrade:
	python3 cyber.py --db-upgrade

db-current:
	python3 cyber.py --db-current

db-revision:
	python3 cyber.py --db-revision "$(message)"

update-badge:
	python3 scripts/update_coverage_badge.py
