.PHONY: up-pl1 up-pl3 eval down

up-pl1:
	PARANOIA_LEVEL=1 docker compose up -d --build

up-pl3:
	PARANOIA_LEVEL=3 docker compose up -d --build

eval:
	python3 tests/waf_eval.py --mode compare --out reports/evaluation_results.md

down:
	docker compose down
