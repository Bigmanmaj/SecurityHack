PY ?= python3
EPISODE ?= episode

.PHONY: install test demo record verify investigate tamper golden clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

record:
	rm -rf $(EPISODE)
	$(PY) -m agent.rag --scenario poisoned --out $(EPISODE)

verify:
	$(PY) verify_episode.py $(EPISODE)

investigate:
	$(PY) -m investigator.cli $(EPISODE)

tamper:
	$(PY) demo/tamper.py $(EPISODE)/records/000012.json

demo:
	@bash demo/demo.sh $(EPISODE)

golden:
	rm -rf episodes/golden
	$(PY) -m agent.rag --scenario poisoned --out episodes/golden
	$(PY) -m investigator.cli episodes/golden
	$(PY) verify_episode.py episodes/golden
	rm -f episodes/golden/.recorder-state.json
	@echo "golden episode rebuilt (recorder state dropped: it is now append-closed)"

clean:
	rm -rf $(EPISODE) .pytest_cache **/__pycache__
