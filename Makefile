PY ?= python3
EPISODE ?= episode

.PHONY: install test demo web record verify investigate tamper golden clean

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

# The browser demo. Loopback only: this server hands out a write endpoint on
# purpose, and it has no business being reachable from the network.
web:
	@echo "  http://127.0.0.1:$${FR_PORT:-8000}   —   keys: 1 run · 2 investigate · 3 tamper · R reset"
	$(PY) -m web.app

golden:
	rm -rf episodes/golden
	$(PY) -m agent.rag --scenario poisoned --out episodes/golden
	$(PY) -m investigator.cli episodes/golden
	rm -f episodes/golden/.recorder-state.json
	$(PY) demo/publish_witness.py episodes/golden > episodes/golden.witness
	$(PY) verify_episode.py episodes/golden
	@echo "golden episode rebuilt; update episodes/golden.witness header by hand if the prose moved"

clean:
	rm -rf $(EPISODE) .pytest_cache **/__pycache__
