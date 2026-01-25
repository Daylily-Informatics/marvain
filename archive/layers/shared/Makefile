# SAM build for SharedDependenciesLayer
# SAM sets ARTIFACTS_DIR for build outputs.

build-SharedDependenciesLayer:
	mkdir -p "$(ARTIFACTS_DIR)/python"
	python3 -m pip install -r requirements.txt -t "$(ARTIFACTS_DIR)/python"
	rm -rf "$(ARTIFACTS_DIR)/python/agent_core"
	cp -R python/agent_core "$(ARTIFACTS_DIR)/python/agent_core"
