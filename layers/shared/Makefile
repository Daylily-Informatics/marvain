# SAM build Makefile for SharedDependenciesLayer
# Installs root requirements.txt into the Layer's python/ directory and
# copies the agent_core package into the Layer.
#
# SAM sets ARTIFACTS_DIR to the layer build output folder (e.g. /asset-output).

.PHONY: build-SharedDependenciesLayer

build-SharedDependenciesLayer:
	@echo "Building SharedDependenciesLayer into $(ARTIFACTS_DIR)"
	mkdir -p "$(ARTIFACTS_DIR)/python"
	# Keep the layer lean: rely on the Lambda runtime for transitive deps (botocore, etc).
	python3 -m pip install -r ../../requirements.txt -t "$(ARTIFACTS_DIR)/python" --no-deps
	rm -rf "$(ARTIFACTS_DIR)/python/agent_core"
	cp -R ../../agent_core "$(ARTIFACTS_DIR)/python/agent_core"
