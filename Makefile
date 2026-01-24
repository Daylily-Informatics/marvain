.PHONY: build deploy logs

build:
	sam build

deploy:
	sam deploy --guided

logs:
	@echo "Use: sam logs -n HubApiFunction --tail"
