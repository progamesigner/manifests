.DEFAULT_GOAL := help

.PHONY: apply deploy dry-run validate help

apply: deploy

deploy:
	kustomize build . | kubectl apply -f -

dry-run:
	kustomize build . | kubectl apply --dry-run=client -f -

validate:
	kustomize build . | kubectl apply --dry-run=server -f -

help:
	@echo "Available targets:"
	@echo "  apply     - Alias for deploy"
	@echo "  deploy    - Apply kubernetes manifests using kustomize"
	@echo "  dry-run   - Show what would be applied without making changes"
	@echo "  validate  - Validate manifests against the server"
	@echo "  help      - Display this help message"
