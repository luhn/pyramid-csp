
lint:
	ruff pyramid_csp
	black --check pyramid_csp
	isort --check pyramid_csp

format:
	isort pyramid_csp
	black pyramid_csp
	ruff --fix pyramid_csp
