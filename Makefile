
test:
	pytest test.py

lint:
	ruff pyramid_csp test.py
	black --check pyramid_csp test.py
	isort --check pyramid_csp test.py

format:
	isort pyramid_csp test.py
	black pyramid_csp test.py
	ruff --fix pyramid_csp test.py
