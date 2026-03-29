build:
	@echo "Compiling injectdb (dev)..."
	uv run maturin develop

release:
	@echo "Compiling injectdb (release)..."
	uv run maturin build --release

unittest:
	@echo "Running Rust tests..."
	cargo test --release

	@echo "Running Python tests..."
	uv run pytest

test-wild:
	@echo "Running Rust tests..."
	cargo test --release -- --include-ignored test_validate_query_dataset --nocapture;

update:
	@echo "Updating dependencies..."
	cargo update

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf target/ dist/ *.egg-info
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

prune:
	git fetch -p && for branch in $$(git branch -vv | grep ': gone]' | awk '{print $$1}'); do git branch -D $$branch; done
