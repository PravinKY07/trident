# TRIDENT — build and run entry points
# The user in Africa runs three commands: clone, `make setup`, `python -m trident`.

.PHONY: setup run test clean help

help:
	@echo "TRIDENT — available targets:"
	@echo "  make setup    Install dependencies and fetch the model"
	@echo "  make run      Start the TRIDENT service"
	@echo "  make test     Run the test suite"
	@echo "  make clean    Remove build artifacts and the downloaded model"

setup:
	python -m pip install --upgrade pip
	python -m pip install -r requirements.txt
	python -m trident.setup.download_model
	@echo "[TRIDENT] Setup complete. Run 'make run' to start."

run:
	python -m trident

test:
	python -m pytest tests/ -v

clean:
	rm -rf models/*.onnx models/*.bin models/*.safetensors
	rm -rf __pycache__ */__pycache__ */*/__pycache__
	rm -rf .pytest_cache .ruff_cache
	@echo "[TRIDENT] Cleaned."
