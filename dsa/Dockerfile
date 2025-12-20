FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/py/ ./src/py/
COPY tests/py/ ./tests/py/
COPY examples/py/ ./examples/py/
COPY pyproject.toml .
COPY README.md .

# Install the package
RUN pip install -e .

# Default command runs tests
CMD ["python", "-m", "pytest", "tests/py/", "-v"]
