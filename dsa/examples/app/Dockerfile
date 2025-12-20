# Dockerfile for Post-Quantum DSA Demo Application
#
# This image contains both the DSA library and the demo app.

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy DSA source code
COPY src/py/ ./src/py/

# Copy demo app
COPY examples/app/ ./examples/app/

# Install the DSA package
COPY pyproject.toml .
COPY README.md .
RUN pip install -e .

# Default command
CMD ["python", "--version"]
