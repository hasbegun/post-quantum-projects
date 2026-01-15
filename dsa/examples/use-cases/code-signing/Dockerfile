# Post-Quantum Code Signing Container
#
# Build:
#   docker build -t pqc-code-signing -f Dockerfile .
#
# Usage:
#   docker run --rm -v $(pwd):/work pqc-code-signing sign --key /work/key.key --file /work/release.tar.gz
#   docker run --rm -v $(pwd):/work pqc-code-signing verify --key /work/key.key --file /work/release.tar.gz

FROM python:3.11-slim

LABEL maintainer="PQC Code Signing"
LABEL description="Post-quantum code signing and verification tools"
LABEL version="1.0"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy the PQC library source
COPY src/py /app/src/py

# Copy the code signing tools
COPY examples/use-cases/code-signing/*.py /app/tools/

# Install Python dependencies
RUN pip install --no-cache-dir pycryptodome

# Set Python path
ENV PYTHONPATH="/app/src/py:${PYTHONPATH}"

# Create wrapper script
RUN echo '#!/bin/bash\n\
case "$1" in\n\
    sign)\n\
        shift\n\
        python /app/tools/sign_release.py "$@"\n\
        ;;\n\
    verify)\n\
        shift\n\
        python /app/tools/verify_release.py "$@"\n\
        ;;\n\
    keygen)\n\
        shift\n\
        python /app/tools/keygen.py "$@"\n\
        ;;\n\
    *)\n\
        echo "PQC Code Signing Tool"\n\
        echo ""\n\
        echo "Usage: docker run pqc-code-signing <command> [options]"\n\
        echo ""\n\
        echo "Commands:"\n\
        echo "  sign    Sign a file"\n\
        echo "  verify  Verify a signature"\n\
        echo ""\n\
        echo "Examples:"\n\
        echo "  docker run --rm -v \$(pwd):/work pqc-code-signing sign --key /work/secret.key --file /work/release.tar.gz"\n\
        echo "  docker run --rm -v \$(pwd):/work pqc-code-signing verify --key /work/public.key --file /work/release.tar.gz"\n\
        ;;\n\
esac' > /usr/local/bin/pqc && chmod +x /usr/local/bin/pqc

ENTRYPOINT ["pqc"]
CMD ["--help"]
