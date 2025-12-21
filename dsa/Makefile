.PHONY: build build-py build-cpp test test-py test-cpp \
        test-mldsa test-slhdsa test-mldsa-cpp test-slhdsa-cpp \
        test-kat test-kat-mldsa test-kat-slhdsa \
        test-keygen test-keygen-py test-keygen-cpp \
        dev shell clean help \
        demo-api demo-document demo-compare demo-cpp demo-app demo-app-down \
        cert-mldsa cert-slhdsa \
        keygen keygen-cpp \
        keygen-mldsa44 keygen-mldsa65 keygen-mldsa87 keygen-slhdsa keygen-slhdsa-small \
        keygen-cpp-mldsa44 keygen-cpp-mldsa65 keygen-cpp-mldsa87 keygen-cpp-slhdsa keygen-cpp-slhdsa-small

# Docker image names
IMAGE_NAME_PY := dsa-py
IMAGE_NAME_CPP := dsa-cpp
CONTAINER_NAME := dsa-dev

help:
	@echo "Post-Quantum DSA (FIPS 204 & 205) Makefile"
	@echo "==========================================="
	@echo ""
	@echo "Build:"
	@echo "  make build        - Build all Docker images"
	@echo "  make build-py     - Build Python Docker image"
	@echo "  make build-cpp    - Build C++ Docker image"
	@echo ""
	@echo "Test:"
	@echo "  make test         - Run all tests (Python + C++)"
	@echo "  make test-py      - Run all Python tests"
	@echo "  make test-cpp     - Run all C++ tests"
	@echo "  make test-mldsa   - Run ML-DSA Python tests only"
	@echo "  make test-slhdsa  - Run SLH-DSA Python tests only"
	@echo "  make test-mldsa-cpp   - Run ML-DSA C++ tests only"
	@echo "  make test-slhdsa-cpp  - Run SLH-DSA C++ tests only"
	@echo ""
	@echo "NIST KAT Tests (C++):"
	@echo "  make test-kat         - Run all NIST KAT tests"
	@echo "  make test-kat-mldsa   - Run ML-DSA NIST KAT tests"
	@echo "  make test-kat-slhdsa  - Run SLH-DSA NIST KAT tests"
	@echo ""
	@echo "Keygen Certificate Tests:"
	@echo "  make test-keygen      - Run all keygen certificate tests"
	@echo "  make test-keygen-py   - Run Python keygen tests"
	@echo "  make test-keygen-cpp  - Run C++ keygen certificate tests"
	@echo ""
	@echo "Examples:"
	@echo "  make demo-api      - API authentication (ML-DSA Python)"
	@echo "  make demo-document - Document signing (SLH-DSA Python)"
	@echo "  make demo-compare  - Compare ML-DSA vs SLH-DSA (Python)"
	@echo "  make demo-cpp      - Run C++ ML-DSA + SLH-DSA demo"
	@echo "  make demo-app [ALG=<alg>]  - Multi-container client/server demo"
	@echo "  make demo-app-down - Stop and remove demo app containers"
	@echo ""
	@echo "Certificate Examples (C++):"
	@echo "  make cert-mldsa   - ML-DSA certificate example"
	@echo "  make cert-slhdsa  - SLH-DSA certificate example"
	@echo ""
	@echo "Key Generation:"
	@echo "  make keygen-cpp ALG=<alg> OUT=<name> [options] - Generate keys (C++, faster)"
	@echo "  make keygen ALG=<alg> OUT=<name> [options]     - Generate keys (Python)"
	@echo ""
	@echo "  Output files (in ./keys/ by default):"
	@echo "    <name>_public.key       - Public key"
	@echo "    <name>_secret.key       - Secret key"
	@echo "    <name>_certificate.json - Certificate metadata"
	@echo ""
	@echo "  Algorithms: mldsa44, mldsa65, mldsa87"
	@echo "              slh-shake-128f/s, slh-shake-192f/s, slh-shake-256f/s"
	@echo "              slh-sha2-128f/s, slh-sha2-192f/s, slh-sha2-256f/s"
	@echo ""
	@echo "  Certificate Options (like OpenSSL):"
	@echo "    CN=<name>        Common Name (e.g., CN=api.example.com)"
	@echo "    ORG=<name>       Organization (e.g., ORG='My Company')"
	@echo "    OU=<name>        Organizational Unit"
	@echo "    COUNTRY=<code>   2-letter country code (e.g., COUNTRY=US)"
	@echo "    STATE=<name>     State or Province"
	@echo "    LOCALITY=<name>  City"
	@echo "    EMAIL=<email>    Email address"
	@echo "    DAYS=<n>         Validity period in days (default: 365)"
	@echo "    SERIAL=<hex>     Serial number in hex"
	@echo "    KEYS_DIR=<dir>   Output directory (default: ./keys)"
	@echo ""
	@echo "  Examples:"
	@echo "    make keygen-cpp ALG=mldsa65 OUT=myserver"
	@echo "    # Creates: ./keys/myserver_public.key, ./keys/myserver_secret.key, ..."
	@echo ""
	@echo "    make keygen-cpp ALG=mldsa65 OUT=api CN=api.example.com ORG='My Corp'"
	@echo "    # Creates: ./keys/api_public.key with certificate metadata"
	@echo ""
	@echo "  Shortcut targets (creates ./keys/key_*.key):"
	@echo "    Python:             C++:"
	@echo "    keygen-mldsa44      keygen-cpp-mldsa44"
	@echo "    keygen-mldsa65      keygen-cpp-mldsa65"
	@echo "    keygen-mldsa87      keygen-cpp-mldsa87"
	@echo "    keygen-slhdsa       keygen-cpp-slhdsa"
	@echo "    keygen-slhdsa-small keygen-cpp-slhdsa-small"
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Run Python tests with mounted source"
	@echo "  make shell        - Interactive Python shell"
	@echo "  make clean        - Remove Docker resources"

# Build targets
build: build-py build-cpp

build-py:
	docker build -t $(IMAGE_NAME_PY) -f Dockerfile .

build-cpp:
	docker build -t $(IMAGE_NAME_CPP) -f Dockerfile.cpp .

# Test targets
test: test-py test-cpp

test-py: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/ -v

test-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa

test-mldsa: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/test_mldsa.py -v

test-slhdsa: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/test_slhdsa.py -v --tb=short

test-mldsa-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa

test-slhdsa-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa

# NIST KAT Tests (FIPS 204 & 205 compliance)
test-kat: test-kat-mldsa test-kat-slhdsa

test-kat-mldsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa_kat

test-kat-slhdsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa_kat

# Keygen Certificate Tests
test-keygen: test-keygen-py test-keygen-cpp

test-keygen-py: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/test_keygen.py -v

test-keygen-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_keygen

# Development
dev:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src:ro \
		-v $(PWD)/tests:/app/tests:ro \
		$(IMAGE_NAME_PY) \
		python -m pytest tests/py/ -v

shell: build-py
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -it --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src \
		-v $(PWD)/tests:/app/tests \
		$(IMAGE_NAME_PY) \
		python

# Key generation targets (with mounted volume)
# Usage: make keygen-cpp ALG=mldsa44 OUT=myserver [CN=...] [ORG=...] etc.
# Creates: ./keys/myserver_public.key, ./keys/myserver_secret.key, ./keys/myserver_certificate.json
ALG ?= mldsa44
OUT ?= key
KEYS_DIR ?= ./keys

# Certificate parameters (optional)
CN ?=
ORG ?=
OU ?=
COUNTRY ?=
STATE ?=
LOCALITY ?=
EMAIL ?=
DAYS ?=
SERIAL ?=

# Build certificate options string
CERT_OPTS :=
ifneq ($(CN),)
  CERT_OPTS += --cn "$(CN)"
endif
ifneq ($(ORG),)
  CERT_OPTS += --org "$(ORG)"
endif
ifneq ($(OU),)
  CERT_OPTS += --ou "$(OU)"
endif
ifneq ($(COUNTRY),)
  CERT_OPTS += --country "$(COUNTRY)"
endif
ifneq ($(STATE),)
  CERT_OPTS += --state "$(STATE)"
endif
ifneq ($(LOCALITY),)
  CERT_OPTS += --locality "$(LOCALITY)"
endif
ifneq ($(EMAIL),)
  CERT_OPTS += --email "$(EMAIL)"
endif
ifneq ($(DAYS),)
  CERT_OPTS += --days $(DAYS)
endif
ifneq ($(SERIAL),)
  CERT_OPTS += --serial "$(SERIAL)"
endif

# Python key generation
keygen: build-py
	@mkdir -p $(KEYS_DIR)
	docker run --rm -v $(PWD)/$(KEYS_DIR):/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py $(ALG) /keys/$(OUT) $(CERT_OPTS)

# C++ key generation (faster)
keygen-cpp: build-cpp
	@mkdir -p $(KEYS_DIR)
	docker run --rm -v $(PWD)/$(KEYS_DIR):/keys $(IMAGE_NAME_CPP) ./build/keygen $(ALG) /keys/$(OUT) $(CERT_OPTS)

# Shortcut targets for common algorithms (Python)
keygen-mldsa44: ALG=mldsa44
keygen-mldsa44: keygen

keygen-mldsa65: ALG=mldsa65
keygen-mldsa65: keygen

keygen-mldsa87: ALG=mldsa87
keygen-mldsa87: keygen

keygen-slhdsa: ALG=slh-shake-128f
keygen-slhdsa: keygen

keygen-slhdsa-small: ALG=slh-shake-128s
keygen-slhdsa-small: keygen

# Shortcut targets for common algorithms (C++)
keygen-cpp-mldsa44: ALG=mldsa44
keygen-cpp-mldsa44: keygen-cpp

keygen-cpp-mldsa65: ALG=mldsa65
keygen-cpp-mldsa65: keygen-cpp

keygen-cpp-mldsa87: ALG=mldsa87
keygen-cpp-mldsa87: keygen-cpp

keygen-cpp-slhdsa: ALG=slh-shake-128f
keygen-cpp-slhdsa: keygen-cpp

keygen-cpp-slhdsa-small: ALG=slh-shake-128s
keygen-cpp-slhdsa-small: keygen-cpp

# Demo targets
demo-api: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/api_authentication.py

demo-document: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/document_signing.py

demo-compare: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/comparison.py

demo-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/dsa_demo

# Certificate example targets (C++)
cert-mldsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/mldsa_cert_example

cert-slhdsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/slhdsa_cert_example

# Multi-container demo app
# Usage: make demo-app [ALG=mldsa44]
demo-app:
	cd examples/app && ALGORITHM=$(ALG) docker-compose up --build --abort-on-container-exit
	cd examples/app && docker-compose down

demo-app-down:
	cd examples/app && docker-compose down --rmi local

# Cleanup
clean:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_PY) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_CPP) 2>/dev/null || true
	@echo "Cleaned up Docker resources"
