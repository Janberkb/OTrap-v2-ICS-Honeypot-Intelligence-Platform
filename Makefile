# OTrap v2.0 — Makefile
# Usage: make help

SHELL := /bin/bash
.DEFAULT_GOAL := help

SENSOR_DIR  := ./sensor
MANAGER_DIR := ./manager
PROTO_DIR   := ./proto
UI_DIR      := ./ui
VERSION     ?= 2.0.0
GO_BIN      := $(shell go env GOPATH)/bin
PROTO_VENV  := ./.tools/proto-venv
PROTO_PY    := $(PROTO_VENV)/bin/python

.PHONY: help proto build-sensor build-manager build-ui dev up down install-manager test smoke ui-smoke s7-test hmi-test clean

# ─── Help ─────────────────────────────────────────────────────────────────────

help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n\nTargets:\n"} \
	/^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# ─── Proto generation ─────────────────────────────────────────────────────────

proto: ## Regenerate committed gRPC stubs from sensor.proto (maintainer task)
	@command -v protoc >/dev/null || (echo "ERROR: protoc is required (install protobuf-compiler)." && exit 1)
	@mkdir -p $(GO_BIN)
	@if [ ! -x "$(GO_BIN)/protoc-gen-go" ]; then \
		echo "→ Installing protoc-gen-go..."; \
		go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.34.1; \
	fi
	@if [ ! -x "$(GO_BIN)/protoc-gen-go-grpc" ]; then \
		echo "→ Installing protoc-gen-go-grpc..."; \
		go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.3.0; \
	fi
	@if [ ! -x "$(PROTO_PY)" ]; then \
		echo "→ Creating local proto tool venv at $(PROTO_VENV)..."; \
		python3 -m venv $(PROTO_VENV); \
		$(PROTO_PY) -m pip install grpcio-tools==1.62.0 protobuf==4.25.3; \
	fi
	@echo "→ Generating Go stubs..."
	@mkdir -p $(SENSOR_DIR)/proto/sensorv1
	PATH="$(GO_BIN):$$PATH" protoc -I=$(PROTO_DIR) \
		--go_out=$(SENSOR_DIR)/proto/sensorv1 \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(SENSOR_DIR)/proto/sensorv1 \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/sensor.proto
	@echo "→ Generating Python stubs..."
	@mkdir -p $(MANAGER_DIR)/grpc
	$(PROTO_PY) -m grpc_tools.protoc \
		-I$(PROTO_DIR) \
		--python_out=$(MANAGER_DIR)/grpc \
		--grpc_python_out=$(MANAGER_DIR)/grpc \
		$(PROTO_DIR)/sensor.proto
	sed -i 's/^import sensor_pb2/from manager.grpc import sensor_pb2/' \
		$(MANAGER_DIR)/grpc/sensor_pb2_grpc.py
	@echo "✓ Proto generation complete"

# ─── Build ────────────────────────────────────────────────────────────────────

build-sensor: ## Build Go sensor binary from committed proto stubs
	cd $(SENSOR_DIR) && \
	CGO_ENABLED=0 go build -ldflags="-w -s -X main.version=$(VERSION)" \
		-o bin/sensor ./cmd/sensor
	@echo "✓ Sensor binary: sensor/bin/sensor"

build-manager: ## Build Manager Docker image
	docker build -t otrap-manager:latest $(MANAGER_DIR)

build-ui: ## Build UI Docker image
	docker build -t otrap-ui:latest $(UI_DIR)

build: build-manager build-ui ## Build all Docker images (sensor built inside container)
	docker compose build sensor
	@echo "✓ All images built"

# ─── Development ──────────────────────────────────────────────────────────────

dev: ## Start full stack in dev mode (hot-reload)
	@cp -n .env.example .env 2>/dev/null || true
	docker compose -f docker-compose.yml -f docker-compose.dev.yml up

up: ## Start full production stack
	@[ -f .env ] || (echo "ERROR: .env not found. Copy .env.example and fill in values." && exit 1)
	docker compose up -d
	@echo "✓ OTrap stack started"
	@echo "  Management UI:  http://localhost:3000"
	@echo "  Manager API:    http://localhost:8080"
	@echo "  S7 honeypot:    :102"

install-manager: ## Bootstrap .env, start postgres/redis/manager/ui, and persist gRPC CA
	./scripts/install_manager.sh

down: ## Stop all services
	docker compose down

logs: ## Follow all service logs
	docker compose logs -f

# ─── Testing ──────────────────────────────────────────────────────────────────

test: ## Run Go sensor unit tests
	cd $(SENSOR_DIR) && go test ./...

smoke: ## Run full stack smoke test
	@[ "$(ADMIN_PASS)" ] || (echo "Set ADMIN_PASS=yourpassword" && exit 1)
	ADMIN_PASS=$(ADMIN_PASS) python3 scripts/smoke_test.py

ui-smoke: ## Run browser login smoke test
	@[ "$(ADMIN_PASS)" ] || (echo "Set ADMIN_PASS=yourpassword" && exit 1)
	mkdir -p output/playwright
	cd $(UI_DIR) && { [ -d node_modules ] || npm ci --prefer-offline; }
	cd $(UI_DIR) && npx playwright install chromium
	cd $(UI_DIR) && ADMIN_PASS=$(ADMIN_PASS) ADMIN_USER=$${ADMIN_USER:-admin} UI_URL=$${UI_URL:-http://localhost:3000} node scripts/ui_login_smoke.mjs

s7-test: ## Run S7 exploit simulation
	python3 scripts/verify_s7_exploit.py \
		--host $${S7_HOST:-127.0.0.1} \
		--api $${API:-http://localhost:8080}

hmi-test: ## Run HMI OWASP probe verification
	python3 scripts/verify_hmi.py --host $${HMI_HOST:-http://127.0.0.1:80}

# ─── Sensor token helper ──────────────────────────────────────────────────────

sensor-token: ## Generate a sensor join token (requires ADMIN_PASS)
	@[ "$(SENSOR_NAME)" ] || (echo "Set SENSOR_NAME=my-sensor" && exit 1)
	@[ "$(ADMIN_PASS)" ] || (echo "Set ADMIN_PASS=yourpassword" && exit 1)
	@echo "→ Logging in and generating token..."
	@ADMIN_PASS=$(ADMIN_PASS) ADMIN_USER=$${ADMIN_USER:-admin} SENSOR_NAME=$(SENSOR_NAME) API=$${API:-http://localhost:8080} python3 scripts/generate_sensor_token.py

# ─── Cleanup ──────────────────────────────────────────────────────────────────

clean: ## Remove build artifacts
	rm -f $(SENSOR_DIR)/bin/sensor
	rm -f $(SENSOR_DIR)/proto/sensorv1/sensor.pb.go
	rm -f $(SENSOR_DIR)/proto/sensorv1/sensor_grpc.pb.go
	rm -f $(MANAGER_DIR)/grpc/sensor_pb2.py
	rm -f $(MANAGER_DIR)/grpc/sensor_pb2_grpc.py
	@echo "✓ Clean"

lint: ## Run linters
	cd $(SENSOR_DIR) && go vet ./...
	cd $(SENSOR_DIR) && go build ./...
	cd $(MANAGER_DIR) && python3 -m py_compile main.py config.py
	@echo "✓ Lint passed"
