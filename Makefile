.PHONY: test-unit test-unit-short test-unit-installer

INSTALLER_COVERAGE_MIN ?= 75

test-unit-installer:
	go test ./internal/installer/... -count=1 -coverprofile=installer-coverage.out
	@COVERAGE=$$(go tool cover -func=installer-coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "installer coverage: $$COVERAGE% (min $(INSTALLER_COVERAGE_MIN)%)"; \
	awk "BEGIN {exit !($$COVERAGE >= $(INSTALLER_COVERAGE_MIN))}"

test-unit:
	go test ./... -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

test-unit-quality-gate: test-unit-installer test-unit

test-unit-short: test-unit
