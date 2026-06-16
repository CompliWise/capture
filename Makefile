.PHONY: test-unit test-unit-short test-unit-installer test-unit-quality-gate

INSTALLER_COVERAGE_TARGET ?= 75
INSTALLER_COVERAGE_FLOOR ?= 50
# internal/installer/... packages (testfixtures excluded from coverage gate)
INSTALLER_PACKAGES := $(shell go list ./internal/installer/... | grep -v testfixtures)

test-unit-installer:
	go test $(INSTALLER_PACKAGES) -count=1 -coverprofile=installer-coverage.out
	@COVERAGE=$$(go tool cover -func=installer-coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo "installer coverage: $$COVERAGE% (floor $(INSTALLER_COVERAGE_FLOOR)%, target $(INSTALLER_COVERAGE_TARGET)%)"; \
	awk "BEGIN {exit !($$COVERAGE >= $(INSTALLER_COVERAGE_FLOOR))}"; \
	if awk "BEGIN {exit !($$COVERAGE >= $(INSTALLER_COVERAGE_TARGET))}"; then \
		echo "installer coverage meets target $(INSTALLER_COVERAGE_TARGET)%"; \
	else \
		echo "installer coverage below target $(INSTALLER_COVERAGE_TARGET)% — raise via installer story tests"; \
	fi

test-unit: test-unit-installer
	go test ./... -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

test-unit-quality-gate: test-unit-installer test-unit

test-unit-short: test-unit
