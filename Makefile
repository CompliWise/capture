.PHONY: test-unit test-unit-short
test-unit:
	go test ./... -count=1 -coverprofile=coverage.out
	@go tool cover -func=coverage.out | tail -1

test-unit-short: test-unit
