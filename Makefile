.PHONY: test-unit
test-unit:
	go test ./... -count=1 -coverprofile=coverage.out
