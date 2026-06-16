package macos

import (
	"testing"

	"github.com/bluewave-labs/capture/internal/installer"
)

func TestResolveKeychainPathDefault(t *testing.T) {
	path, err := ResolveKeychainPath("")
	if err != nil {
		t.Fatalf("ResolveKeychainPath: %v", err)
	}
	if path != DefaultSystemKeychain {
		t.Fatalf("expected default system keychain, got %q", path)
	}
}

func TestResolveKeychainPathValidSystem(t *testing.T) {
	path, err := ResolveKeychainPath("/Library/Keychains/System.keychain")
	if err != nil {
		t.Fatalf("ResolveKeychainPath: %v", err)
	}
	if path != "/Library/Keychains/System.keychain" {
		t.Fatalf("unexpected path %q", path)
	}
}

func TestResolveKeychainPathValidUserLogin(t *testing.T) {
	path, err := ResolveKeychainPath("/Users/demo/Library/Keychains/login.keychain-db")
	if err != nil {
		t.Fatalf("ResolveKeychainPath: %v", err)
	}
	if path != "/Users/demo/Library/Keychains/login.keychain-db" {
		t.Fatalf("unexpected path %q", path)
	}
}

func TestResolveKeychainPathRejectsTraversal(t *testing.T) {
	_, err := ResolveKeychainPath("/Library/Keychains/../etc/passwd")
	if err == nil {
		t.Fatal("expected traversal rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PATH" {
		t.Fatalf("expected ERR_INVALID_PATH, got %q", installer.ErrorCode(err))
	}
}

func TestResolveKeychainPathRejectsOutsideKeychains(t *testing.T) {
	_, err := ResolveKeychainPath("/tmp/custom.keychain")
	if err == nil {
		t.Fatal("expected invalid path rejection")
	}
	if installer.ErrorCode(err) != "ERR_INVALID_PATH" {
		t.Fatalf("expected ERR_INVALID_PATH, got %q", installer.ErrorCode(err))
	}
}
