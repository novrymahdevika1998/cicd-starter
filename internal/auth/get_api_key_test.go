package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("no authorization header", func(t *testing.T) {
		headers := http.Header{}
		_, err := GetAPIKey(headers)
		if err != ErrNoAuthHeaderIncluded {
			t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed - no space", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("malformed - wrong scheme", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer token123")
		_, err := GetAPIKey(headers)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("valid api key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey my-secret-key")
		key, err := GetAPIKey(headers)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if key != "my-secret-key" {
			t.Fatalf("expected 'my-secret-key', got '%s'", key)
		}
	})
}
