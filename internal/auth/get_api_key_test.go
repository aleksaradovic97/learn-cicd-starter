package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantKey   string
		wantError error
	}{
		{
			name:      "valid API key",
			header:    "ApiKey my-secret-key",
			wantKey:   "my-secret-key",
			wantError: nil,
		},
		{
			name:      "missing authorization header",
			header:    "",
			wantKey:   "",
			wantError: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong authorization scheme",
			header:    "Bearer my-secret-key",
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name:      "missing API key",
			header:    "ApiKey",
			wantKey:   "",
			wantError: errors.New("malformed authorization header"),
		},
		{
			name:      "empty API key",
			header:    "ApiKey ",
			wantKey:   "",
			wantError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.header != "" {
				headers.Set("Authorization", tt.header)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if tt.wantError == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected an error, got nil")
				}
				if err.Error() != tt.wantError.Error() {
					t.Errorf("expected error %q, got %q", tt.wantError.Error(), err.Error())
				}
			}
		})
	}
}
