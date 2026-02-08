package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr string
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: "no authorization header included",
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": {""}},
			wantKey: "",
			wantErr: "no authorization header included",
		},
		{
			name:    "malformed header missing space",
			headers: http.Header{"Authorization": {"ApiKey"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "wrong auth scheme",
			headers: http.Header{"Authorization": {"Bearer some-token"}},
			wantKey: "",
			wantErr: "malformed authorization header",
		},
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": {"ApiKey my-secret-key-1"}},
			wantKey: "my-secret-key",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			if errMsg != tt.wantErr {
				t.Fatalf("expected error %q, got %q", tt.wantErr, errMsg)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
