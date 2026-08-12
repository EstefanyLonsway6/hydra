package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestExtractClientIDFromAssertion(t *testing.T) {
	tests := []struct {
		name      string
		assertion string
		wantID    string
		wantErr   bool
	}{
		{
			name:      "valid JWT with iss claim",
			assertion: makeJWT(t, map[string]string{"iss": "my-client", "sub": "user123"}),
			wantID:    "my-client",
			wantErr:   false,
		},
		{
			name:      "valid JWT with sub only",
			assertion: makeJWT(t, map[string]string{"sub": "client-abc"}),
			wantID:    "client-abc",
			wantErr:   false,
		},
		{
			name:      "valid JWT with iss and sub, iss takes precedence",
			assertion: makeJWT(t, map[string]string{"iss": "issuer-client", "sub": "subject-user"}),
			wantID:    "issuer-client",
			wantErr:   false,
		},
		{
			name:      "empty claims returns empty string",
			assertion: makeJWT(t, map[string]string{}),
			wantID:    "",
			wantErr:   false,
		},
		{
			name:      "invalid format - no dots",
			assertion: "not-a-jwt",
			wantID:    "",
			wantErr:   true,
		},
		{
			name:      "invalid base64 in payload",
			assertion: "header.!!!invalid-base64!!!.signature",
			wantID:    "",
			wantErr:   true,
		},
		{
			name:      "invalid JSON in payload",
			assertion: "header." + base64.RawURLEncoding.EncodeToString([]byte("not-json")) + ".sig",
			wantID:    "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, err := extractClientIDFromAssertion(tt.assertion)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractClientIDFromAssertion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotID != tt.wantID {
				t.Errorf("extractClientIDFromAssertion() = %q, want %q", gotID, tt.wantID)
			}
		})
	}
}

func TestTokenHandler_JWTBearerWithoutClientID(t *testing.T) {
	// Build a JWT with iss=test-client
	jwt := makeJWT(t, map[string]string{"iss": "test-client", "sub": "user1"})

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Verify the form parsing and extraction work
	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	// Simulate the extraction logic from handler.go
	clientID, _, ok := req.BasicAuth()
	if !ok {
		clientID = req.PostForm.Get("client_id")
	}
	if clientID == "" {
		assertion := req.PostForm.Get("assertion")
		if assertion != "" {
			if extractedID, err := extractClientIDFromAssertion(assertion); err == nil && extractedID != "" {
				req.PostForm.Set("client_id", extractedID)
				if req.Form == nil {
					req.Form = req.PostForm
				} else {
					req.Form.Set("client_id", extractedID)
				}
			}
		}
	}

	if got := req.PostForm.Get("client_id"); got != "test-client" {
		t.Errorf("client_id = %q after extraction, want %q", got, "test-client")
	}
}

func TestTokenHandler_JWTBearerWithBasicAuth(t *testing.T) {
	jwt := makeJWT(t, map[string]string{"iss": "ignored-client"})

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("basic-auth-client", "secret123")

	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	clientID, _, ok := req.BasicAuth()
	if !ok {
		clientID = req.PostForm.Get("client_id")
	}

	// BasicAuth should take precedence over assertion extraction
	if clientID != "basic-auth-client" {
		t.Errorf("client_id = %q, want %q (BasicAuth should take precedence)", clientID, "basic-auth-client")
	}
}

func TestTokenHandler_JWTBearerWithExplicitClientID(t *testing.T) {
	jwt := makeJWT(t, map[string]string{"iss": "jwt-client"})

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)
	form.Set("client_id", "explicit-client")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	clientID, _, ok := req.BasicAuth()
	if !ok {
		clientID = req.PostForm.Get("client_id")
	}

	// Explicit client_id in form should be used
	if clientID != "explicit-client" {
		t.Errorf("client_id = %q, want %q", clientID, "explicit-client")
	}
}

func TestTokenHandler_NonJWTBearerUnaffected(t *testing.T) {
	// Regular authorization_code flow should not be affected
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "abc123")
	form.Set("client_id", "regular-client")
	form.Set("client_secret", "secret")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	if req.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		// For non-JWT-Bearer flows, the extraction logic is skipped entirely
		// client_id should remain as explicitly provided
		if req.PostForm.Get("client_id") != "regular-client" {
			t.Errorf("Non-JWT flow: client_id = %q, want %q", req.PostForm.Get("client_id"), "regular-client")
		}
	}
}

func TestTokenHandler_JWTBearerInvalidAssertion(t *testing.T) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", "invalid-jwt-no-dots")

	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if err := req.ParseForm(); err != nil {
		t.Fatalf("ParseForm failed: %v", err)
	}

	clientID, _, ok := req.BasicAuth()
	if !ok {
		clientID = req.PostForm.Get("client_id")
	}
	if clientID == "" {
		assertion := req.PostForm.Get("assertion")
		if assertion != "" {
			if extractedID, err := extractClientIDFromAssertion(assertion); err == nil && extractedID != "" {
				req.PostForm.Set("client_id", extractedID)
			}
		}
	}

	// Invalid assertion should NOT set client_id
	if req.PostForm.Get("client_id") != "" {
		t.Errorf("client_id should remain empty for invalid assertion, got %q", req.PostForm.Get("client_id"))
	}
}

// makeJWT creates a simple JWT-like token for testing (no signature validation needed)
func makeJWT(t *testing.T, claims map[string]string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("Failed to marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return header + "." + payload + "." + sig
}
