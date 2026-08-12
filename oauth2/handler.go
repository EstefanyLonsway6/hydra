package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

// extractClientIDFromAssertion extracts the client ID from the JWT assertion's iss or sub claim.
func extractClientIDFromAssertion(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return "", errors.New("invalid assertion format")
	}
	payloadSegment := parts[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return "", err
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", err
	}
	if claims.Issuer != "" {
		return claims.Issuer, nil
	}
	return claims.Subject, nil
}

func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var session = NewSession("")
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.r.Logger().WithError(err).Debug("Error occurred during parsing of request form on TokenHandler")
		h.r.OAuth2Provider().WriteAccessError(w, nil, fosite.ErrInvalidRequest.WithDebug(err.Error()))
		return
	}

	// If grant_type is jwt-bearer and client_id is omitted, extract it from the assertion
	if r.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		clientID, _, ok := r.BasicAuth()
		if !ok {
			clientID = r.PostForm.Get("client_id")
		}
		if clientID == "" {
			assertion := r.PostForm.Get("assertion")
			if assertion != "" {
				if extractedID, err := extractClientIDFromAssertion(assertion); err == nil && extractedID != "" {
					r.PostForm.Set("client_id", extractedID)
					if r.Form == nil {
						r.Form = r.PostForm
					} else {
						r.Form.Set("client_id", extractedID)
					}
				}
			}
		}
	}

	accessRequest, err := h.r.OAuth2Provider().NewAccessRequest(ctx, r, session)
	if err != nil {
		h.r.Logger().WithError(err).Debug("Error occurred during resolve of AccessRequest on TokenHandler")
		h.r.OAuth2Provider().WriteAccessError(w, accessRequest, err)
		return
	}

	// ... rest of TokenHandler implementation
}