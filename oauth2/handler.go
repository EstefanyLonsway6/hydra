package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

// ErrNoClientIdentifier is returned when the JWT assertion does not contain
// a usable client identifier (iss or sub claim).
var ErrNoClientIdentifier = errors.New("no client identifier found in assertion claims")

// extractClientIDFromAssertion extracts the client ID from the JWT assertion's iss or sub claim.
// Per RFC 7523 Section 3, the issuer (iss) claim is the primary client identifier.
// Falls back to subject (sub) if iss is not present.
func extractClientIDFromAssertion(assertion string) (string, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) < 2 {
		return "", errors.New("invalid assertion format: expected at least 2 dot-separated segments")
	}
	payloadSegment := parts[1]
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return "", fmt.Errorf("failed to decode assertion payload: %w", err)
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", fmt.Errorf("failed to parse assertion claims: %w", err)
	}
	if claims.Issuer != "" {
		return claims.Issuer, nil
	}
	if claims.Subject != "" {
		return claims.Subject, nil
	}
	return "", ErrNoClientIdentifier
}

func (h *Handler) TokenHandler(w http.ResponseWriter, r *http.Request) {
	var session = NewSession("")
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.r.Logger().WithError(err).Debug("Error occurred during parsing of request form on TokenHandler")
		h.r.OAuth2Provider().WriteAccessError(w, nil, fosite.ErrInvalidRequest.WithDebug(err.Error()))
		return
	}

	// If grant_type is jwt-bearer and client_id is omitted, extract it from the assertion.
	// Per RFC 7523 Section 2.1, client_id is optional for JWT Bearer grant type;
	// the client identity can be determined from the assertion's iss or sub claim.
	if r.PostForm.Get("grant_type") == "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		clientID, _, ok := r.BasicAuth()
		if !ok {
			clientID = r.PostForm.Get("client_id")
		}
		if clientID == "" {
			assertion := r.PostForm.Get("assertion")
			if assertion == "" {
				h.r.Logger().Debug("JWT Bearer request missing both client_id and assertion")
				h.r.OAuth2Provider().WriteAccessError(w, nil,
					fosite.ErrInvalidGrant.WithDebug("client_id or assertion is required for JWT Bearer grant"))
				return
			}
			extractedID, err := extractClientIDFromAssertion(assertion)
			if err != nil {
				h.r.Logger().WithError(err).Debug("Failed to extract client_id from JWT assertion")
				h.r.OAuth2Provider().WriteAccessError(w, nil,
					fosite.ErrInvalidGrant.WithDebug("failed to extract client identity from assertion: "+err.Error()))
				return
			}
			if extractedID == "" {
				h.r.Logger().Debug("JWT assertion contains no usable client identifier")
				h.r.OAuth2Provider().WriteAccessError(w, nil,
					fosite.ErrInvalidClient.WithDebug("no client identifier found in assertion claims"))
				return
			}
			r.PostForm.Set("client_id", extractedID)
			if r.Form == nil {
				r.Form = r.PostForm
			} else {
				r.Form.Set("client_id", extractedID)
			}
		}
	}

	accessRequest, err := h.r.OAuth2Provider().NewAccessRequest(ctx, r, session)
	if err != nil {
		h.r.Logger().WithError(err).Debug("Error occurred during resolve of AccessRequest on TokenHandler")
		h.r.OAuth2Provider().WriteAccessError(w, accessRequest, err)
		return
	}

	// Grant the access request and write the token response
	response, err := h.r.OAuth2Provider().NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.r.Logger().WithError(err).Debug("Error occurred during creation of AccessResponse on TokenHandler")
		h.r.OAuth2Provider().WriteAccessError(w, accessRequest, err)
		return
	}
	h.r.OAuth2Provider().WriteAccessResponse(w, accessRequest, response)
}
