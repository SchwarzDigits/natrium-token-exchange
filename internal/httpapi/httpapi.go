// Package httpapi serves the token exchange: POST /v1/token checks the Wire token, the admission of its user and the
// client's public key, and returns a signed token bound to that key. GET /.well-known/jwks.json publishes the keys
// that verify the tokens.
//
// Any web page may call the API (CORS with origin *). CORS only protects credentials that the browser adds by itself,
// such as cookies. The API has none: the client sets the Wire token in the Authorization header, and a page without
// the token gets no further than 401.
//
// The Wire token and the issued token never appear in logs, errors or metrics.
package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/signing"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/wireauth"
)

// Paths of the API.
const (
	PathToken = "/v1/token"
	PathJWKS  = "/.well-known/jwks.json"
)

// maxBodyBytes bounds the request body. A request has about 60 bytes.
const maxBodyBytes = 1024

// preflightMaxAge is how long a browser may cache the answer to a preflight request, in seconds.
const preflightMaxAge = "600"

// jwksCacheControl lets verifiers cache the key set for five minutes. A new key must be published at least this long
// before it signs; see docs/operations.md.
const jwksCacheControl = "public, max-age=300"

// Error codes in the body of error responses, {"error": "<code>"}.
const (
	codeBadRequest   = "bad_request"
	codeUnauthorized = "unauthorized"
	codeNotAllowed   = "not_allowed"
	codeUnavailable  = "unavailable"
	codeInternal     = "internal"
)

// Results of a request, in the log and in the metrics.
const (
	resultOK           = "ok"
	resultBadRequest   = codeBadRequest
	resultUnauthorized = codeUnauthorized
	resultNotAllowed   = codeNotAllowed
	resultUnavailable  = codeUnavailable
	resultInternal     = codeInternal
)

var results = []string{
	resultOK, resultBadRequest, resultUnauthorized, resultNotAllowed, resultUnavailable, resultInternal,
}

// Authenticator returns the user of a Wire access token. See wireauth.Client.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (wireauth.User, error)
}

// Admitter decides whether a user may get a token. See allow.List.
type Admitter interface {
	Admits(u wireauth.User) bool
}

// Signer issues tokens and publishes its keys. See signing.Signer.
type Signer interface {
	Issue(g signing.Grant) (signing.Token, error)
	JWKS() []byte
}

// Options configure the handler. All fields are required.
type Options struct {
	Auth    Authenticator
	Allow   Admitter
	Signer  Signer
	Log     *slog.Logger
	Metrics prometheus.Registerer
}

// Handler serves the API.
type Handler struct {
	opts     Options
	requests *prometheus.CounterVec
	wireAuth prometheus.Histogram
}

// New returns the handler and registers its metrics.
func New(opts Options) *Handler {
	h := &Handler{
		opts: opts,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "natrium_token_exchange_requests_total",
			Help: "Requests to " + PathToken + " by result.",
		}, []string{"result"}),
		wireAuth: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "natrium_token_exchange_wire_auth_duration_seconds",
			Help:    "Duration of the token check with the Wire backend.",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}),
	}
	for _, r := range results {
		h.requests.WithLabelValues(r)
	}
	opts.Metrics.MustRegister(h.requests, h.wireAuth)
	return h
}

// Register adds the API, its preflight and the key set to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+PathToken, h.token)
	mux.HandleFunc("OPTIONS "+PathToken, h.preflight)
	mux.HandleFunc("GET "+PathJWKS, h.jwks)
}

type tokenRequest struct {
	PublicKey *string `json:"publicKey"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expiresIn"`
}

// outcome is what a request logs.
type outcome struct {
	result string
	user   wireauth.User
	key    string
	jti    string
	err    error
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Cache-Control", "no-store")
	o := h.serve(w, r)
	h.requests.WithLabelValues(o.result).Inc()

	attrs := []any{"result", o.result}
	if o.user.ID != "" {
		attrs = append(attrs, "user", o.user.String())
	}
	if o.user.Team != "" {
		attrs = append(attrs, "team", o.user.Team)
	}
	if o.key != "" {
		attrs = append(attrs, "key", o.key)
	}
	if o.jti != "" {
		attrs = append(attrs, "jti", o.jti)
	}
	switch {
	case o.result == resultInternal:
		h.opts.Log.Error("token", append(attrs, "error", o.err)...)
	case o.err != nil:
		h.opts.Log.Warn("token", append(attrs, "error", o.err)...)
	default:
		h.opts.Log.Info("token", attrs...)
	}
}

// serve answers the request in the order: token, admission, body and key, issue.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) outcome {
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return outcome{result: resultUnauthorized}
	}
	start := time.Now()
	user, err := h.opts.Auth.Authenticate(r.Context(), token)
	h.wireAuth.Observe(time.Since(start).Seconds())
	switch {
	case errors.Is(err, wireauth.ErrUnauthorized):
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return outcome{result: resultUnauthorized}
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return outcome{result: resultUnavailable, err: err}
	}
	o := outcome{user: user}

	if !h.opts.Allow.Admits(user) {
		writeError(w, http.StatusForbidden, codeNotAllowed)
		o.result = resultNotAllowed
		return o
	}

	key, err := readRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		o.result = resultBadRequest
		return o
	}
	o.key = base64.RawURLEncoding.EncodeToString(key)

	issued, err := h.opts.Signer.Issue(signing.Grant{Subject: user.String(), Team: user.Team, PublicKey: key})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		o.result, o.err = resultInternal, err
		return o
	}
	writeJSON(w, http.StatusOK, tokenResponse{Token: issued.JWT, ExpiresIn: int64(issued.ExpiresIn / time.Second)})
	o.result, o.jti = resultOK, issued.ID
	return o
}

// bearerToken returns the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// readRequest decodes the body strictly: one JSON object with known fields and nothing after it, and a public key in
// base64url without padding that is a usable Ed25519 public key.
func readRequest(w http.ResponseWriter, r *http.Request) (ed25519.PublicKey, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var req tokenRequest
	if err := dec.Decode(&req); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON object")
	}
	if req.PublicKey == nil {
		return nil, errors.New("publicKey is missing")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(*req.PublicKey)
	if err != nil {
		return nil, err
	}
	return signing.ParsePublicKey(raw)
}

func (h *Handler) jwks(w http.ResponseWriter, _ *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", jwksCacheControl)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(h.opts.Signer.JWKS())
}

func writeError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// preflight answers the CORS preflight of a browser: POST with the headers Authorization and Content-Type is allowed
// from any origin.
func (h *Handler) preflight(w http.ResponseWriter, _ *http.Request) {
	allowAnyOrigin(w)
	w.Header().Set("Access-Control-Allow-Methods", http.MethodPost)
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
	w.WriteHeader(http.StatusNoContent)
}

// allowAnyOrigin lets pages of any origin read the answer. Credentials are not allowed; the API needs none.
func allowAnyOrigin(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}
