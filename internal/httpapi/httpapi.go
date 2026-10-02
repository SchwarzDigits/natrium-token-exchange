// Package httpapi serves the token exchange: POST /v1/token checks the Wire token, the admission of its user, the
// requested audience with the client's public key where the audience needs one, the user's Wire client if the request
// names one, and the user's limits, and returns a signed token for that audience. GET /.well-known/jwks.json
// publishes the keys that verify the tokens.
//
// Only a bounded number of requests to Wire run at once. A request beyond that is refused at once with 503, so a
// flood of requests does not turn into a flood of requests to Wire.
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
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/limits"
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

// overloadedRetryAfter is the Retry-After of a request refused because too many token checks run.
const overloadedRetryAfter = time.Second

// Error codes in the body of error responses, {"error": "<code>"}.
const (
	codeBadRequest      = "bad_request"
	codeUnknownClient   = "unknown_client"
	codeUnauthorized    = "unauthorized"
	codeNotAllowed      = "not_allowed"
	codeTooManyRequests = "too_many_requests"
	codeUnavailable     = "unavailable"
	codeInternal        = "internal"
)

// Results of a request, in the log and in the metrics.
const (
	resultOK            = "ok"
	resultBadRequest    = codeBadRequest
	resultUnknownClient = codeUnknownClient
	resultUnauthorized  = codeUnauthorized
	resultNotAllowed    = codeNotAllowed
	resultLimited       = "limited"
	resultOverloaded    = "overloaded"
	resultUnavailable   = codeUnavailable
	resultInternal      = codeInternal
)

var results = []string{
	resultOK, resultBadRequest, resultUnknownClient, resultUnauthorized, resultNotAllowed, resultLimited,
	resultOverloaded, resultUnavailable, resultInternal,
}

// Authenticator returns the user of a Wire access token and checks the user's clients. See wireauth.Client.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (wireauth.User, error)
	CheckClient(ctx context.Context, token, clientID string) error
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

// Limiter bounds the tokens and keys per user. See limits.Limiter.
type Limiter interface {
	Take(user, key string, now time.Time) limits.Decision
}

// Audience is a kind of token that a request names in its audience field.
type Audience struct {
	// Aud is the aud claim: the servers that accept the token. The first one is the server the kind is named for.
	Aud []string
	// TTL is the lifetime of the token.
	TTL time.Duration
	// Key tells whether a request must carry the client's public key, which the token is then bound to. A request for
	// an audience without a key must not carry one.
	Key bool
}

// Options configure the handler. All fields are required, except Now.
type Options struct {
	Auth   Authenticator
	Allow  Admitter
	Signer Signer
	Limits Limiter
	// Audiences are the kinds of token the service issues, by the name a request uses.
	Audiences map[string]Audience
	// MaxConcurrentChecks bounds the requests to Wire that run at once. At least 1.
	MaxConcurrentChecks int
	Log                 *slog.Logger
	Metrics             prometheus.Registerer
	// Now returns the current time. nil uses time.Now.
	Now func() time.Time
}

// Handler serves the API.
type Handler struct {
	opts     Options
	checks   chan struct{}
	requests *prometheus.CounterVec
	issued   *prometheus.CounterVec
	wireAuth prometheus.Histogram
}

// New returns the handler and registers its metrics.
func New(opts Options) *Handler {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	h := &Handler{
		opts:   opts,
		checks: make(chan struct{}, max(opts.MaxConcurrentChecks, 1)),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "natrium_token_exchange_requests_total",
			Help: "Requests to " + PathToken + " by result.",
		}, []string{"result"}),
		issued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "natrium_token_exchange_tokens_issued_total",
			Help: "Tokens issued, by audience.",
		}, []string{"audience"}),
		wireAuth: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "natrium_token_exchange_wire_auth_duration_seconds",
			Help:    "Duration of a request to the Wire backend.",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5, 5},
		}),
	}
	for _, r := range results {
		h.requests.WithLabelValues(r)
	}
	for name := range opts.Audiences {
		h.issued.WithLabelValues(name)
	}
	opts.Metrics.MustRegister(h.requests, h.issued, h.wireAuth)
	return h
}

// Register adds the API, its preflight and the key set to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+PathToken, h.token)
	mux.HandleFunc("OPTIONS "+PathToken, h.preflight)
	mux.HandleFunc("GET "+PathJWKS, h.jwks)
}

type tokenRequest struct {
	Audience  *string `json:"audience"`
	PublicKey *string `json:"publicKey"`
	ClientID  *string `json:"clientId"`
}

// request is a decoded and checked token request.
type request struct {
	name     string
	audience Audience
	key      ed25519.PublicKey
	client   string
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expiresIn"`
}

// outcome is what a request logs.
type outcome struct {
	result   string
	user     wireauth.User
	audience string
	key      string
	client   string
	jti      string
	limit    string
	err      error
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
	if o.audience != "" {
		attrs = append(attrs, "audience", o.audience)
	}
	if o.key != "" {
		attrs = append(attrs, "key", o.key)
	}
	if o.client != "" {
		attrs = append(attrs, "client", o.client)
	}
	if o.jti != "" {
		attrs = append(attrs, "jti", o.jti)
	}
	if o.limit != "" {
		attrs = append(attrs, "limit", o.limit)
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

// serve answers the request in the order: token, admission, body with audience and key, client, limits, issue.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request) outcome {
	token, ok := bearerToken(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeError(w, http.StatusUnauthorized, codeUnauthorized)
		return outcome{result: resultUnauthorized}
	}
	user, err := h.authenticate(r.Context(), token)
	switch {
	case errors.Is(err, errOverloaded):
		w.Header().Set("Retry-After", retryAfterSeconds(overloadedRetryAfter))
		writeError(w, http.StatusServiceUnavailable, codeUnavailable)
		return outcome{result: resultOverloaded}
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

	req, err := h.readRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeBadRequest)
		o.result, o.err = resultBadRequest, err
		return o
	}
	o.audience, o.client = req.name, req.client
	if req.key != nil {
		o.key = base64.RawURLEncoding.EncodeToString(req.key)
	}

	if req.client != "" {
		err := h.wire(func() error { return h.opts.Auth.CheckClient(r.Context(), token, req.client) })
		switch {
		case errors.Is(err, errOverloaded):
			w.Header().Set("Retry-After", retryAfterSeconds(overloadedRetryAfter))
			writeError(w, http.StatusServiceUnavailable, codeUnavailable)
			o.result = resultOverloaded
			return o
		case errors.Is(err, wireauth.ErrUnknownClient):
			writeError(w, http.StatusBadRequest, codeUnknownClient)
			o.result = resultUnknownClient
			return o
		case errors.Is(err, wireauth.ErrUnauthorized):
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, codeUnauthorized)
			o.result = resultUnauthorized
			return o
		case err != nil:
			writeError(w, http.StatusServiceUnavailable, codeUnavailable)
			o.result, o.err = resultUnavailable, err
			return o
		}
	}

	if d := h.opts.Limits.Take(user.String(), o.key, h.opts.Now()); !d.Allowed {
		w.Header().Set("Retry-After", retryAfterSeconds(d.RetryAfter))
		writeError(w, http.StatusTooManyRequests, codeTooManyRequests)
		o.result, o.limit = resultLimited, d.Reason
		return o
	}

	issued, err := h.opts.Signer.Issue(signing.Grant{
		Subject:   user.String(),
		Team:      user.Team,
		Audience:  req.audience.Aud,
		TTL:       req.audience.TTL,
		PublicKey: req.key,
		Client:    req.client,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal)
		o.result, o.err = resultInternal, err
		return o
	}
	h.issued.WithLabelValues(req.name).Inc()
	writeJSON(w, http.StatusOK, tokenResponse{Token: issued.JWT, ExpiresIn: int64(issued.ExpiresIn / time.Second)})
	o.result, o.jti = resultOK, issued.ID
	return o
}

// errOverloaded reports that a request to Wire was not made because MaxConcurrentChecks requests run.
var errOverloaded = errors.New("httpapi: too many requests to Wire at once")

// authenticate checks token with Wire, see wire.
func (h *Handler) authenticate(ctx context.Context, token string) (wireauth.User, error) {
	var user wireauth.User
	err := h.wire(func() error {
		var err error
		user, err = h.opts.Auth.Authenticate(ctx, token)
		return err
	})
	return user, err
}

// wire runs call, a request to Wire, if fewer than MaxConcurrentChecks requests run, and returns errOverloaded
// otherwise.
func (h *Handler) wire(call func() error) error {
	select {
	case h.checks <- struct{}{}:
	default:
		return errOverloaded
	}
	defer func() { <-h.checks }()
	start := time.Now()
	err := call()
	h.wireAuth.Observe(time.Since(start).Seconds())
	return err
}

// retryAfterSeconds rounds d up to whole seconds, at least 1, for a Retry-After header.
func retryAfterSeconds(d time.Duration) string {
	return strconv.Itoa(max(int(math.Ceil(d.Seconds())), 1))
}

// bearerToken returns the token of an "Authorization: Bearer <token>" header.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// readRequest decodes the body strictly: one JSON object with known fields and nothing after it, a configured
// audience, exactly when the audience needs one a public key in base64url without padding that is a usable Ed25519
// public key, and optionally a Wire client ID.
func (h *Handler) readRequest(w http.ResponseWriter, r *http.Request) (request, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return request{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var tr tokenRequest
	if err := dec.Decode(&tr); err != nil {
		return request{}, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return request{}, errors.New("data after the JSON object")
	}
	if tr.Audience == nil {
		return request{}, errors.New("audience is missing")
	}
	req := request{name: *tr.Audience}
	var ok bool
	if req.audience, ok = h.opts.Audiences[req.name]; !ok {
		return request{}, errors.New("unknown audience")
	}
	if tr.ClientID != nil {
		if !wireauth.IsClientID(*tr.ClientID) {
			return request{}, errors.New("clientId is not a Wire client ID")
		}
		req.client = *tr.ClientID
	}
	switch {
	case !req.audience.Key && tr.PublicKey != nil:
		return request{}, errors.New("publicKey is not allowed for this audience")
	case !req.audience.Key:
		return req, nil
	case tr.PublicKey == nil:
		return request{}, errors.New("publicKey is missing")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(*tr.PublicKey)
	if err != nil {
		return request{}, errors.New("publicKey is not base64url without padding")
	}
	if req.key, err = signing.ParsePublicKey(raw); err != nil {
		return request{}, err
	}
	return req, nil
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

// allowAnyOrigin lets pages of any origin read the answer, including Retry-After. Credentials are not allowed; the API
// needs none.
func allowAnyOrigin(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Expose-Headers", "Retry-After")
}
