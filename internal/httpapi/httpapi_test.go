package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/allow"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/limits"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/signing"
	"github.com/SchwarzDigits/natrium-token-exchange/internal/wireauth"
)

const (
	wireToken = "token-of-alice"
	aliceID   = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	bobID     = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	domain    = "wire.example"
	team      = "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c"
	issuer    = "https://token.example"
	audience  = "wss://vfs.example/v1/ws"
	pinAud    = "https://pin.example"
)

var audiences = map[string]Audience{
	"storage": {Aud: []string{audience}, TTL: time.Hour, Key: true},
	"pin":     {Aud: []string{pinAud, audience}, TTL: 10 * time.Minute},
}

type fakeAuth struct {
	mu    sync.Mutex
	calls int
	user  wireauth.User
	err   error
	// clients are the Wire clients of the user.
	clients []string
	// entered and release, if set, hold every check until release is closed.
	entered chan struct{}
	release chan struct{}
}

func (f *fakeAuth) Authenticate(_ context.Context, t string) (wireauth.User, error) {
	if f.release != nil {
		f.entered <- struct{}{}
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return wireauth.User{}, f.err
	}
	if t != wireToken {
		return wireauth.User{}, wireauth.ErrUnauthorized
	}
	return f.user, nil
}

func (f *fakeAuth) CheckClient(_ context.Context, t, clientID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	switch {
	case t != wireToken:
		return wireauth.ErrUnauthorized
	case !slices.Contains(f.clients, clientID):
		return wireauth.ErrUnknownClient
	}
	return nil
}

type failingSigner struct{ *signing.Signer }

func (failingSigner) Issue(signing.Grant) (signing.Token, error) {
	return signing.Token{}, errors.New("no randomness")
}

type fixture struct {
	handler http.Handler
	auth    *fakeAuth
	signer  *signing.Signer
	logs    *bytes.Buffer
	api     *Handler
	now     time.Time
}

// maxChecks is the bound of concurrent token checks in the fixture.
const maxChecks = 2

func newFixture(t *testing.T, sign func(*signing.Signer) Signer) *fixture {
	t.Helper()
	signer, err := signing.New([]signing.Key{{ID: "k1", Seed: bytes.Repeat([]byte{1}, signing.SeedSize)}}, "k1",
		signing.Options{Issuer: issuer})
	require.NoError(t, err)
	list, err := allow.New(allow.Rules{AllowedTeams: []string{team}})
	require.NoError(t, err)
	f := &fixture{
		auth: &fakeAuth{user: wireauth.User{
			QualifiedID: wireauth.QualifiedID{Domain: domain, ID: aliceID}, Team: team,
		}},
		signer: signer,
		logs:   &bytes.Buffer{},
		now:    time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC),
	}
	var s Signer = signer
	if sign != nil {
		s = sign(signer)
	}
	limiter, err := limits.New(limits.Limit{N: 3, Window: time.Hour}, limits.Limit{N: 2, Window: 24 * time.Hour})
	require.NoError(t, err)
	f.api = New(Options{
		Auth:                f.auth,
		Allow:               list,
		Signer:              s,
		Limits:              limiter,
		Audiences:           audiences,
		MaxConcurrentChecks: maxChecks,
		Log:                 slog.New(slog.NewJSONHandler(f.logs, nil)),
		Metrics:             prometheus.NewRegistry(),
		Now:                 func() time.Time { return f.now },
	})
	mux := http.NewServeMux()
	f.api.Register(mux)
	f.handler = mux
	return f
}

func clientKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return public
}

func body(key []byte) string {
	return `{"audience":"storage","publicKey":"` + base64.RawURLEncoding.EncodeToString(key) + `"}`
}

func publicKeyOf(t *testing.T, token string) any {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	require.NoError(t, err)
	return parsed.Claims.(jwt.MapClaims)["cnf"]
}

func (f *fixture) post(t *testing.T, auth, payload string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, PathToken, strings.NewReader(payload))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

func (f *fixture) count(result string) float64 {
	return testutil.ToFloat64(f.api.requests.WithLabelValues(result))
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &e))
	return e.Error
}

func TestIssuesATokenBoundToTheClientKey(t *testing.T) {
	f := newFixture(t, nil)
	key := clientKey(t)
	rec := f.post(t, "Bearer "+wireToken, body(key))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "Retry-After", rec.Header().Get("Access-Control-Expose-Headers"))

	var resp struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expiresIn"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.EqualValues(t, 3600, resp.ExpiresIn)

	parsed, err := jwt.Parse(resp.Token, func(*jwt.Token) (any, error) {
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, signing.SeedSize)).Public(), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience(audience))
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, aliceID+"@"+domain, claims["sub"])
	require.Equal(t, team, claims["team"])
	require.Equal(t, base64.RawURLEncoding.EncodeToString(key), claims["cnf"].(map[string]any)["jwk"].(map[string]any)["x"])

	logs := f.logs.String()
	require.Contains(t, logs, `"result":"ok"`)
	require.Contains(t, logs, `"audience":"storage"`)
	require.EqualValues(t, 1, testutil.ToFloat64(f.api.issued.WithLabelValues("storage")))
	require.Contains(t, logs, aliceID+"@"+domain)
	require.Contains(t, logs, base64.RawURLEncoding.EncodeToString(key))
	require.Contains(t, logs, claims["jti"])
	require.NotContains(t, logs, wireToken)
	require.NotContains(t, logs, resp.Token)
	require.EqualValues(t, 1, f.count(resultOK))
}

func TestRejectsMissingOrInvalidWireTokens(t *testing.T) {
	f := newFixture(t, nil)
	key := clientKey(t)
	for _, auth := range []string{"", "Bearer", "Bearer ", "Basic " + wireToken, wireToken} {
		rec := f.post(t, auth, body(key))
		require.Equal(t, http.StatusUnauthorized, rec.Code, auth)
		require.Equal(t, "Bearer", rec.Header().Get("WWW-Authenticate"))
		require.Equal(t, codeUnauthorized, errorCode(t, rec))
	}
	require.Zero(t, f.auth.calls, "a request without a bearer token is not sent to Wire")

	rec := f.post(t, "Bearer someone-else", body(key))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.EqualValues(t, 6, f.count(resultUnauthorized))
	require.NotContains(t, f.logs.String(), "someone-else")
}

func TestWireUnavailable(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.err = errors.Join(wireauth.ErrUnavailable, errors.New("connection refused"))
	rec := f.post(t, "Bearer "+wireToken, body(clientKey(t)))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.Equal(t, codeUnavailable, errorCode(t, rec))
	require.EqualValues(t, 1, f.count(resultUnavailable))
}

func TestRefusesUsersOutsideTheList(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.user = wireauth.User{QualifiedID: wireauth.QualifiedID{Domain: domain, ID: bobID}}
	rec := f.post(t, "Bearer "+wireToken, `not even JSON`)
	require.Equal(t, http.StatusForbidden, rec.Code, "admission is checked before the body")
	require.Equal(t, codeNotAllowed, errorCode(t, rec))
	require.EqualValues(t, 1, f.count(resultNotAllowed))
	require.Contains(t, f.logs.String(), bobID+"@"+domain)
}

func TestRejectsBadBodies(t *testing.T) {
	f := newFixture(t, nil)
	key := clientKey(t)
	encoded := base64.RawURLEncoding.EncodeToString(key)
	for name, payload := range map[string]string{
		"empty":             ``,
		"not JSON":          `publicKey`,
		"empty object":      `{}`,
		"missing audience":  `{"publicKey":"` + encoded + `"}`,
		"unknown audience":  `{"audience":"backup","publicKey":"` + encoded + `"}`,
		"null audience":     `{"audience":null}`,
		"missing key":       `{"audience":"storage"}`,
		"null key":          `{"audience":"storage","publicKey":null}`,
		"key for pin":       `{"audience":"pin","publicKey":"` + encoded + `"}`,
		"unknown field":     `{"audience":"storage","publicKey":"` + encoded + `","extra":1}`,
		"trailing data":     body(key) + `{}`,
		"padded base64":     `{"audience":"storage","publicKey":"` + base64.URLEncoding.EncodeToString(key) + `"}`,
		"standard base64":   `{"audience":"storage","publicKey":"` + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32)) + `"}`,
		"short key":         body(key[:31]),
		"identity point":    body(edwards25519.NewIdentityPoint().Bytes()),
		"too large":         `{"audience":"storage","publicKey":"` + encoded + `"` + strings.Repeat(" ", maxBodyBytes) + `}`,
		"array":             `[` + body(key) + `]`,
		"key is a number":   `{"audience":"storage","publicKey":42}`,
		"two JSON objects":  body(key) + body(key),
		"audience a number": `{"audience":1}`,
		"client upper case": `{"audience":"pin","clientId":"3A7E"}`,
		"client too long":   `{"audience":"pin","clientId":"3a7e1b9f2c4d5e6f0"}`,
		"client empty":      `{"audience":"pin","clientId":""}`,
		"client a path":     `{"audience":"pin","clientId":"../self"}`,
		"client a number":   `{"audience":"pin","clientId":42}`,
	} {
		rec := f.post(t, "Bearer "+wireToken, payload)
		require.Equal(t, http.StatusBadRequest, rec.Code, name)
		require.Equal(t, codeBadRequest, errorCode(t, rec), name)
	}
}

func TestSignerFailureIsInternal(t *testing.T) {
	f := newFixture(t, func(s *signing.Signer) Signer { return failingSigner{s} })
	rec := f.post(t, "Bearer "+wireToken, body(clientKey(t)))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, codeInternal, errorCode(t, rec))
	require.Contains(t, f.logs.String(), `"level":"ERROR"`)
}

func TestPreflight(t *testing.T) {
	f := newFixture(t, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodOptions, PathToken, nil))
	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "POST", rec.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "Authorization, Content-Type", rec.Header().Get("Access-Control-Allow-Headers"))
	require.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
}

func TestOtherMethodsAreNotAllowed(t *testing.T) {
	f := newFixture(t, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathToken, nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

func TestServesTheKeySet(t *testing.T) {
	f := newFixture(t, nil)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathJWKS, nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, jwksCacheControl, rec.Header().Get("Cache-Control"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	require.JSONEq(t, string(f.signer.JWKS()), rec.Body.String())
}

func TestLimitsTokensPerUser(t *testing.T) {
	f := newFixture(t, nil)
	key := clientKey(t)
	for range 3 {
		require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(key)).Code)
	}
	f.now = f.now.Add(10 * time.Minute)
	rec := f.post(t, "Bearer "+wireToken, body(key))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, codeTooManyRequests, errorCode(t, rec))
	require.Equal(t, "3000", rec.Header().Get("Retry-After"), "50 minutes until the first token leaves the window")
	require.EqualValues(t, 1, f.count(resultLimited))
	require.Contains(t, f.logs.String(), `"limit":"tokens"`)

	f.now = f.now.Add(50 * time.Minute)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(key)).Code)
}

func TestLimitsKeysPerUser(t *testing.T) {
	f := newFixture(t, nil)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(clientKey(t))).Code)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(clientKey(t))).Code)
	rec := f.post(t, "Bearer "+wireToken, body(clientKey(t)))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "86400", rec.Header().Get("Retry-After"))
	require.Contains(t, f.logs.String(), `"limit":"keys"`)
}

func TestBoundsConcurrentChecks(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.entered = make(chan struct{})
	f.auth.release = make(chan struct{})
	key := clientKey(t)

	codes := make(chan int, maxChecks)
	for range maxChecks {
		go func() { codes <- f.post(t, "Bearer "+wireToken, body(key)).Code }()
		<-f.auth.entered
	}
	rec := f.post(t, "Bearer "+wireToken, body(key))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, "a check beyond the bound is refused at once")
	require.Equal(t, codeUnavailable, errorCode(t, rec))
	require.Equal(t, "1", rec.Header().Get("Retry-After"))
	require.EqualValues(t, 1, f.count(resultOverloaded))

	close(f.auth.release)
	for range maxChecks {
		require.Equal(t, http.StatusOK, <-codes)
	}
	f.auth.release = nil
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(key)).Code, "the slots are free again")
}

func TestIssuesAPinTokenWithoutKey(t *testing.T) {
	f := newFixture(t, nil)
	rec := f.post(t, "Bearer "+wireToken, `{"audience":"pin"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Token     string `json:"token"`
		ExpiresIn int64  `json:"expiresIn"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.EqualValues(t, 600, resp.ExpiresIn)

	parsed, err := jwt.Parse(resp.Token, func(*jwt.Token) (any, error) {
		return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, signing.SeedSize)).Public(), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuer), jwt.WithAudience(pinAud))
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, aliceID+"@"+domain, claims["sub"])
	require.Nil(t, publicKeyOf(t, resp.Token), "a PIN token is not bound to a key")

	require.Equal(t, []any{pinAud, audience}, claims["aud"],
		"the storage server accepts a PIN token for looking up the slot, which needs no key")

	require.Contains(t, f.logs.String(), `"audience":"pin"`)
	require.NotContains(t, f.logs.String(), `"key"`)
	require.EqualValues(t, 1, testutil.ToFloat64(f.api.issued.WithLabelValues("pin")))
}

func TestPinTokensCountOnlyAsTokens(t *testing.T) {
	f := newFixture(t, nil)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(clientKey(t))).Code)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, body(clientKey(t))).Code)
	require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, `{"audience":"pin"}`).Code,
		"the key limit of 2 is full, but a PIN token has no key")
	require.Equal(t, http.StatusTooManyRequests, f.post(t, "Bearer "+wireToken, `{"audience":"pin"}`).Code,
		"the token limit of 3 applies to PIN tokens too")
}

func TestIssuesTokensForAWireClientOfTheUser(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.clients = []string{"3a7e1b9f2c4d5e6f"}
	key := clientKey(t)
	rec := f.post(t, "Bearer "+wireToken,
		`{"audience":"storage","publicKey":"`+base64.RawURLEncoding.EncodeToString(key)+`","clientId":"3a7e1b9f2c4d5e6f"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	parsed, _, err := jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	require.Equal(t, "3a7e1b9f2c4d5e6f", claims["wire_client"])
	require.Equal(t, audience, claims["aud"], "a storage token names only the storage server")
	require.Contains(t, f.logs.String(), `"client":"3a7e1b9f2c4d5e6f"`)

	rec = f.post(t, "Bearer "+wireToken, `{"audience":"pin","clientId":"3a7e1b9f2c4d5e6f"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = f.post(t, "Bearer "+wireToken, `{"audience":"pin"}`)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	parsed, _, err = jwt.NewParser().ParseUnverified(resp.Token, jwt.MapClaims{})
	require.NoError(t, err)
	require.NotContains(t, parsed.Claims.(jwt.MapClaims), "wire_client", "without a clientId there is no claim")
}

func TestRefusesClientsOfOtherUsers(t *testing.T) {
	f := newFixture(t, nil)
	f.auth.clients = []string{"3a7e1b9f2c4d5e6f"}
	rec := f.post(t, "Bearer "+wireToken, `{"audience":"pin","clientId":"1234"}`)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Equal(t, codeUnknownClient, errorCode(t, rec))
	require.EqualValues(t, 1, f.count(resultUnknownClient))
	require.Contains(t, f.logs.String(), `"client":"1234"`)

	for range 3 {
		require.Equal(t, http.StatusOK, f.post(t, "Bearer "+wireToken, `{"audience":"pin"}`).Code,
			"a refused request is not counted against the limits")
	}
}
