// Package signing holds the Ed25519 keys of the service, issues the tokens and publishes the public keys as a JSON Web
// Key Set (RFC 7517). A token is a JSON Web Token (RFC 7519) signed with EdDSA (RFC 8037). A token for a client key is
// bound to it with a confirmation claim (RFC 7800).
package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"filippo.io/edwards25519"
)

const (
	// Algorithm is the JWS algorithm of the tokens and of the keys in the key set.
	Algorithm = "EdDSA"
	// SeedSize is the size of a signing key's seed and of a client's public key.
	SeedSize = ed25519.SeedSize
	// maxKeyIDLength bounds a key ID.
	maxKeyIDLength = 64
	// jtiBytes is the size of a token's random ID.
	jtiBytes = 16

	keyType  = "OKP"
	curve    = "Ed25519"
	keyUsage = "sig"
	jwtType  = "JWT"
)

// ErrWeakPublicKey reports a client key that is not a usable Ed25519 public key: not a point of the curve, or a point
// of small order, for which signatures can be forged without a private key.
var ErrWeakPublicKey = errors.New("signing: not a usable Ed25519 public key")

var b64 = base64.RawURLEncoding

// Key is a signing key: its key ID and its 32-byte Ed25519 seed. The seed is secret.
type Key struct {
	ID   string
	Seed []byte
}

// NewKey returns a key with a random seed.
func NewKey(id string) (Key, error) {
	if err := checkKeyID(id); err != nil {
		return Key{}, err
	}
	seed := make([]byte, SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return Key{}, fmt.Errorf("signing: random seed: %w", err)
	}
	return Key{ID: id, Seed: seed}, nil
}

// Entry returns the key in the form ParseKeys reads: <key ID>:<base64url seed>. The entry contains the secret seed.
func (k Key) Entry() string {
	return k.ID + ":" + b64.EncodeToString(k.Seed)
}

// ParseKeys reads comma-separated keys of the form <key ID>:<base64url seed without padding>, as cmd/new-signing-key
// prints them. Errors never contain a seed.
func ParseKeys(s string) ([]Key, error) {
	var keys []Key
	for i, entry := range strings.Split(s, ",") {
		id, encoded, ok := strings.Cut(strings.TrimSpace(entry), ":")
		if !ok {
			return nil, fmt.Errorf("key %d: must have the form <key ID>:<base64url seed>", i+1)
		}
		seed, err := b64.Strict().DecodeString(encoded)
		if err != nil || len(seed) != SeedSize {
			return nil, fmt.Errorf("key %d (%s): the seed must be %d bytes in base64url without padding", i+1, id,
				SeedSize)
		}
		keys = append(keys, Key{ID: id, Seed: seed})
	}
	return keys, nil
}

// CheckKeys reports whether keys can sign: at least one, valid and distinct key IDs, seeds of SeedSize bytes, and
// current among the key IDs.
func CheckKeys(keys []Key, current string) error {
	if len(keys) == 0 {
		return errors.New("at least one key is required")
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if err := checkKeyID(k.ID); err != nil {
			return err
		}
		if seen[k.ID] {
			return fmt.Errorf("key ID %q appears twice", k.ID)
		}
		seen[k.ID] = true
		if len(k.Seed) != SeedSize {
			return fmt.Errorf("key %s: the seed must be %d bytes", k.ID, SeedSize)
		}
	}
	if !seen[current] {
		return fmt.Errorf("the current key ID %q is not among the keys", current)
	}
	return nil
}

// checkKeyID reports whether id is 1 to 64 characters from A-Z, a-z, 0-9, '-' and '_'.
func checkKeyID(id string) error {
	if id == "" || len(id) > maxKeyIDLength {
		return fmt.Errorf("a key ID must have 1 to %d characters, got %d", maxKeyIDLength, len(id))
	}
	for _, c := range []byte(id) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return fmt.Errorf("key ID %q: only A-Z, a-z, 0-9, '-' and '_' are allowed", id)
		}
	}
	return nil
}

// ParsePublicKey checks a client's Ed25519 public key. It returns ErrWeakPublicKey unless raw is the 32-byte encoding
// of a curve point that is not of small order.
func ParsePublicKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != ed25519.PublicKeySize {
		return nil, ErrWeakPublicKey
	}
	point, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return nil, ErrWeakPublicKey
	}
	if new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, ErrWeakPublicKey
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

// Options configure a Signer.
type Options struct {
	// Issuer is the iss claim, e.g. https://token.example.
	Issuer string
	// Now returns the current time. nil uses time.Now.
	Now func() time.Time
}

// Signer issues tokens with the current key and publishes all keys.
type Signer struct {
	opts    Options
	current string
	private ed25519.PrivateKey
	jwks    []byte
}

// New returns a signer that signs with the key named current. keys must pass CheckKeys.
func New(keys []Key, current string, opts Options) (*Signer, error) {
	if err := CheckKeys(keys, current); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Signer{opts: opts, current: current}
	set := keySet{Keys: []publicJWK{}}
	for _, k := range keys {
		private := ed25519.NewKeyFromSeed(k.Seed)
		if k.ID == current {
			s.private = private
		}
		set.Keys = append(set.Keys, publicJWK{
			jwk: newJWK(private.Public().(ed25519.PublicKey)),
			Kid: k.ID,
			Alg: Algorithm,
			Use: keyUsage,
		})
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("signing: encode the key set: %w", err)
	}
	s.jwks = jwks
	return s, nil
}

// CurrentKeyID returns the ID of the key that signs new tokens.
func (s *Signer) CurrentKeyID() string {
	return s.current
}

// JWKS returns the public keys as a JSON Web Key Set, in the order of the keys given to New.
func (s *Signer) JWKS() []byte {
	return s.jwks
}

// Grant is what a token confirms: the user, the user's team (empty without one), the servers that accept it, its
// lifetime, the client key it is bound to, and the user's Wire client. Without a key the token has no cnf claim,
// without a client no wire_client claim. A single audience is written as a string, several as an array.
type Grant struct {
	Subject   string
	Team      string
	Audience  []string
	TTL       time.Duration
	PublicKey ed25519.PublicKey
	// Client is the ID of the Wire client the token was requested for, checked with Wire.
	Client string
}

// Token is an issued token and what the service logs about it.
type Token struct {
	// JWT is the compact serialization. It is a credential and must not be logged.
	JWT       string
	ID        string
	ExpiresIn time.Duration
}

// Issue returns a token for g, valid from now for the configured lifetime.
func (s *Signer) Issue(g Grant) (Token, error) {
	jti := make([]byte, jtiBytes)
	if _, err := rand.Read(jti); err != nil {
		return Token{}, fmt.Errorf("signing: random token ID: %w", err)
	}
	now := s.opts.Now().Unix()
	c := claims{
		Issuer:    s.opts.Issuer,
		Audience:  audClaim(g.Audience),
		Subject:   g.Subject,
		Team:      g.Team,
		Client:    g.Client,
		IssuedAt:  now,
		NotBefore: now,
		Expiry:    now + int64(g.TTL/time.Second),
		ID:        b64.EncodeToString(jti),
	}
	if g.PublicKey != nil {
		c.Confirmation = &confirmation{JWK: newJWK(g.PublicKey)}
	}
	header, err := json.Marshal(jwtHeader{Alg: Algorithm, Kid: s.current, Typ: jwtType})
	if err != nil {
		return Token{}, fmt.Errorf("signing: encode the header: %w", err)
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return Token{}, fmt.Errorf("signing: encode the claims: %w", err)
	}
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	signature := ed25519.Sign(s.private, []byte(signingInput))
	return Token{
		JWT:       signingInput + "." + b64.EncodeToString(signature),
		ID:        c.ID,
		ExpiresIn: time.Duration(c.Expiry-now) * time.Second,
	}, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type claims struct {
	Issuer       string        `json:"iss"`
	Audience     any           `json:"aud"`
	Subject      string        `json:"sub"`
	Team         string        `json:"team,omitempty"`
	Client       string        `json:"wire_client,omitempty"`
	Confirmation *confirmation `json:"cnf,omitempty"`
	IssuedAt     int64         `json:"iat"`
	NotBefore    int64         `json:"nbf"`
	Expiry       int64         `json:"exp"`
	ID           string        `json:"jti"`
}

// audClaim returns the value of the aud claim: one audience as a string, several as an array (RFC 7519, section
// 4.1.3).
func audClaim(auds []string) any {
	if len(auds) == 1 {
		return auds[0]
	}
	return auds
}

type confirmation struct {
	JWK jwk `json:"jwk"`
}

// jwk is an Ed25519 public key as a JSON Web Key (RFC 8037).
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

func newJWK(public ed25519.PublicKey) jwk {
	return jwk{Kty: keyType, Crv: curve, X: b64.EncodeToString(public)}
}

type publicJWK struct {
	jwk
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type keySet struct {
	Keys []publicJWK `json:"keys"`
}
