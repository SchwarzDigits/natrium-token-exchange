package signing

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const (
	issuer   = "https://token.example"
	audience = "wss://vfs.example/v1/ws"
	subject  = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0@wire.example"
	team     = "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c"
)

var fixedNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func key(id string, fill byte) Key {
	return Key{ID: id, Seed: bytes.Repeat([]byte{fill}, SeedSize)}
}

func clientKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	return public
}

func newSigner(t *testing.T, keys []Key, current string) *Signer {
	t.Helper()
	s, err := New(keys, current, Options{
		Issuer: issuer,
		Now:    func() time.Time { return fixedNow },
	})
	require.NoError(t, err)
	return s
}

// publicKeys reads the key set the way a verifier does.
func publicKeys(t *testing.T, s *Signer) map[string]map[string]string {
	t.Helper()
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(s.JWKS(), &set))
	out := map[string]map[string]string{}
	for _, k := range set.Keys {
		out[k["kid"]] = k
	}
	return out
}

// verify checks a token with an independent JWT library against the published key set, as the storage server does.
func verify(t *testing.T, s *Signer, token string) (jwt.MapClaims, *jwt.Token) {
	t.Helper()
	keys := publicKeys(t, s)
	parsed, err := jwt.Parse(token, func(tok *jwt.Token) (any, error) {
		k, ok := keys[tok.Header["kid"].(string)]
		require.True(t, ok, "kid not in the key set")
		x, err := base64.RawURLEncoding.DecodeString(k["x"])
		require.NoError(t, err)
		return ed25519.PublicKey(x), nil
	},
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithTimeFunc(func() time.Time { return fixedNow.Add(time.Minute) }),
	)
	require.NoError(t, err)
	return parsed.Claims.(jwt.MapClaims), parsed
}

func TestIssuedTokenVerifiesAgainstTheKeySet(t *testing.T) {
	s := newSigner(t, []Key{key("k1", 1)}, "k1")
	client := clientKey(t)
	tok, err := s.Issue(Grant{Subject: subject, Team: team, Audience: []string{audience}, TTL: time.Hour, PublicKey: client})
	require.NoError(t, err)
	require.Equal(t, time.Hour, tok.ExpiresIn)

	claims, parsed := verify(t, s, tok.JWT)
	require.Equal(t, "k1", parsed.Header["kid"])
	require.Equal(t, "JWT", parsed.Header["typ"])
	require.Equal(t, subject, claims["sub"])
	require.Equal(t, team, claims["team"])
	require.Equal(t, tok.ID, claims["jti"])
	require.EqualValues(t, fixedNow.Unix(), claims["iat"])
	require.EqualValues(t, fixedNow.Unix(), claims["nbf"])
	require.EqualValues(t, fixedNow.Add(time.Hour).Unix(), claims["exp"])
	require.Equal(t, map[string]any{"jwk": map[string]any{
		"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(client),
	}}, claims["cnf"])
}

func TestTokenWithoutTeamHasNoTeamClaim(t *testing.T) {
	s := newSigner(t, []Key{key("k1", 1)}, "k1")
	tok, err := s.Issue(Grant{Subject: subject, Audience: []string{audience}, TTL: time.Hour, PublicKey: clientKey(t)})
	require.NoError(t, err)
	claims, _ := verify(t, s, tok.JWT)
	require.NotContains(t, claims, "team")
}

func TestTokenIDsAreUnique(t *testing.T) {
	s := newSigner(t, []Key{key("k1", 1)}, "k1")
	g := Grant{Subject: subject, Audience: []string{audience}, TTL: time.Hour, PublicKey: clientKey(t)}
	a, err := s.Issue(g)
	require.NoError(t, err)
	b, err := s.Issue(g)
	require.NoError(t, err)
	require.NotEqual(t, a.ID, b.ID)
	require.Len(t, a.ID, 22) // 16 bytes in base64url
}

func TestExpiredTokenIsRejectedByAVerifier(t *testing.T) {
	s := newSigner(t, []Key{key("k1", 1)}, "k1")
	tok, err := s.Issue(Grant{Subject: subject, Audience: []string{audience}, TTL: time.Hour, PublicKey: clientKey(t)})
	require.NoError(t, err)
	_, err = jwt.Parse(tok.JWT, func(*jwt.Token) (any, error) {
		return ed25519.NewKeyFromSeed(key("k1", 1).Seed).Public(), nil
	}, jwt.WithTimeFunc(func() time.Time { return fixedNow.Add(time.Hour + time.Second) }))
	require.ErrorIs(t, err, jwt.ErrTokenExpired)
}

func TestRotationSignsWithTheCurrentKeyAndPublishesAll(t *testing.T) {
	s := newSigner(t, []Key{key("old", 1), key("new", 2)}, "new")
	require.Equal(t, "new", s.CurrentKeyID())
	tok, err := s.Issue(Grant{Subject: subject, Audience: []string{audience}, TTL: time.Hour, PublicKey: clientKey(t)})
	require.NoError(t, err)
	_, parsed := verify(t, s, tok.JWT)
	require.Equal(t, "new", parsed.Header["kid"])

	keys := publicKeys(t, s)
	require.Len(t, keys, 2)
	for id, fill := range map[string]byte{"old": 1, "new": 2} {
		public := ed25519.NewKeyFromSeed(key(id, fill).Seed).Public().(ed25519.PublicKey)
		require.Equal(t, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(public),
			"kid": id, "alg": "EdDSA", "use": "sig",
		}, keys[id])
	}
	require.NotContains(t, string(s.JWKS()), `"d"`, "the key set must not contain private keys")
}

func TestParseKeys(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, SeedSize))
	keys, err := ParseKeys("a:" + seed + ", b:" + seed)
	require.NoError(t, err)
	require.Equal(t, []Key{{ID: "a", Seed: bytes.Repeat([]byte{7}, SeedSize)}, {ID: "b", Seed: keys[1].Seed}}, keys)

	for _, bad := range []string{
		"",
		"a",
		"a:" + seed[:10],
		"a:" + seed + "=",
		"a:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, SeedSize)),
	} {
		_, err := ParseKeys(bad)
		require.Error(t, err, bad)
		require.NotContains(t, err.Error(), seed[:10], "errors must not contain the seed")
	}
}

func TestNewKeyRoundTripsThroughItsEntry(t *testing.T) {
	k, err := NewKey("2026-09")
	require.NoError(t, err)
	require.Len(t, k.Seed, SeedSize)
	parsed, err := ParseKeys(k.Entry())
	require.NoError(t, err)
	require.Equal(t, []Key{k}, parsed)

	_, err = NewKey("bad id")
	require.Error(t, err)
}

func TestCheckKeys(t *testing.T) {
	require.NoError(t, CheckKeys([]Key{key("a", 1), key("b", 2)}, "b"))
	for name, tc := range map[string]struct {
		keys    []Key
		current string
	}{
		"none":              {nil, "a"},
		"current missing":   {[]Key{key("a", 1)}, "b"},
		"duplicate ID":      {[]Key{key("a", 1), key("a", 2)}, "a"},
		"empty ID":          {[]Key{key("", 1)}, ""},
		"bad character":     {[]Key{key("a/b", 1)}, "a/b"},
		"long ID":           {[]Key{key(strings.Repeat("a", maxKeyIDLength+1), 1)}, strings.Repeat("a", 65)},
		"short seed":        {[]Key{{ID: "a", Seed: []byte{1}}}, "a"},
		"current is empty ": {[]Key{key("a", 1)}, ""},
	} {
		require.Error(t, CheckKeys(tc.keys, tc.current), name)
	}
}

func TestParsePublicKey(t *testing.T) {
	good := clientKey(t)
	parsed, err := ParsePublicKey(good)
	require.NoError(t, err)
	require.Equal(t, good, parsed)

	identity := edwards25519.NewIdentityPoint().Bytes()
	// y = -1: the point of order 2.
	orderTwo := append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 30)...)
	orderTwo = append(orderTwo, 0x7f)
	for name, raw := range map[string][]byte{
		"empty":     nil,
		"short":     good[:31],
		"long":      append(append([]byte{}, good...), 0),
		"identity":  identity,
		"order two": orderTwo,
		"not on the curve": func() []byte {
			for i := range 256 {
				candidate := append([]byte{byte(i)}, bytes.Repeat([]byte{0x42}, 31)...)
				if _, err := new(edwards25519.Point).SetBytes(candidate); err != nil {
					return candidate
				}
			}
			t.Fatal("no encoding off the curve found")
			return nil
		}(),
	} {
		_, err := ParsePublicKey(raw)
		require.ErrorIs(t, err, ErrWeakPublicKey, name)
	}
}

func TestTokenWithoutKeyHasNoConfirmation(t *testing.T) {
	s := newSigner(t, []Key{key("k1", 1)}, "k1")
	tok, err := s.Issue(Grant{Subject: subject, Audience: []string{audience}, TTL: 10 * time.Minute})
	require.NoError(t, err)
	require.Equal(t, 10*time.Minute, tok.ExpiresIn)
	claims, _ := verify(t, s, tok.JWT)
	require.NotContains(t, claims, "cnf")
	require.EqualValues(t, fixedNow.Add(10*time.Minute).Unix(), claims["exp"])
}
