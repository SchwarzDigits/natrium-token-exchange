// Package wireauth checks a Wire access token by asking the Wire backend whose user it belongs to (GET /self). The
// backend stays the only party that decides whether a token is valid. The package depends on nothing else in this
// module. It is taken over from natrium-pin-service and additionally reads the user's team.
package wireauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultTimeout bounds one check, including connecting to the backend.
	defaultTimeout = 5 * time.Second
	// maxResponseBytes bounds the /self response that is read. A profile is a few KiB.
	maxResponseBytes = 1 << 20
	// maxTokenLength bounds the tokens passed to the backend. Wire access tokens have about 200 characters.
	maxTokenLength = 4096
	selfPath       = "/self"
)

var (
	// ErrUnauthorized reports a missing token or a token the backend rejected.
	ErrUnauthorized = errors.New("wireauth: the token was rejected")
	// ErrUnavailable reports that the backend could not be asked or gave no usable answer.
	ErrUnavailable = errors.New("wireauth: the Wire backend is unavailable")
)

// QualifiedID identifies a Wire user across backends. Domain is lowercase and ID is a lowercase UUID in the form
// 8-4-4-4-12.
type QualifiedID struct {
	Domain string
	ID     string
}

// String returns the ID in the form Wire writes it, ID@domain.
func (q QualifiedID) String() string {
	return q.ID + "@" + q.Domain
}

// User is the owner of a token: the qualified ID and, for a member of a team, the team's ID as a lowercase UUID.
// Team is empty for a user without a team.
type User struct {
	QualifiedID
	Team string
}

// Client checks tokens against one Wire backend.
type Client struct {
	selfURL string
	http    *http.Client
	timeout time.Duration
}

// CheckAPIURL reports whether apiURL can be used as the base URL of the Wire API: an https URL with a host and without
// query or fragment. The path normally ends with the API version, e.g. https://nginz-https.wire.example/v15.
func CheckAPIURL(apiURL string) error {
	u, err := url.Parse(apiURL)
	switch {
	case err != nil:
		return fmt.Errorf("is not a URL: %w", err)
	case u.Scheme != "https" || u.Host == "":
		return errors.New("must be an https URL with a host, e.g. https://nginz-https.wire.example/v15")
	case u.RawQuery != "" || u.Fragment != "" || u.User != nil:
		return errors.New("must not have a query, a fragment or user information")
	}
	return nil
}

// New returns a client for the Wire API at apiURL, see CheckAPIURL. httpClient is used for the requests; nil uses a
// client of its own. The client never follows redirects, so the token only goes to apiURL.
func New(apiURL string, httpClient *http.Client) (*Client, error) {
	if err := CheckAPIURL(apiURL); err != nil {
		return nil, fmt.Errorf("wireauth: API URL %w", err)
	}
	c := http.Client{}
	if httpClient != nil {
		c = *httpClient
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{selfURL: strings.TrimSuffix(apiURL, "/") + selfPath, http: &c, timeout: defaultTimeout}, nil
}

// Authenticate asks the backend for the user of token. It returns ErrUnauthorized if the token is missing or the
// backend rejects it, and ErrUnavailable, wrapped with the cause, if the backend cannot be asked or its answer is not
// usable. Errors never contain the token.
func (c *Client) Authenticate(ctx context.Context, token string) (User, error) {
	if !plausibleToken(token) {
		return User{}, ErrUnauthorized
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.selfURL, nil)
	if err != nil {
		return User{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return User{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return User{}, ErrUnauthorized
	default:
		return User{}, fmt.Errorf("%w: GET %s answered %d", ErrUnavailable, selfPath, resp.StatusCode)
	}

	var self struct {
		QualifiedID struct {
			Domain string `json:"domain"`
			ID     string `json:"id"`
		} `json:"qualified_id"`
		Team *string `json:"team"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&self); err != nil {
		return User{}, fmt.Errorf("%w: decode %s: %w", ErrUnavailable, selfPath, err)
	}
	user := User{QualifiedID: QualifiedID{
		Domain: strings.ToLower(self.QualifiedID.Domain),
		ID:     strings.ToLower(self.QualifiedID.ID),
	}}
	if !IsDomain(user.Domain) || !IsUUID(user.ID) {
		return User{}, fmt.Errorf("%w: %s returned no valid qualified_id", ErrUnavailable, selfPath)
	}
	if self.Team != nil {
		user.Team = strings.ToLower(*self.Team)
		if !IsUUID(user.Team) {
			return User{}, fmt.Errorf("%w: %s returned no valid team", ErrUnavailable, selfPath)
		}
	}
	return user, nil
}

// plausibleToken reports whether token can be sent in a header: not empty, not too long, only visible ASCII. It does
// not look at the token's format; that is up to the backend.
func plausibleToken(token string) bool {
	if token == "" || len(token) > maxTokenLength {
		return false
	}
	for _, c := range []byte(token) {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// IsDomain reports whether s consists of lowercase letters, digits, hyphens and dots, at most 253 characters.
func IsDomain(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// IsUUID reports whether s is a UUID in the form 8-4-4-4-12 with lowercase hexadecimal digits.
func IsUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}
