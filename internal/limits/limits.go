// Package limits bounds what one user can get from one instance of the service: the tokens issued in a window, and
// the distinct client keys in use in a window. A key is in use from its last token until a whole window has passed. A
// token without a key counts only against the tokens.
//
// The counts are kept in memory. The service has no store, so with several instances each one counts on its own, and
// a user can get up to the limit from each.
package limits

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Reasons for a refusal, in Decision.Reason.
const (
	ReasonTokens = "tokens"
	ReasonKeys   = "keys"
)

// Limit allows N within Window.
type Limit struct {
	N      int
	Window time.Duration
}

// String returns the limit in the form ParseLimit reads, e.g. 60/1h0m0s.
func (l Limit) String() string {
	return strconv.Itoa(l.N) + "/" + l.Window.String()
}

// Check reports whether the limit allows at least one in a window of at least one second.
func (l Limit) Check() error {
	switch {
	case l.N < 1:
		return fmt.Errorf("%s: at least 1 is required", l)
	case l.Window < time.Second:
		return fmt.Errorf("%s: the window must be at least one second", l)
	}
	return nil
}

// ParseLimit reads a limit of the form <n>/<window>, e.g. 60/1h or 10/24h.
func ParseLimit(s string) (Limit, error) {
	n, window, ok := strings.Cut(strings.TrimSpace(s), "/")
	if !ok {
		return Limit{}, fmt.Errorf("%q must be <n>/<window>, e.g. 60/1h", s)
	}
	count, err := strconv.Atoi(n)
	if err != nil {
		return Limit{}, fmt.Errorf("%q is not a number", n)
	}
	d, err := time.ParseDuration(window)
	if err != nil {
		return Limit{}, fmt.Errorf("%q is not a duration, e.g. 1h or 24h", window)
	}
	l := Limit{N: count, Window: d}
	return l, l.Check()
}

// Decision is the answer of Take. RetryAfter is set when a request is refused: the time until it would be allowed.
type Decision struct {
	Allowed    bool
	RetryAfter time.Duration
	Reason     string
}

// usage is what one user got within the windows.
type usage struct {
	// issued holds the times of the tokens within the token window, oldest first.
	issued []time.Time
	// keys holds the last use of each key within the key window.
	keys map[string]time.Time
}

// Limiter counts per user. It is safe for concurrent use.
type Limiter struct {
	tokens Limit
	keys   Limit

	mu    sync.Mutex
	users map[string]*usage
}

// New returns a limiter for the given limits, which must pass Check.
func New(tokens, keys Limit) (*Limiter, error) {
	if err := errors.Join(tokens.Check(), keys.Check()); err != nil {
		return nil, err
	}
	return &Limiter{tokens: tokens, keys: keys, users: map[string]*usage{}}, nil
}

// Take records a token for user and key at now if both limits allow it. An empty key is a token without a key, which
// only the token limit applies to. A refused request is not recorded.
func (l *Limiter) Take(user, key string, now time.Time) Decision {
	l.mu.Lock()
	defer l.mu.Unlock()
	u := l.users[user]
	if u == nil {
		u = &usage{keys: map[string]time.Time{}}
	}
	l.prune(u, now)

	if len(u.issued) >= l.tokens.N {
		return Decision{RetryAfter: u.issued[0].Add(l.tokens.Window).Sub(now), Reason: ReasonTokens}
	}
	if _, known := u.keys[key]; key != "" && !known && len(u.keys) >= l.keys.N {
		oldest := now
		for _, used := range u.keys {
			if used.Before(oldest) {
				oldest = used
			}
		}
		return Decision{RetryAfter: oldest.Add(l.keys.Window).Sub(now), Reason: ReasonKeys}
	}
	u.issued = append(u.issued, now)
	if key != "" {
		u.keys[key] = now
	}
	l.users[user] = u
	return Decision{Allowed: true}
}

// prune drops the tokens and keys whose window has passed at now.
func (l *Limiter) prune(u *usage, now time.Time) {
	i := 0
	for i < len(u.issued) && !now.Before(u.issued[i].Add(l.tokens.Window)) {
		i++
	}
	u.issued = u.issued[i:]
	for key, used := range u.keys {
		if !now.Before(used.Add(l.keys.Window)) {
			delete(u.keys, key)
		}
	}
}

// Sweep forgets the users whose tokens and keys have all left their windows at now, and returns how many users are
// still counted.
func (l *Limiter) Sweep(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for user, u := range l.users {
		l.prune(u, now)
		if len(u.issued) == 0 && len(u.keys) == 0 {
			delete(l.users, user)
		}
	}
	return len(l.users)
}

// Users returns how many users are counted.
func (l *Limiter) Users() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.users)
}

// Run sweeps every interval until ctx is canceled.
func (l *Limiter) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.Sweep(now)
		}
	}
}
