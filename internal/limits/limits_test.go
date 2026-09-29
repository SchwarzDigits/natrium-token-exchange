package limits

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var start = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func newLimiter(t *testing.T, tokens, keys Limit) *Limiter {
	t.Helper()
	l, err := New(tokens, keys)
	require.NoError(t, err)
	return l
}

func TestTokensPerWindow(t *testing.T) {
	l := newLimiter(t, Limit{N: 3, Window: time.Hour}, Limit{N: 10, Window: 24 * time.Hour})
	for i := range 3 {
		require.True(t, l.Take("alice", "k", start.Add(time.Duration(i)*time.Minute)).Allowed)
	}
	d := l.Take("alice", "k", start.Add(10*time.Minute))
	require.False(t, d.Allowed)
	require.Equal(t, ReasonTokens, d.Reason)
	require.Equal(t, 50*time.Minute, d.RetryAfter, "until the first token leaves the window")

	require.True(t, l.Take("bob", "k", start.Add(10*time.Minute)).Allowed, "users are counted apart")
	require.True(t, l.Take("alice", "k", start.Add(time.Hour)).Allowed, "the first token has left the window")
	require.False(t, l.Take("alice", "k", start.Add(time.Hour)).Allowed)
}

func TestRefusalsAreNotCounted(t *testing.T) {
	l := newLimiter(t, Limit{N: 1, Window: time.Hour}, Limit{N: 10, Window: time.Hour})
	require.True(t, l.Take("alice", "k", start).Allowed)
	for range 5 {
		require.False(t, l.Take("alice", "k", start.Add(time.Minute)).Allowed)
	}
	require.True(t, l.Take("alice", "k", start.Add(time.Hour)).Allowed)
}

func TestDistinctKeysInUse(t *testing.T) {
	l := newLimiter(t, Limit{N: 100, Window: time.Hour}, Limit{N: 2, Window: 24 * time.Hour})
	require.True(t, l.Take("alice", "k1", start).Allowed)
	require.True(t, l.Take("alice", "k2", start.Add(time.Hour)).Allowed)
	require.True(t, l.Take("alice", "k1", start.Add(2*time.Hour)).Allowed, "a key in use counts once")

	d := l.Take("alice", "k3", start.Add(3*time.Hour))
	require.False(t, d.Allowed)
	require.Equal(t, ReasonKeys, d.Reason)
	require.Equal(t, 22*time.Hour, d.RetryAfter, "until k2, used longest ago, leaves the window")

	require.True(t, l.Take("bob", "k3", start.Add(3*time.Hour)).Allowed, "keys are counted per user")
	require.True(t, l.Take("alice", "k3", start.Add(25*time.Hour)).Allowed, "k2 has left the window")
	require.False(t, l.Take("alice", "k4", start.Add(25*time.Hour)).Allowed, "k1 was used again at +2h")
}

func TestSweepForgetsIdleUsers(t *testing.T) {
	l := newLimiter(t, Limit{N: 5, Window: time.Hour}, Limit{N: 5, Window: 2 * time.Hour})
	l.Take("alice", "k", start)
	l.Take("bob", "k", start.Add(90*time.Minute))
	require.Equal(t, 2, l.Users())
	require.Equal(t, 2, l.Sweep(start.Add(90*time.Minute)))
	require.Equal(t, 1, l.Sweep(start.Add(2*time.Hour)), "alice's key has left its window")
	require.Equal(t, 0, l.Sweep(start.Add(4*time.Hour)))
}

func TestConcurrentTakesKeepTheLimit(t *testing.T) {
	l := newLimiter(t, Limit{N: 50, Window: time.Hour}, Limit{N: 1000, Window: time.Hour})
	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for i := range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.Take("alice", fmt.Sprint(i), start).Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	require.Equal(t, 50, allowed)
}

func TestRunStopsWithTheContext(t *testing.T) {
	l := newLimiter(t, Limit{N: 1, Window: time.Second}, Limit{N: 1, Window: time.Second})
	l.Take("alice", "k", time.Now())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		l.Run(ctx, 10*time.Millisecond)
		close(done)
	}()
	require.Eventually(t, func() bool { return l.Users() == 0 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	<-done
}

func TestParseLimit(t *testing.T) {
	l, err := ParseLimit(" 60/1h ")
	require.NoError(t, err)
	require.Equal(t, Limit{N: 60, Window: time.Hour}, l)
	require.Equal(t, "60/1h0m0s", l.String())

	for _, bad := range []string{"", "60", "x/1h", "60/x", "0/1h", "-1/1h", "5/500ms"} {
		_, err := ParseLimit(bad)
		require.Error(t, err, bad)
	}
}

func TestNewChecksTheLimits(t *testing.T) {
	_, err := New(Limit{N: 0, Window: time.Hour}, Limit{N: 1, Window: time.Hour})
	require.Error(t, err)
	_, err = New(Limit{N: 1, Window: time.Hour}, Limit{N: 1, Window: 0})
	require.Error(t, err)
}

func TestTokensWithoutKeyCountOnlyAsTokens(t *testing.T) {
	l := newLimiter(t, Limit{N: 3, Window: time.Hour}, Limit{N: 1, Window: 24 * time.Hour})
	require.True(t, l.Take("alice", "k1", start).Allowed)
	require.True(t, l.Take("alice", "", start).Allowed, "no key, so the full key limit does not apply")
	require.True(t, l.Take("alice", "", start).Allowed)
	d := l.Take("alice", "", start)
	require.False(t, d.Allowed)
	require.Equal(t, ReasonTokens, d.Reason)
}
