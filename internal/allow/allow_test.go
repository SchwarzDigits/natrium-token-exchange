package allow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/wireauth"
)

const (
	teamA   = "8b3c1a2e-0f4d-4e5a-9b6c-7d8e9f0a1b2c"
	teamB   = "1f2e3d4c-5b6a-4978-8a9b-0c1d2e3f4a5b"
	teamC   = "5c6d7e8f-9a0b-4c1d-8e2f-3a4b5c6d7e8f"
	aliceID = "39b7f597-dfd1-4dff-86f5-fe1b79cb70a0"
	bobID   = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	alice   = aliceID + "@wire.example"
	bob     = bobID + "@wire.example"
)

func user(id, team string) wireauth.User {
	return wireauth.User{QualifiedID: wireauth.QualifiedID{Domain: "wire.example", ID: id}, Team: team}
}

func mustNew(t *testing.T, r Rules) List {
	t.Helper()
	l, err := New(r)
	require.NoError(t, err)
	return l
}

func TestAdmissions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules Rules
		user  wireauth.User
		want  bool
	}{
		// The expected production setup: every team except the denied ones, no users without a team.
		{"all teams: member of another team", Rules{AllowedTeams: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, teamB), true},
		{"all teams: member of a denied team", Rules{AllowedTeams: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, teamA), false},
		{"all teams: user without a team", Rules{AllowedTeams: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, ""), false},

		{"listed team", Rules{AllowedTeams: []string{teamA}}, user(bobID, teamA), true},
		{"unlisted team", Rules{AllowedTeams: []string{teamA}}, user(bobID, teamB), false},
		{"listed user without a team", Rules{AllowedUsers: []string{alice}}, user(aliceID, ""), true},
		{"listed user in an unlisted team", Rules{AllowedTeams: []string{teamA}, AllowedUsers: []string{alice}},
			user(aliceID, teamB), true},

		{"everyone", Rules{AllowedUsers: []string{"*"}}, user(bobID, ""), true},
		{"everyone except a team: that team", Rules{AllowedUsers: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, teamA), false},
		{"everyone except a team: no team", Rules{AllowedUsers: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, ""), true},
		{"everyone except a team: other team", Rules{AllowedUsers: []string{"*"}, DeniedTeams: []string{teamA}},
			user(bobID, teamB), true},

		{"denied user in an allowed team", Rules{AllowedTeams: []string{teamA}, DeniedUsers: []string{bob}},
			user(bobID, teamA), false},
		{"allowed user in a denied team", Rules{AllowedTeams: []string{"*"}, DeniedTeams: []string{teamA},
			AllowedUsers: []string{alice}}, user(aliceID, teamA), true},
		{"user both allowed and denied", Rules{AllowedUsers: []string{alice}, DeniedUsers: []string{alice}},
			user(aliceID, ""), false},
		{"team both allowed and denied", Rules{AllowedTeams: []string{teamA}, DeniedTeams: []string{teamA}},
			user(bobID, teamA), false},

		{"only one team out of all denied", Rules{AllowedTeams: []string{teamA}, DeniedTeams: []string{"*"}},
			user(bobID, teamA), true},
		{"all teams denied", Rules{AllowedTeams: []string{teamA}, DeniedTeams: []string{"*"}},
			user(bobID, teamB), false},
		{"all teams denied beats all users allowed", Rules{AllowedUsers: []string{"*"}, DeniedTeams: []string{"*"}},
			user(bobID, teamC), false},
		{"all teams denied leaves users without a team", Rules{AllowedUsers: []string{"*"},
			DeniedTeams: []string{"*"}}, user(bobID, ""), true},
		{"all users denied, but a listed team", Rules{AllowedTeams: []string{teamA}, DeniedUsers: []string{"*"}},
			user(bobID, teamA), true},
		{"all users denied beats all users allowed", Rules{AllowedUsers: []string{"*"}, DeniedUsers: []string{"*"}},
			user(bobID, ""), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, mustNew(t, tc.rules).Admits(tc.user))
		})
	}
}

func TestEntriesAreComparedInLowercase(t *testing.T) {
	l := mustNew(t, Rules{
		AllowedTeams: []string{strings.ToUpper(teamA)},
		DeniedUsers:  []string{" " + strings.ToUpper(bob) + " "},
	})
	require.True(t, l.Admits(user(aliceID, teamA)))
	require.False(t, l.Admits(user(bobID, teamA)))
}

func TestZeroListAdmitsNobody(t *testing.T) {
	require.False(t, List{}.Admits(user(aliceID, teamA)))
}

func TestNewRejectsInvalidRules(t *testing.T) {
	for name, r := range map[string]Rules{
		"nothing allowed":     {},
		"only denials":        {DeniedTeams: []string{"*"}, DeniedUsers: []string{bob}},
		"team not a UUID":     {AllowedTeams: []string{"sales"}},
		"denied team":         {AllowedTeams: []string{"*"}, DeniedTeams: []string{"sales"}},
		"user without @":      {AllowedUsers: []string{aliceID}},
		"user bad domain":     {AllowedUsers: []string{aliceID + "@wire|example"}},
		"user not a UUID":     {AllowedUsers: []string{"alice@wire.example"}},
		"denied user":         {AllowedUsers: []string{"*"}, DeniedUsers: []string{"bob"}},
		"blank allowed teams": {AllowedTeams: []string{" "}},
		"double star":         {AllowedTeams: []string{"**"}},
	} {
		_, err := New(r)
		require.Error(t, err, name)
	}
}

func TestCheckLists(t *testing.T) {
	require.NoError(t, CheckTeams([]string{"*", teamA}))
	require.Error(t, CheckTeams([]string{"x"}))
	require.NoError(t, CheckUsers([]string{"*", alice}))
	require.Error(t, CheckUsers([]string{"x"}))
}

func TestLogAttrs(t *testing.T) {
	l := mustNew(t, Rules{AllowedTeams: []string{"*"}, DeniedTeams: []string{teamA, teamB}})
	require.Equal(t, []any{"allowed_teams", "*", "denied_teams", "2", "allowed_users", "0", "denied_users", "0"},
		l.LogAttrs())
}

func TestSplit(t *testing.T) {
	require.Nil(t, Split(""))
	require.Nil(t, Split(" , ,"))
	require.Equal(t, []string{"a", "b"}, Split(" a,, b ,"))
}
