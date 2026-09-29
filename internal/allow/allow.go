// Package allow decides which Wire users may get a token, from four lists: allowed and denied teams, allowed and
// denied users. Each list holds IDs or "*" for all.
//
// The most specific matching entry decides, and at the same specificity a denial wins:
//
//  1. the user's own qualified ID in DeniedUsers, then in AllowedUsers;
//  2. the user's team in DeniedTeams, then in AllowedTeams;
//  3. "*" in DeniedTeams, then in AllowedTeams, for a user who has a team;
//  4. "*" in DeniedUsers, then in AllowedUsers;
//  5. otherwise the user is denied.
//
// A user without a team matches no team entry, so "*" in AllowedTeams admits every member of a team and nobody else.
package allow

import (
	"errors"
	"fmt"
	"strings"

	"github.com/SchwarzDigits/natrium-token-exchange/internal/wireauth"
)

// Wildcard in a list matches every team, or every user.
const Wildcard = "*"

// Rules are the four lists as configured. Entries are compared in lowercase.
type Rules struct {
	// AllowedTeams and DeniedTeams hold team UUIDs or "*".
	AllowedTeams []string
	DeniedTeams  []string
	// AllowedUsers and DeniedUsers hold qualified IDs of the form <uuid>@<domain> or "*".
	AllowedUsers []string
	DeniedUsers  []string
}

// entries is one parsed list.
type entries struct {
	all bool
	ids map[string]bool
}

func (e entries) has(id string) bool {
	return e.ids[id]
}

func (e entries) empty() bool {
	return !e.all && len(e.ids) == 0
}

func (e entries) size() string {
	if e.all {
		return Wildcard
	}
	return fmt.Sprint(len(e.ids))
}

// List decides admissions. Its zero value admits nobody.
type List struct {
	allowedTeams, deniedTeams, allowedUsers, deniedUsers entries
}

// New parses the rules. At least one entry in AllowedTeams or AllowedUsers is required, since otherwise nobody could
// be admitted.
func New(r Rules) (List, error) {
	var l List
	var err error
	if l.allowedTeams, err = parse(r.AllowedTeams, checkTeam); err != nil {
		return List{}, fmt.Errorf("allowed teams: %w", err)
	}
	if l.deniedTeams, err = parse(r.DeniedTeams, checkTeam); err != nil {
		return List{}, fmt.Errorf("denied teams: %w", err)
	}
	if l.allowedUsers, err = parse(r.AllowedUsers, checkUser); err != nil {
		return List{}, fmt.Errorf("allowed users: %w", err)
	}
	if l.deniedUsers, err = parse(r.DeniedUsers, checkUser); err != nil {
		return List{}, fmt.Errorf("denied users: %w", err)
	}
	if l.allowedTeams.empty() && l.allowedUsers.empty() {
		return List{}, errors.New("at least one allowed team or allowed user is required")
	}
	return l, nil
}

// CheckTeams reports whether every entry is a team UUID or "*".
func CheckTeams(list []string) error {
	_, err := parse(list, checkTeam)
	return err
}

// CheckUsers reports whether every entry is a qualified ID <uuid>@<domain> or "*".
func CheckUsers(list []string) error {
	_, err := parse(list, checkUser)
	return err
}

func parse(list []string, check func(string) error) (entries, error) {
	e := entries{ids: map[string]bool{}}
	for _, raw := range list {
		id := strings.ToLower(strings.TrimSpace(raw))
		if id == Wildcard {
			e.all = true
			continue
		}
		if err := check(id); err != nil {
			return entries{}, err
		}
		e.ids[id] = true
	}
	return e, nil
}

func checkTeam(id string) error {
	if !wireauth.IsUUID(id) {
		return fmt.Errorf("team %q is neither a UUID nor %q", id, Wildcard)
	}
	return nil
}

func checkUser(id string) error {
	uuid, domain, ok := strings.Cut(id, "@")
	if !ok || !wireauth.IsUUID(uuid) || !wireauth.IsDomain(domain) {
		return fmt.Errorf("user %q is neither a qualified ID of the form <uuid>@<domain> nor %q", id, Wildcard)
	}
	return nil
}

// Split reads a comma-separated list. Empty entries are skipped, so an empty string gives no entries.
func Split(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

// Admits reports whether u may get a token, by the rules in the package documentation.
func (l List) Admits(u wireauth.User) bool {
	user := u.String()
	switch {
	case l.deniedUsers.has(user):
		return false
	case l.allowedUsers.has(user):
		return true
	}
	if u.Team != "" {
		switch {
		case l.deniedTeams.has(u.Team):
			return false
		case l.allowedTeams.has(u.Team):
			return true
		case l.deniedTeams.all:
			return false
		case l.allowedTeams.all:
			return true
		}
	}
	return !l.deniedUsers.all && l.allowedUsers.all
}

// LogAttrs returns the size of each list, or "*", for the log at start.
func (l List) LogAttrs() []any {
	return []any{
		"allowed_teams", l.allowedTeams.size(),
		"denied_teams", l.deniedTeams.size(),
		"allowed_users", l.allowedUsers.size(),
		"denied_users", l.deniedUsers.size(),
	}
}
