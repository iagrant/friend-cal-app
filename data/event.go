package data

import (
	"golang.org/x/oauth2"
)

// Event holds all the information for a single event poll.
// Note that all fields start with a capital letter, making them public.
type Event struct {
	Name        string
	Dates       []string
	Votes       map[string][]string
	OrganizerID string
	StartTime   string
	EndTime     string
	Timezone    string
	Location    string
	Description string
}

type User struct {
	GoogleID    string
	Name        string
	Email       string
	AccessToken *oauth2.Token
}
