package data

import (
	"golang.org/x/oauth2"
)

type Event struct {
	Name        string
	Uuid        string
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
	PhotoURL    string
	AccessToken *oauth2.Token
	CSRFToken   string
}
