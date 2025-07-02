package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"friend-cal-app/data"
	"friend-cal-app/view"
	"os" // For reading environment variables

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

var (
	googleOauthConfig *oauth2.Config
	oauthStateString  = "random" // In a real app, generate a random string for security
)

//go:generate templ generate

var (
	events = make(map[string]*data.Event)
	mu     sync.Mutex
	// sessions maps a random session ID (the cookie value) to a Google user ID.
	sessions = make(map[string]string)
	// users maps a Google user ID to a User object.
	users = make(map[string]*data.User)
)

func main() {
	// --- OAUTH SETUP ---
	// In a real app, load these from environment variables or a secret manager
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),     // <-- PLACE YOURS HERE (or in an env var)
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"), // <-- PLACE YOURS HERE (or in an env var)
		Scopes: []string{
			"https://www.googleapis.com/auth/calendar.events",
			"https://www.googleapis.com/auth/contacts.readonly",
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}
	// --- END OAUTH SETUP ---
	mux := http.NewServeMux()

	// 1. Register all your specific page handlers first.
	mux.HandleFunc("GET /", handleShowCreatePage)
	mux.HandleFunc("POST /create", handleCreateEvent)
	mux.HandleFunc("GET /event/{id}", handleShowEventPage)
	mux.HandleFunc("POST /event/{id}/vote", handleVote)
	mux.HandleFunc("GET /event/{id}/organizer", handleShowOrganizerPage)
	mux.HandleFunc("GET /thanks", handleThanksPage)
	mux.HandleFunc("GET /auth/google/login", handleGoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", handleGoogleCallback)
	mux.HandleFunc("GET /auth/google/logout", handleLogout)
	mux.HandleFunc("GET /my-events", handleMyEvents)

	// 2. Register the file server using HandleFunc on a GET request.
	fileServer := http.FileServer(http.Dir("./static"))
	mux.HandleFunc("GET /static/{path...}", http.StripPrefix("/static/", fileServer).ServeHTTP)

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauthConfig.AuthCodeURL(oauthStateString)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the session cookie.
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Tells the browser to delete the cookie
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// getUser finds a user based on the session cookie in the request.
// Returns nil if the user is not logged in.
func getUser(r *http.Request) *data.User {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}

	mu.Lock()
	defer mu.Unlock()
	googleID, ok := sessions[cookie.Value]
	if !ok {
		return nil
	}

	return users[googleID]
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != oauthStateString {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	token, err := googleOauthConfig.Exchange(context.Background(), r.FormValue("code"))
	if err != nil {
		fmt.Printf("could not get token: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Use the token to get an API client.
	client := googleOauthConfig.Client(context.Background(), token)
	peopleService, err := people.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		fmt.Printf("could not create people service: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Get the user's profile information.
	person, err := peopleService.People.Get("people/me").PersonFields("names,emailAddresses").Do()
	if err != nil {
		fmt.Printf("could not get person: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Extract user info and store it.
	mu.Lock()
	googleID := person.ResourceName[len("people/"):]
	user := &data.User{
		GoogleID:    googleID,
		Name:        person.Names[0].DisplayName,
		Email:       person.EmailAddresses[0].Value,
		AccessToken: token,
	}
	users[googleID] = user

	// Create a new session.
	sessionID := uuid.New().String()
	sessions[sessionID] = googleID
	mu.Unlock()

	// Set a secure cookie on the user's browser.
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,         // Makes the cookie inaccessible to JavaScript
		Secure:   r.TLS != nil, // Only send over HTTPS in production
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to the home page.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleShowCreatePage(w http.ResponseWriter, r *http.Request) {
	// Get the current user. It will be nil if they're not logged in.
	user := getUser(r) // Get the current user
	// Pass the user to the view.
	fmt.Printf("User on homepage: %+v\n", user)
	view.CreatePage(user).Render(context.Background(), w)
}

func handleCreateEvent(w http.ResponseWriter, r *http.Request) {
	// Get the logged-in user.
	user := getUser(r)
	if user == nil {
		// Redirect to login if they aren't signed in.
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}
	r.ParseForm()
	eventName := r.FormValue("eventName")
	datesStr := r.FormValue("dates")
	dates := strings.Split(datesStr, ",")
	for i, d := range dates {
		dates[i] = strings.TrimSpace(d)
	}

	mu.Lock()
	defer mu.Unlock()

	eventID := uuid.New().String()[:8]
	events[eventID] = &data.Event{
		Name:        eventName,
		Dates:       dates,
		Votes:       make(map[string][]string),
		OrganizerID: user.GoogleID,
	}

	http.Redirect(w, r, "/event/"+eventID+"/organizer", http.StatusSeeOther)
}

func handleShowEventPage(w http.ResponseWriter, r *http.Request) {
	user := getUser(r) // Get the current user
	eventID := r.PathValue("id")
	mu.Lock()
	event, ok := events[eventID]
	mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}
	view.EventPage(*event, eventID, user).Render(context.Background(), w)
}

func handleMyEvents(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	organized := make(map[string]*data.Event)
	attending := make(map[string]*data.Event)

	mu.Lock()
	for id, event := range events {
		// Check if the user organized this event
		if event.OrganizerID == user.GoogleID {
			organized[id] = event
			continue // Don't show an organized event in the attending list too
		}

		// New, reliable check for attendance.
		for _, voterIDs := range event.Votes {
			for _, voterID := range voterIDs {
				if voterID == user.GoogleID {
					attending[id] = event
					break // Found user, no need to check other dates
				}
			}
		}
	}
	mu.Unlock()

	view.MyEventsPage(user, organized, attending).Render(context.Background(), w)
}

func handleVote(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}
	eventID := r.PathValue("id")
	r.ParseForm()
	votedDates := r.Form["dates"]

	mu.Lock()
	defer mu.Unlock()

	event, ok := events[eventID]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// First, remove any previous votes from this user to allow them to change their vote.
	for date, voterIDs := range event.Votes {
		newVoterIDs := []string{}
		for _, voterID := range voterIDs {
			if voterID != user.GoogleID {
				newVoterIDs = append(newVoterIDs, voterID)
			}
		}
		event.Votes[date] = newVoterIDs
	}

	if len(votedDates) > 0 {
		for _, date := range votedDates {
			event.Votes[date] = append(event.Votes[date], user.GoogleID)
		}
	}

	// Instead of rendering a component, redirect to the new page.
	http.Redirect(w, r, "/thanks", http.StatusSeeOther)
}

func handleShowOrganizerPage(w http.ResponseWriter, r *http.Request) {
	user := getUser(r) // Get the current user
	eventID := r.PathValue("id")
	mu.Lock()
	event, ok := events[eventID]
	mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	organizerURL := fmt.Sprintf("/event/%s/organizer", eventID)
	guestURL := fmt.Sprintf("/event/%s", eventID)
	view.OrganizerPage(*event, eventID, organizerURL, guestURL, user, users).Render(context.Background(), w)
}

func handleThanksPage(w http.ResponseWriter, r *http.Request) {
	user := getUser(r) // Get the current user
	view.ThanksPage(user).Render(context.Background(), w)
}
