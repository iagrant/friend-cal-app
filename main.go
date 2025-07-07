package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"crypto/rand"
	"encoding/base64"
	"friend-cal-app/data"
	"friend-cal-app/view"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

//go:generate templ generate

var (
	googleOauthConfig *oauth2.Config
	events            = make(map[string]*data.Event)
	mu                sync.Mutex
	// sessions maps a random session ID (the cookie value) to a Google user ID.
	sessions = make(map[string]string)
	// users maps a Google user ID to a User object.
	users = make(map[string]*data.User)
)

func main() {
	// --- OAUTH SETUP ---
	googleOauthConfig = &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/google/callback",
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
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
	mux.HandleFunc("POST /event/{id}/finalize", handleFinalizeEvent)
	mux.HandleFunc("GET /finalize-success", handleFinalizeSuccess)
	mux.HandleFunc("GET /event/{id}/edit", handleShowEditEventPage)
	mux.HandleFunc("POST /event/{id}/edit", handleUpdateEvent)
	mux.HandleFunc("POST /event/{id}/delete", handleDeleteEvent)

	// 2. Register the file server using HandleFunc on a GET request.
	fileServer := http.FileServer(http.Dir("./static"))
	mux.HandleFunc("GET /static/{path...}", http.StripPrefix("/static/", fileServer).ServeHTTP)

	fmt.Println("Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	redirectURL := r.URL.Query().Get("redirect_url")
	if redirectURL != "" {
		// If it exists, store it in a temporary cookie.
		http.SetCookie(w, &http.Cookie{
			Name:     "login_redirect_url",
			Value:    redirectURL,
			Path:     "/",
			Expires:  time.Now().Add(10 * time.Minute),
			HttpOnly: true,
		})
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute), // Cookie expires in 10 minutes
		HttpOnly: true,
	})

	url := googleOauthConfig.AuthCodeURL(state)
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
	// 1. Read the state value from the cookie.
	oauthState, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Failed to read state cookie", http.StatusBadRequest)
		return
	}

	// 2. Compare the cookie's state with the state from the redirect URL.
	if r.FormValue("state") != oauthState.Value {
		http.Error(w, "Invalid oauth state", http.StatusBadRequest)
		return
	}

	// 3. Clean up by deleting the state cookie.
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1, // Deletes the cookie
	})

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
	person, err := peopleService.People.Get("people/me").PersonFields("names,emailAddresses,photos").Do()
	if err != nil {
		fmt.Printf("could not get person: %s\n", err.Error())
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	photoURL := ""
	if len(person.Photos) > 0 && person.Photos[0].Url != "" {
		photoURL = person.Photos[0].Url
	}

	// Extract user info and store it.
	mu.Lock()
	googleID := person.ResourceName[len("people/"):]
	user := &data.User{
		GoogleID:    googleID,
		Name:        person.Names[0].DisplayName,
		Email:       person.EmailAddresses[0].Value,
		PhotoURL:    photoURL,
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
	redirectCookie, err := r.Cookie("login_redirect_url")
	if err == nil && redirectCookie.Value != "" {
		// If it exists, redirect there.
		url := redirectCookie.Value

		// Clean up the redirect cookie.
		http.SetCookie(w, &http.Cookie{
			Name:   "login_redirect_url",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})

		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	// Redirect to the home page.
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleShowCreatePage(w http.ResponseWriter, r *http.Request) {
	// Get the current user. It will be nil if they're not logged in.
	user := getUser(r) // Get the current user
	// Pass the user to the view.
	//fmt.Printf("User on homepage: %+v\n", user)
	view.CreatePage(user).Render(context.Background(), w)
}

func handleCreateEvent(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	r.ParseForm()

	// Get the timezone from the cookie.
	tzCookie, _ := r.Cookie("timezone")
	userTimezone := "UTC" // Default to UTC if no cookie
	if tzCookie != nil {
		userTimezone = tzCookie.Value
	}

	// Get all other form values.
	eventName := r.FormValue("eventName")
	location := r.FormValue("location")
	startTimeStr := r.FormValue("startTime")
	endTimeStr := r.FormValue("endTime")
	datesStr := r.FormValue("dates")
	description := r.FormValue("description")
	dates := strings.Split(datesStr, ",")
	if datesStr == "" || len(dates) == 0 || dates[0] == "" {
		http.Error(w, "Please select at least one date.", http.StatusBadRequest)
		return
	}
	for i, d := range dates {
		dates[i] = strings.TrimSpace(d)
	}

	mu.Lock()
	defer mu.Unlock()

	eventID := uuid.New().String()
	events[eventID] = &data.Event{
		Name:        eventName,
		Location:    location,
		Dates:       dates,
		Votes:       make(map[string][]string),
		OrganizerID: user.GoogleID,
		StartTime:   startTimeStr,
		EndTime:     endTimeStr,
		Timezone:    userTimezone,
		Description: description,
	}

	http.Redirect(w, r, "/event/"+eventID+"/organizer", http.StatusSeeOther)
}

func handleShowEventPage(w http.ResponseWriter, r *http.Request) {
	// Get user's display preferences from cookies
	formatPref := getFormatPreference(r)

	user := getUser(r)
	eventID := r.PathValue("id")

	mu.Lock()
	event, ok := events[eventID]
	mu.Unlock() // Unlock after reading from shared maps

	if !ok {
		http.NotFound(w, r)
		return
	}

	userVotes := make(map[string]bool)
	if user != nil {
		mu.Lock()
		for date, voterIDs := range event.Votes {
			for _, voterID := range voterIDs {
				if voterID == user.GoogleID {
					userVotes[date] = true
				}
			}
		}
		mu.Unlock()
	}

	// Pass all necessary data to the template
	view.EventPage(*event, eventID, user, userVotes, r.URL.String(), formatPref).Render(context.Background(), w)
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
	defer mu.Unlock()

	for id, event := range events {

		// Check if the user organized this event
		if event.OrganizerID == user.GoogleID {
			organized[id] = event
			//continue //this continue is being removed so events you organize show up in attending list. not sure if im a fan of that tho...
		}

	AttendLoop:
		// Now, always check for attendance, even if they are the organizer.
		for _, voterIDs := range event.Votes {
			for _, voterID := range voterIDs {
				if voterID == user.GoogleID {
					attending[id] = event
					break AttendLoop // Found user, stop checking this event
				}
			}
		}
	}

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
	if user == nil {
		// If not, redirect to the login page, remembering where they tried to go.
		loginURL := fmt.Sprintf("/auth/google/login?redirect_url=%s", r.URL.Path)
		http.Redirect(w, r, loginURL, http.StatusSeeOther)
		return
	}

	eventID := r.PathValue("id")
	mu.Lock()
	defer mu.Unlock()
	event, ok := events[eventID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if event.OrganizerID != user.GoogleID {
		// If they aren't the organizer, deny access.
		http.Error(w, "Forbidden: You are not the organizer of this event.", http.StatusForbidden)
		return
	}

	formatPref := getFormatPreference(r)
	organizerURL := fmt.Sprintf("/event/%s/organizer", eventID)
	guestURL := fmt.Sprintf("/event/%s", eventID)
	view.OrganizerPage(*event, eventID, organizerURL, guestURL, user, users, formatPref).Render(context.Background(), w)
}

func handleThanksPage(w http.ResponseWriter, r *http.Request) {
	user := getUser(r) // Get the current user
	view.ThanksPage(user).Render(context.Background(), w)
}

func handleDeleteEvent(w http.ResponseWriter, r *http.Request) {
	// 1. Authentication: Check if a user is logged in.
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	eventID := r.PathValue("id")

	mu.Lock()
	defer mu.Unlock()
	event, ok := events[eventID]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// 2. Authorization: Check if the logged-in user is the event organizer.
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden: You are not the organizer of this event.", http.StatusForbidden)
		return
	}

	// 3. Delete the event from the map.
	delete(events, eventID)

	// 4. Redirect the user to their "My Events" page.
	http.Redirect(w, r, "/my-events", http.StatusSeeOther)
}

func handleFinalizeEvent(w http.ResponseWriter, r *http.Request) {
	// Get User and Event, and check authorization
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}
	eventID := r.PathValue("id")
	mu.Lock()
	event, ok := events[eventID]
	mu.Unlock()
	if !ok || event.OrganizerID != user.GoogleID {
		http.Error(w, "Event not found or you are not the organizer", http.StatusForbidden)
		return
	}
	r.ParseForm()
	finalDate := r.FormValue("finalDate")

	// Gather attendees
	attendeeEmails := []string{}
	uniqueVoterIDs := make(map[string]bool)
	mu.Lock()
	for _, voterIDs := range event.Votes {
		for _, voterID := range voterIDs {
			if !uniqueVoterIDs[voterID] {
				if voter := users[voterID]; voter != nil {
					attendeeEmails = append(attendeeEmails, voter.Email)
				}
				uniqueVoterIDs[voterID] = true
			}
		}
	}
	mu.Unlock()

	// Create a Google Calendar client using the organizer's stored token.
	client := googleOauthConfig.Client(context.Background(), user.AccessToken)
	calService, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		http.Error(w, "Could not create calendar service: "+err.Error(), http.StatusInternalServerError)
		return
	}
	calendarDescription := strings.ReplaceAll(event.Description, "\n", "<br>")
	// Construct the calendar event
	calendarEvent := &calendar.Event{
		Summary:     event.Name,
		Location:    event.Location,
		Description: calendarDescription,
	}

	// Handle timed vs. all-day events
	if event.StartTime != "" && event.EndTime != "" {
		// Use the timezone stored with the event.
		loc, err := time.LoadLocation(event.Timezone)
		if err != nil {
			loc, _ = time.LoadLocation("UTC")
			fmt.Printf("Invalid timezone '%s', defaulting to UTC. Error: %v\n", event.Timezone, err)
		}

		// Combine date and time strings.
		startStr := fmt.Sprintf("%sT%s:00", finalDate, event.StartTime)
		endStr := fmt.Sprintf("%sT%s:00", finalDate, event.EndTime)

		// Parse the full strings in the event's original timezone.
		layout := "2006-01-02T15:04:05"
		startTime, _ := time.ParseInLocation(layout, startStr, loc)
		endTime, _ := time.ParseInLocation(layout, endStr, loc)

		// Validate that the parsed end time is after the start time.
		if !endTime.After(startTime) {
			http.Error(w, "Invalid time range: The end time must be after the start time.", http.StatusBadRequest)
			return
		}

		calendarEvent.Start = &calendar.EventDateTime{
			DateTime: startTime.Format(time.RFC3339),
		}
		calendarEvent.End = &calendar.EventDateTime{
			DateTime: endTime.Format(time.RFC3339),
		}
	} else {
		// All-day event
		calendarEvent.Start = &calendar.EventDateTime{Date: finalDate}
		calendarEvent.End = &calendar.EventDateTime{Date: finalDate}
	}

	// Add attendees to the event.
	for _, email := range attendeeEmails {
		calendarEvent.Attendees = append(calendarEvent.Attendees, &calendar.EventAttendee{Email: email})
	}

	_, err = calService.Events.Insert("primary", calendarEvent).SendUpdates("all").Do()
	if err != nil {
		http.Error(w, "Unable to create calendar event: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/finalize-success", http.StatusSeeOther)
}

func handleFinalizeSuccess(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	view.FinalizeSuccessPage(user).Render(context.Background(), w)
}

func getFormatPreference(r *http.Request) string {
	cookie, err := r.Cookie("time_format")
	if err != nil || (cookie.Value != "12h" && cookie.Value != "24h") {
		return "24h" // Default to 24-hour format
	}
	return cookie.Value
}

func handleShowEditEventPage(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	eventID := r.PathValue("id")
	mu.Lock()
	defer mu.Unlock()
	event, ok := events[eventID]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Authorization check
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	view.EditEventPage(event, eventID, user).Render(context.Background(), w)
}

func handleUpdateEvent(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	eventID := r.PathValue("id")
	mu.Lock()
	defer mu.Unlock()
	event, ok := events[eventID]
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Authorization check
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.ParseForm()

	// Update the event fields with the new values from the form.
	event.Name = r.FormValue("eventName")
	event.Location = r.FormValue("location")
	event.Description = r.FormValue("description")
	event.StartTime = r.FormValue("startTime")
	event.EndTime = r.FormValue("endTime")

	datesStr := r.FormValue("dates")
	event.Dates = strings.Split(datesStr, ",")
	for i, d := range event.Dates {
		event.Dates[i] = strings.TrimSpace(d)
	}

	// Redirect back to the organizer page.
	http.Redirect(w, r, "/event/"+eventID+"/organizer", http.StatusSeeOther)
}
