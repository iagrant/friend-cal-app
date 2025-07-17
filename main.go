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

	"friend-cal-app/db"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/calendar/v3"
	"google.golang.org/api/option"
	"google.golang.org/api/people/v1"
)

//go:generate templ generate

var (
	googleOauthConfig *oauth2.Config
	dbQueries         *db.Queries
	mu                sync.Mutex
	// sessions maps a random session ID (the cookie value) to a Google user ID.
	sessions = make(map[string]string)
	// users maps a Google user ID to a User object.
	users = make(map[string]*data.User)
)

func main() {
	// --- DB Conn ---
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}
	defer conn.Close(ctx)
	dbQueries = db.New(conn)
	// --- End DB Conn ---

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
	mux.HandleFunc("GET /event/{uuid}", handleShowEventPage)
	mux.HandleFunc("POST /event/{uuid}/vote", handleVote)
	mux.HandleFunc("GET /event/{uuid}/organizer", handleShowOrganizerPage)
	mux.HandleFunc("GET /thanks", handleThanksPage)
	mux.HandleFunc("GET /auth/google/login", handleGoogleLogin)
	mux.HandleFunc("GET /auth/google/callback", handleGoogleCallback)
	mux.HandleFunc("GET /auth/google/logout", handleLogout)
	mux.HandleFunc("GET /my-events", handleMyEvents)
	mux.HandleFunc("POST /event/{uuid}/finalize", handleFinalizeEvent)
	mux.HandleFunc("GET /finalize-success", handleFinalizeSuccess)
	mux.HandleFunc("GET /event/{uuid}/edit", handleShowEditEventPage)
	mux.HandleFunc("POST /event/{uuid}/edit", handleUpdateEvent)
	mux.HandleFunc("POST /event/{uuid}/delete", handleDeleteEvent)

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
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
	})

	url := googleOauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "session_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
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
		http.Redirect(w, r, "/?error="+"Please+select+at+least+one+date.", http.StatusSeeOther)
		return
	}
	for i, d := range dates {
		dates[i] = strings.TrimSpace(d)
	}

	// Validate start and end times if both are provided
	if startTimeStr != "" && endTimeStr != "" {
		// Assuming time format is HH:MM
		start, err := time.Parse("15:04", startTimeStr)
		if err != nil {
			http.Redirect(w, r, "/?error="+"Invalid+start+time+format.+Please+use+HH:MM.", http.StatusSeeOther)
			return
		}
		end, err := time.Parse("15:04", endTimeStr)
		if err != nil {
			http.Redirect(w, r, "/?error="+"Invalid+end+time+format.+Please+use+HH:MM.", http.StatusSeeOther)
			return
		}
		if end.Before(start) {
			http.Redirect(w, r, "/?error="+"End+time+cannot+be+before+start+time.", http.StatusSeeOther)
			return
		}
	}

	params := db.CreateEventParams{
		Name:        eventName,
		Location:    pgtype.Text{String: location, Valid: location != ""},
		Description: pgtype.Text{String: description, Valid: description != ""},
		OrganizerID: user.GoogleID,
		Timezone:    pgtype.Text{String: userTimezone, Valid: userTimezone != ""},
		StartTime:   pgtype.Text{String: startTimeStr, Valid: startTimeStr != ""},
		EndTime:     pgtype.Text{String: endTimeStr, Valid: endTimeStr != ""},
		Dates:       dates,
	}
	event, err := dbQueries.CreateEvent(context.Background(), params)
	log.Printf("CreateEvent params: %+v\n", params)
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to create event", http.StatusInternalServerError)
		return
	}

	// Automatically add the organizer as an attendee
	_, err = dbQueries.CreateAttendee(context.Background(), db.CreateAttendeeParams{
		EventID: event.ID,
		UserID:  user.GoogleID,
		Name:    user.Name,
		Email:   user.Email,
	})
	if err != nil {
		log.Printf("Failed to add organizer as attendee: %v\n", err)
		// This is not a critical error, so we don't return, but log it.
	}

	http.Redirect(w, r, fmt.Sprintf("/event/%s/organizer", event.Uuid), http.StatusSeeOther)
}

func handleShowEventPage(w http.ResponseWriter, r *http.Request) {
	// Get user's display preferences from cookies
	formatPref := getFormatPreference(r)

	user := getUser(r)
	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	dbVotes, err := dbQueries.GetVotesByEvent(context.Background(), event.ID)
	if err != nil {
		http.Error(w, "Failed to get votes", http.StatusInternalServerError)
		return
	}

	votes := make(map[string][]string)
	for _, vote := range dbVotes {
		votes[vote.Date] = append(votes[vote.Date], vote.UserID)
	}

	dataEvent := data.Event{
		Name:        event.Name,
		Dates:       event.Dates,
		Votes:       votes,
		OrganizerID: event.OrganizerID,
		StartTime:   event.StartTime.String,
		EndTime:     event.EndTime.String,
		Timezone:    event.Timezone.String,
		Location:    event.Location.String,
		Description: event.Description.String,
	}

	userVotes := make(map[string]bool)
	if user != nil {
		for _, vote := range dbVotes {
			if vote.UserID == user.GoogleID {
				userVotes[vote.Date] = true
			}
		}
	}

	// Fetch attendees from the database
	dbAttendees, err := dbQueries.GetAttendees(context.Background(), event.ID)
	if err != nil {
		log.Printf("Failed to get attendees: %v\n", err)
		http.Error(w, "Failed to get attendees", http.StatusInternalServerError)
		return
	}

	// Create a map of attendees for easy lookup in the template
	attendeeMap := make(map[string]*data.User)
	mu.Lock()
	for _, attendee := range dbAttendees {
		if u, ok := users[attendee.UserID]; ok {
			attendeeMap[attendee.UserID] = u
		} else {
			// If user not in memory, create a basic user object
			attendeeMap[attendee.UserID] = &data.User{
				GoogleID: attendee.UserID,
				Name:     attendee.Name,
				Email:    attendee.Email,
			}
		}
	}
	mu.Unlock()

	// Ensure organizer is in the attendee map
	if _, ok := attendeeMap[event.OrganizerID]; !ok {
		mu.Lock()
		if u, ok := users[event.OrganizerID]; ok {
			attendeeMap[event.OrganizerID] = u
		} else {
			// Fallback if organizer not in memory (shouldn't happen if logged in)
			attendeeMap[event.OrganizerID] = &data.User{
				GoogleID: event.OrganizerID,
				Name:     "Organizer", // Placeholder name
				Email:    "",
			}
		}
		mu.Unlock()
	}

	// Pass all necessary data to the template
	view.EventPage(dataEvent, eventUUIDStr, user, userVotes, r.URL.String(), formatPref, event.OrganizerID == user.GoogleID).Render(context.Background(), w)
}

func handleMyEvents(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	organizedEvents, err := dbQueries.GetEventsByOrganizer(context.Background(), user.GoogleID)
	if err != nil {
		http.Error(w, "Failed to get organized events", http.StatusInternalServerError)
		return
	}

	attendedEvents, err := dbQueries.GetEventsByAttendee(context.Background(), user.GoogleID)
	if err != nil {
		http.Error(w, "Failed to get attended events", http.StatusInternalServerError)
		return
	}

	// Convert db.Event to data.Event for organized events
	var organizedDataEvents []data.Event
	for _, event := range organizedEvents {
		organizedDataEvents = append(organizedDataEvents, data.Event{
			Name:        event.Name,
			Uuid:        event.Uuid.String(),
			OrganizerID: event.OrganizerID,
		})
	}

	// Convert db.Event to data.Event for attended events
	var attendedDataEvents []data.Event
	for _, event := range attendedEvents {
		attendedDataEvents = append(attendedDataEvents, data.Event{
			Name:        event.Name,
			Uuid:        event.Uuid.String(),
			OrganizerID: event.OrganizerID,
		})
	}

	view.MyEventsPage(user, organizedDataEvents, attendedDataEvents).Render(context.Background(), w)
}

func handleVote(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}
	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	r.ParseForm()
	votedDates := r.Form["dates"]

	// First, remove any previous votes from this user to allow them to change their vote.
	err = dbQueries.DeleteVotesByUser(context.Background(), db.DeleteVotesByUserParams{
		EventID: event.ID,
		UserID:  user.GoogleID,
	})
	if err != nil {
		http.Error(w, "Failed to update votes", http.StatusInternalServerError)
		return
	}

	// Add user to attendees table if not already there
	_, err = dbQueries.GetAttendeeByEventAndUser(context.Background(), db.GetAttendeeByEventAndUserParams{
		EventID: event.ID,
		UserID:  user.GoogleID,
	})
	if err == pgx.ErrNoRows {
		// Attendee does not exist, create them
		_, err = dbQueries.CreateAttendee(context.Background(), db.CreateAttendeeParams{
			EventID: event.ID,
			UserID:  user.GoogleID,
			Name:    user.Name,
			Email:   user.Email,
		})
		if err != nil {
			log.Printf("Failed to add voter as attendee: %v\n", err)
			// This is not a critical error, so we don't return, but log it.
		}
	} else if err != nil {
		log.Printf("Failed to check if voter is attendee: %v\n", err)
		http.Error(w, "Failed to process vote", http.StatusInternalServerError)
		return
	}

	// if len(votedDates) > 0 {
	for _, date := range votedDates {
		_, err := dbQueries.CreateVote(context.Background(), db.CreateVoteParams{
			EventID: event.ID,
			UserID:  user.GoogleID,
			Date:    date,
		})
		if err != nil {
			http.Error(w, "Failed to save vote", http.StatusInternalServerError)
			return
		}
	}
	// }

	// // Instead of rendering a component, redirect to the new page.
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

	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	if event.OrganizerID != user.GoogleID {
		// If they aren't the organizer, deny access.
		http.Error(w, "Forbidden: You are not the organizer of this event.", http.StatusForbidden)
		return
	}

	dbVotes, err := dbQueries.GetVotesByEvent(context.Background(), event.ID)
	if err != nil {
		http.Error(w, "Failed to get votes", http.StatusInternalServerError)
		return
	}

	votes := make(map[string][]string)
	for _, vote := range dbVotes {
		votes[vote.Date] = append(votes[vote.Date], vote.UserID)
	}

	dataEvent := data.Event{
		Name:        event.Name,
		Dates:       event.Dates,
		Votes:       votes,
		OrganizerID: event.OrganizerID,
		StartTime:   event.StartTime.String,
		EndTime:     event.EndTime.String,
		Timezone:    event.Timezone.String,
		Location:    event.Location.String,
		Description: event.Description.String,
	}

	// Calculate percentages
	totalVoters := make(map[string]bool)
	for _, voterIDs := range dataEvent.Votes {
		for _, voterID := range voterIDs {
			totalVoters[voterID] = true
		}
	}
	percentages := make(map[string]string)
	totalVoterCount := len(totalVoters)
	if totalVoterCount > 0 {
		for date, voterIDs := range dataEvent.Votes {
			voteCount := len(voterIDs)
			percentage := (float64(voteCount) / float64(totalVoterCount)) * 100
			percentages[date] = fmt.Sprintf("%.0f%%", percentage)
		}
	}

	// Fetch attendees from the database
	dbAttendees, err := dbQueries.GetAttendees(context.Background(), event.ID)
	if err != nil {
		log.Printf("Failed to get attendees: %v\n", err)
		http.Error(w, "Failed to get attendees", http.StatusInternalServerError)
		return
	}

	// Create a map of attendees for easy lookup in the template
	attendeeMap := make(map[string]*data.User)
	mu.Lock()
	for _, attendee := range dbAttendees {
		if u, ok := users[attendee.UserID]; ok {
			attendeeMap[attendee.UserID] = u
		} else {
			// If user not in memory, create a basic user object
			attendeeMap[attendee.UserID] = &data.User{
				GoogleID: attendee.UserID,
				Name:     attendee.Name,
				Email:    attendee.Email,
			}
		}
	}
	mu.Unlock()

	// Ensure organizer is in the attendee map
	if _, ok := attendeeMap[event.OrganizerID]; !ok {
		mu.Lock()
		if u, ok := users[event.OrganizerID]; ok {
			attendeeMap[event.OrganizerID] = u
		} else {
			// Fallback if organizer not in memory (shouldn't happen if logged in)
			attendeeMap[event.OrganizerID] = &data.User{
				GoogleID: event.OrganizerID,
				Name:     "Organizer", // Placeholder name
				Email:    "",
			}
		}
		mu.Unlock()
	}

	formatPref := getFormatPreference(r)
	view.OrganizerPage(dataEvent, eventUUIDStr, r.URL.String(), "/event/"+eventUUIDStr, user, attendeeMap, formatPref, percentages).Render(context.Background(), w)
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

	// Get event UUID from path
	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	// Get event from DB
	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	// 2. Authorization: Check if the logged-in user is the event organizer.
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden: You are not the organizer of this event.", http.StatusForbidden)
		return
	}

	// 3. Delete the event from the database.
	err = dbQueries.DeleteEvent(context.Background(), event.ID)
	if err != nil {
		log.Println(err)
		http.Error(w, "Failed to delete event", http.StatusInternalServerError)
		return
	}

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
	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Event not found or you are not the organizer", http.StatusForbidden)
		return
	}

	r.ParseForm()
	finalDate := r.FormValue("finalDate")

	// Gather attendees from the attendees table
	dbAttendees, err := dbQueries.GetAttendees(context.Background(), event.ID)
	if err != nil {
		log.Printf("Failed to get attendees from DB: %v\n", err)
		http.Error(w, "Failed to get attendees", http.StatusInternalServerError)
		return
	}

	attendeeEmails := []string{}
	for _, attendee := range dbAttendees {
		attendeeEmails = append(attendeeEmails, attendee.Email)
	}

	// Ensure organizer's email is included if not already there
	organizerEmailIncluded := false
	for _, email := range attendeeEmails {
		if email == user.Email {
			organizerEmailIncluded = true
			break
		}
	}
	if !organizerEmailIncluded {
		attendeeEmails = append(attendeeEmails, user.Email)
	}

	// Create a Google Calendar client using the organizer's stored token.
	client := googleOauthConfig.Client(context.Background(), user.AccessToken)
	calService, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		http.Error(w, "Could not create calendar service: "+err.Error(), http.StatusInternalServerError)
		return
	}
	calendarDescription := strings.ReplaceAll(event.Description.String, "\n", "<br>")
	// Construct the calendar event
	calendarEvent := &calendar.Event{
		Summary:     event.Name,
		Location:    event.Location.String,
		Description: calendarDescription,
	}

	// Handle timed vs. all-day events
	if event.StartTime.String != "" && event.EndTime.String != "" {
		// Use the timezone stored with the event.
		loc, err := time.LoadLocation(event.Timezone.String)
		if err != nil {
			loc, _ = time.LoadLocation("UTC")
			fmt.Printf("Invalid timezone '%s', defaulting to UTC. Error: %v\n", event.Timezone.String, err)
		}

		// Combine date and time strings.
		startStr := fmt.Sprintf("%sT%s:00", finalDate, event.StartTime.String)
		endStr := fmt.Sprintf("%sT%s:00", finalDate, event.EndTime.String)

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

	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}

	// Authorization check
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	dataEvent := data.Event{
		Name:        event.Name,
		Dates:       event.Dates,
		Votes:       make(map[string][]string), // Votes are not needed for the edit page
		OrganizerID: event.OrganizerID,
		StartTime:   event.StartTime.String,
		EndTime:     event.EndTime.String,
		Timezone:    event.Timezone.String,
		Location:    event.Location.String,
		Description: event.Description.String,
	}

	view.EditEventPage(&dataEvent, eventUUIDStr, user).Render(context.Background(), w)
}

func handleUpdateEvent(w http.ResponseWriter, r *http.Request) {
	user := getUser(r)
	if user == nil {
		http.Redirect(w, r, "/auth/google/login", http.StatusSeeOther)
		return
	}

	eventUUIDStr := r.PathValue("uuid")
	eventUUID, err := uuid.Parse(eventUUIDStr)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	// Authorization check
	event, err := dbQueries.GetEventByUUID(context.Background(), pgtype.UUID{Bytes: eventUUID, Valid: true})
	if err != nil {
		if err == pgx.ErrNoRows {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Failed to get event", http.StatusInternalServerError)
		}
		return
	}
	if event.OrganizerID != user.GoogleID {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	r.ParseForm()

	// Get the timezone from the cookie.
	tzCookie, _ := r.Cookie("timezone")
	userTimezone := "UTC" // Default to UTC if no cookie
	if tzCookie != nil {
		userTimezone = tzCookie.Value
	}

	datesStr := r.FormValue("dates")
	dates := strings.Split(datesStr, ",")
	if datesStr == "" || len(dates) == 0 || dates[0] == "" {
		http.Redirect(w, r, fmt.Sprintf("/event/%s/edit?error=%s", eventUUIDStr, "Please+select+at+least+one+date."), http.StatusSeeOther)
		return
	}
	for i, d := range dates {
		dates[i] = strings.TrimSpace(d)
	}

	startTimeStr := r.FormValue("startTime")
	endTimeStr := r.FormValue("endTime")

	// Validate start and end times if both are provided
	if startTimeStr != "" && endTimeStr != "" {
		// Assuming time format is HH:MM
		start, err := time.Parse("15:04", startTimeStr)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/event/%s/edit?error=%s", eventUUIDStr, "Invalid+start+time+format.+Please+use+HH:MM."), http.StatusSeeOther)
			return
		}
		end, err := time.Parse("15:04", endTimeStr)
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/event/%s/edit?error=%s", eventUUIDStr, "Invalid+end+time+format.+Please+use+HH:MM."), http.StatusSeeOther)
			return
		}
		if end.Before(start) {
			http.Redirect(w, r, fmt.Sprintf("/event/%s/edit?error=%s", eventUUIDStr, "End+time+cannot+be+before+start+time."), http.StatusSeeOther)
			return
		}
	}

	params := db.UpdateEventParams{
		Uuid:        pgtype.UUID{Bytes: eventUUID, Valid: true},
		Name:        r.FormValue("eventName"),
		Location:    pgtype.Text{String: r.FormValue("location"), Valid: r.FormValue("location") != ""},
		Description: pgtype.Text{String: r.FormValue("description"), Valid: r.FormValue("description") != ""},
		Timezone:    pgtype.Text{String: userTimezone, Valid: userTimezone != ""},
		StartTime:   pgtype.Text{String: startTimeStr, Valid: startTimeStr != ""},
		EndTime:     pgtype.Text{String: endTimeStr, Valid: endTimeStr != ""},
		Dates:       dates,
	}

	_, err = dbQueries.UpdateEvent(context.Background(), params)
	if err != nil {
		http.Error(w, "Failed to update event", http.StatusInternalServerError)
		return
	}

	// Redirect back to the organizer page.
	http.Redirect(w, r, "/event/"+eventUUIDStr+"/organizer", http.StatusSeeOther)
}
