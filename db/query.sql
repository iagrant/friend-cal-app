-- name: GetEvents :many
SELECT * FROM events;

-- name: GetEvent :one
SELECT * FROM events WHERE id = $1;

-- name: GetEventByUUID :one
SELECT * FROM events WHERE uuid = $1;

-- name: CreateEvent :one
INSERT INTO events (name, location, description, organizer_id, timezone, start_time, end_time, dates)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: UpdateEvent :one
UPDATE events
SET name = $2, location = $3, description = $4, timezone = $5, start_time = $6, end_time = $7, dates = $8
WHERE uuid = $1
RETURNING *;

-- name: GetAttendees :many
SELECT * FROM attendees WHERE event_id = $1;

-- name: GetAttendeeByEventAndUser :one
SELECT * FROM attendees WHERE event_id = $1 AND user_id = $2;

-- name: CreateAttendee :one
INSERT INTO attendees (event_id, user_id, name, email) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetVotesByEvent :many
SELECT * FROM votes WHERE event_id = $1;

-- name: CreateVote :one
INSERT INTO votes (event_id, user_id, date) VALUES ($1, $2, $3) RETURNING *;

-- name: DeleteVotesByUser :exec
DELETE FROM votes WHERE event_id = $1 AND user_id = $2;

-- name: DeleteEvent :exec
DELETE FROM events WHERE id = $1;

-- name: GetEventsByOrganizer :many
SELECT * FROM events WHERE organizer_id = $1 ORDER BY created_at DESC;

-- name: GetEventsByAttendee :many
SELECT DISTINCT e.* FROM events e
JOIN votes v ON e.id = v.event_id
WHERE v.user_id = $1 ORDER BY created_at DESC;

-- name: GetUser :one
SELECT * FROM users WHERE google_id = $1;

-- name: UpsertUser :one
INSERT INTO users (google_id, name, email, photo_url, access_token_encrypted)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (google_id) DO UPDATE SET
    name = EXCLUDED.name,
    email = EXCLUDED.email,
    photo_url = EXCLUDED.photo_url,
    access_token_encrypted = EXCLUDED.access_token_encrypted
RETURNING *;

-- name: CreateSession :one
INSERT INTO sessions (id, user_id)
VALUES ($1, $2)
RETURNING *;

-- name: GetSession :one
SELECT * FROM sessions WHERE id = $1;

-- name: DeleteSession :exec
DELETE FROM sessions WHERE id = $1;