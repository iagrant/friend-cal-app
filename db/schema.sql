CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    uuid UUID DEFAULT gen_random_uuid() NOT NULL UNIQUE,
    name TEXT NOT NULL,
    location TEXT,
    description TEXT,
    organizer_id TEXT NOT NULL,
    timezone TEXT,
    start_time TEXT,
    end_time TEXT,
    dates TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE attendees (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id text DEFAULT ''::text NOT NULL,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    UNIQUE(event_id, user_id)
);

CREATE TABLE votes (
    id SERIAL PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    date TEXT NOT NULL,
    UNIQUE(event_id, user_id, date)
);

CREATE TABLE users (
    google_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    photo_url TEXT,
    access_token_encrypted TEXT, -- Encrypted OAuth2 access token
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(google_id) ON DELETE CASCADE,
    csrf_token TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);