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