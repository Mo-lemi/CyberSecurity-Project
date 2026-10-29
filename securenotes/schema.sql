-- SecureNotes database schema.
-- WARNING: running `flask init-db` executes this file and DELETES all existing data.

-- Drop in reverse order: shares depend on notes, notes depend on users.
DROP TABLE IF EXISTS shares;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- COLLATE NOCASE: "Alice" and "alice" count as the same username,
    -- so nobody can register a look-alike of an existing account.
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    -- Only the argon2 hash is stored, never the password itself (threat I4).
    password_hash TEXT    NOT NULL,
    -- Copied into the session cookie at login. Logging out adds 1, so every
    -- older cookie (including a stolen copy) stops working (pentest finding F1).
    session_version INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Every note belongs to exactly one user. ON DELETE CASCADE: if a user
    -- is ever deleted, their notes go with them instead of being left orphaned.
    owner_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- One row per "note X is shared read-only with user Y".
CREATE TABLE shares (
    -- If the note or the user is deleted, the share disappears with it.
    note_id    INTEGER NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- A note can be shared with the same user only once.
    PRIMARY KEY (note_id, user_id)
);
