-- SecureNotes database schema.
-- WARNING: running `flask init-db` executes this file and DELETES all existing data.

DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- COLLATE NOCASE: "Alice" and "alice" count as the same username,
    -- so nobody can register a look-alike of an existing account.
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    -- Only the argon2 hash is stored, never the password itself (threat I4).
    password_hash TEXT    NOT NULL,
    created_at    TEXT    NOT NULL DEFAULT CURRENT_TIMESTAMP
);
