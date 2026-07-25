-- ======================================
-- Spectra Guard v4.1 Database
-- Cloudflare D1
-- ======================================


CREATE TABLE IF NOT EXISTS users (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    username TEXT NOT NULL,

    email TEXT UNIQUE NOT NULL,

    password_hash TEXT NOT NULL,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP

);



CREATE TABLE IF NOT EXISTS websites (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    user_id INTEGER NOT NULL,

    url TEXT NOT NULL,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,


    FOREIGN KEY(user_id)
    REFERENCES users(id)

);



CREATE TABLE IF NOT EXISTS scans (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    website_id INTEGER NOT NULL,


    score INTEGER DEFAULT 0,


    risk TEXT DEFAULT 'Unknown',


    https INTEGER DEFAULT 0,


    cookies INTEGER DEFAULT 0,


    trackers INTEGER DEFAULT 0,


    technologies TEXT,


    vulnerabilities TEXT,


    issues TEXT,


    recommendations TEXT,


    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,


    FOREIGN KEY(website_id)
    REFERENCES websites(id)

);




CREATE TABLE IF NOT EXISTS sessions (

    id INTEGER PRIMARY KEY AUTOINCREMENT,


    user_id INTEGER NOT NULL,


    token TEXT UNIQUE NOT NULL,


    expires_at DATETIME NOT NULL,


    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,


    FOREIGN KEY(user_id)
    REFERENCES users(id)

);
