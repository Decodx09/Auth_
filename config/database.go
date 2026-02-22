package config

import (
	"database/sql"
	"log"
	"os"

	_ "github.com/mattn/go-sqlite3"
)

var DB *sql.DB

func ConnectDB() {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dsn = "sauth_raw.db"
	}

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		log.Fatalf("Failed to open SQLite connection: %v", err)
	}

	if err := db.Ping(); err != nil {
		log.Fatalf("Warning: Failed to ping database: %v\n", err)
	} else {
		log.Println("Database connection established with native SQL!")
	}

	DB = db
	createTables()
}

func createTables() {
	// Raw SQL commands to construct the schema natively
	userTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email VARCHAR(255) NOT NULL UNIQUE,
		password_hash VARCHAR(255) NOT NULL,
		is_verified BOOLEAN DEFAULT FALSE,
		is_active BOOLEAN DEFAULT TRUE,
		role VARCHAR(50) DEFAULT 'user',
		reset_token VARCHAR(255) NULL,
		reset_token_expiry DATETIME NULL,
		verify_token VARCHAR(255) NULL,
		verify_token_expiry DATETIME NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	sessionTableQuery := `
	CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		refresh_token VARCHAR(255) NOT NULL UNIQUE,
		device_info VARCHAR(255),
		expires_at DATETIME NOT NULL,
		is_active BOOLEAN DEFAULT TRUE,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);`

	if _, err := DB.Exec(userTableQuery); err != nil {
		log.Printf("Failed to execute raw SQL for users table: %v\n", err)
	}

	if _, err := DB.Exec(sessionTableQuery); err != nil {
		log.Printf("Failed to execute raw SQL for sessions table: %v\n", err)
	}
}
