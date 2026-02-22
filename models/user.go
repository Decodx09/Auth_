package models

import (
	"database/sql"
	"time"
)

type User struct {
	ID                uint           `json:"id"`
	Email             string         `json:"email"`
	PasswordHash      string         `json:"-"`
	IsVerified        bool           `json:"is_verified"`
	IsActive          bool           `json:"is_active"`
	Role              string         `json:"role"`
	ResetToken        sql.NullString `json:"-"`
	ResetTokenExpiry  sql.NullTime   `json:"-"`
	VerifyToken       sql.NullString `json:"-"`
	VerifyTokenExpiry sql.NullTime   `json:"-"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}
