package models

import "time"

type Session struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	RefreshToken string    `json:"-"`
	DeviceInfo   string    `json:"device_info"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
