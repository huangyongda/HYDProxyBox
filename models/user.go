package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID            int64          `gorm:"primaryKey" json:"id"`
	Username      string         `gorm:"size:100;uniqueIndex;not null" json:"username"`
	PasswordHash  string         `gorm:"size:255;not null" json:"-"`
	RequestLimit  int            `gorm:"default:0" json:"request_limit"`
	RequestCount  int            `gorm:"default:0" json:"request_count"`
	IsAdmin       bool           `gorm:"default:false" json:"is_admin"`
	ExpiresAt     *time.Time     `gorm:"index" json:"expires_at"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	APIKeys       []APIKey       `gorm:"foreignKey:UserID" json:"api_keys,omitempty"`
}

func (User) TableName() string {
	return "users"
}

type UserResponse struct {
	ID           int64   `json:"id"`
	Username     string  `json:"username"`
	RequestLimit int     `json:"request_limit"`
	RequestCount int     `json:"request_count"`
	IsAdmin      bool    `json:"is_admin"`
	ExpiresAt    *string `json:"expires_at"`
	CreatedAt    string  `json:"created_at"`
}

func (u *User) ToResponse() UserResponse {
	var expiresAt *string
	if u.ExpiresAt != nil {
		formatted := u.ExpiresAt.Format("2006-01-02 15:04:05")
		expiresAt = &formatted
	}
	return UserResponse{
		ID:           u.ID,
		Username:     u.Username,
		RequestLimit: u.RequestLimit,
		RequestCount: u.RequestCount,
		IsAdmin:      u.IsAdmin,
		ExpiresAt:    expiresAt,
		CreatedAt:    u.CreatedAt.Format("2006-01-02 15:04:05"),
	}
}
