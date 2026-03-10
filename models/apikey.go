package models

import (
	"time"

	"gorm.io/gorm"
)

type APIKey struct {
	ID        int64          `gorm:"primaryKey" json:"id"`
	UserID    int64          `gorm:"not null;index" json:"user_id"`
	KeyValue  string         `gorm:"size:100;uniqueIndex;not null" json:"key_value"`
	KeyName   string         `gorm:"size:100" json:"key_name"`
	IsActive  bool           `gorm:"default:true" json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt *time.Time     `json:"expires_at,omitempty"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	User      User           `gorm:"foreignKey:UserID" json:"user,omitempty"`
}

func (APIKey) TableName() string {
	return "api_keys"
}

type APIKeyResponse struct {
	ID        int64   `json:"id"`
	UserID    int64   `json:"user_id"`
	Username  string  `json:"username,omitempty"`
	KeyValue  string  `json:"key_value,omitempty"`
	KeyName   string  `json:"key_name"`
	IsActive  bool    `json:"is_active"`
	CreatedAt string  `json:"created_at"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

func (k *APIKey) ToResponse() APIKeyResponse {
	resp := APIKeyResponse{
		ID:        k.ID,
		UserID:    k.UserID,
		KeyValue:  k.KeyValue,
		KeyName:   k.KeyName,
		IsActive:  k.IsActive,
		CreatedAt: k.CreatedAt.Format("2006-01-02 15:04:05"),
	}
	if k.ExpiresAt != nil {
		exp := k.ExpiresAt.Format("2006-01-02 15:04:05")
		resp.ExpiresAt = &exp
	}
	return resp
}
