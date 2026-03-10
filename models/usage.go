package models

import (
	"time"

	"gorm.io/gorm"
)

type UsageLog struct {
	ID              int64          `gorm:"primaryKey" json:"id"`
	APIKeyID        int64          `gorm:"not null;index" json:"api_key_id"`
	UserID          int64          `gorm:"not null;index" json:"user_id"`
	Model           string         `gorm:"size:100;not null" json:"model"`
	PromptTokens    int            `gorm:"default:0" json:"prompt_tokens"`
	CompletionTokens int           `gorm:"default:0" json:"completion_tokens"`
	TotalTokens     int            `gorm:"default:0" json:"total_tokens"`
	Cost            float64        `gorm:"type:decimal(10,6);default:0" json:"cost"`
	LatencyMs       int            `gorm:"default:0" json:"latency_ms"`
	CreatedAt       time.Time      `json:"created_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

func (UsageLog) TableName() string {
	return "usage_logs"
}

type UsageLogResponse struct {
	ID              int64   `json:"id"`
	APIKeyID        int64   `json:"api_key_id"`
	UserID          int64   `json:"user_id"`
	Model           string  `json:"model"`
	PromptTokens    int     `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalTokens     int     `json:"total_tokens"`
	Cost            float64 `json:"cost"`
	LatencyMs       int     `json:"latency_ms"`
	CreatedAt       string  `json:"created_at"`
}

func (u *UsageLog) ToResponse() UsageLogResponse {
	return UsageLogResponse{
		ID:               u.ID,
		APIKeyID:         u.APIKeyID,
		UserID:           u.UserID,
		Model:            u.Model,
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
		Cost:             u.Cost,
		LatencyMs:        u.LatencyMs,
		CreatedAt:        u.CreatedAt.Format("2006-01-02 15:04:05"),
	}
}
