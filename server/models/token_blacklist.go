package models

import (
	"time"

	"gorm.io/gorm"
)

type TokenBlacklist struct {
	gorm.Model
	Token     string    `gorm:"unique;not null"`
	ExpiresAt time.Time `gorm:"not null;index"`
}
