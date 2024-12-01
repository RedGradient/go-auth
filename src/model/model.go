package model

import (
	"github.com/google/uuid"
	"time"
)

type RefreshTokenModel struct {
	ID uint `gorm:"primaryKey"`
	Guid uuid.UUID `gorm:"type:uuid;not null"`
	RefreshTokenHash string `gorm:"type:text;not null"`
	Revoked bool `gorm:"default:false"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}