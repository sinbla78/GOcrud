package models

import "time"

// User 모델
type User struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `gorm:"size:100" json:"name"`
	Email           string    `gorm:"size:255;uniqueIndex" json:"email"` // 길이 제한 추가
	Password        string    `gorm:"size:255" json:"-"` // JSON 출력에서 제외
	IsEmailVerified bool      `gorm:"default:false" json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// EmailVerification 모델 - 이메일 인증 토큰 관리
type EmailVerification struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Email     string    `gorm:"size:255;index" json:"email"` // 길이 제한 추가
	Token     string    `gorm:"size:255;uniqueIndex" json:"token"` // 길이 제한 추가
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `gorm:"default:false" json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

// Post 모델
type Post struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `gorm:"size:255" json:"title"` // 길이 제한 추가
	Content   string    `gorm:"type:text" json:"content"` // TEXT 타입으로 명시
	UserID    uint      `json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"user"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
