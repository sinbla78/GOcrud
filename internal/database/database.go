package database

import (
	"GOcrud/internal/models"
	"log"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func Init(dsn string) *gorm.DB {
	if dsn == "" {
		log.Println("DB_DSN이 설정되지 않았습니다. 더미 연결을 사용합니다.")
		return &gorm.DB{}
	}

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Printf("DB 연결 실패: %v", err)
		return &gorm.DB{}
	}

	// 모델 마이그레이션
	err = db.AutoMigrate(&models.User{}, &models.Post{}, &models.EmailVerification{})
	if err != nil {
		log.Printf("DB 마이그레이션 실패: %v", err)
	}

	return db
}
