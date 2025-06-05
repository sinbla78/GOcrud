package database

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"GOcrud/internal/models"

	"gorm.io/driver/mysql"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Database struct {
	DB     *gorm.DB
	Driver string
}

func Init(driver, dsn string) *Database {
	var db *gorm.DB
	var err error

	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	switch driver {
	case "mysql":
		db, err = initMySQL(dsn, config)
	case "sqlite":
		db, err = initSQLite(dsn, config)
	default:
		log.Fatalf("지원하지 않는 데이터베이스 드라이버: %s", driver)
	}

	if err != nil {
		log.Fatalf("데이터베이스 연결 실패 (%s): %v", driver, err)
	}

	err = db.AutoMigrate(&models.User{}, &models.Post{}, &models.EmailVerification{})
	if err != nil {
		log.Printf("DB 마이그레이션 실패: %v", err)
	} else {
		log.Printf("%s 데이터베이스 마이그레이션 완료", driver)
	}

	return &Database{
		DB:     db,
		Driver: driver,
	}
}

func initMySQL(dsn string, config *gorm.Config) (*gorm.DB, error) {
	if dsn == "" {
		return nil, fmt.Errorf("MySQL DSN이 설정되지 않았습니다")
	}

	log.Println("MySQL 데이터베이스에 연결 중...")
	db, err := gorm.Open(mysql.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("MySQL 연결 실패: %w", err)
	}

	log.Println("MySQL 데이터베이스 연결 성공")
	return db, nil
}

func initSQLite(dsn string, config *gorm.Config) (*gorm.DB, error) {
	dir := filepath.Dir(dsn)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("SQLite 디렉토리 생성 실패: %w", err)
	}

	log.Printf("SQLite 데이터베이스에 연결 중: %s", dsn)
	db, err := gorm.Open(sqlite.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("SQLite 연결 실패: %w", err)
	}

	log.Printf("SQLite 데이터베이스 연결 성공: %s", dsn)
	return db, nil
}

func (d *Database) Ping() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Ping()
}

func (d *Database) Close() error {
	sqlDB, err := d.DB.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}
