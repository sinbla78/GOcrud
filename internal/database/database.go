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

// InitWithFallback - 주 DB 실패 시 대체 DB로 자동 전환
func InitWithFallback(primaryDriver, primaryDSN, fallbackDriver, fallbackDSN string) *Database {
	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	// 1차: 주 데이터베이스 시도
	if primaryDriver != "" && primaryDSN != "" {
		log.Printf("주 데이터베이스 연결 시도: %s", primaryDriver)
		
		db, err := connectDB(primaryDriver, primaryDSN, config)
		if err == nil {
			log.Printf("✅ %s 데이터베이스 연결 성공", primaryDriver)
			return createDatabase(db, primaryDriver)
		}
		
		log.Printf("❌ %s 데이터베이스 연결 실패: %v", primaryDriver, err)
		log.Printf("대체 데이터베이스로 전환합니다...")
	}

	// 2차: 대체 데이터베이스 시도
	if fallbackDriver != "" && fallbackDSN != "" {
		log.Printf("대체 데이터베이스 연결 시도: %s", fallbackDriver)
		
		db, err := connectDB(fallbackDriver, fallbackDSN, config)
		if err == nil {
			log.Printf("✅ %s 데이터베이스 연결 성공 (대체 DB)", fallbackDriver)
			return createDatabase(db, fallbackDriver)
		}
		
		log.Printf("❌ %s 데이터베이스 연결 실패: %v", fallbackDriver, err)
	}

	// 3차: 응급 SQLite (메모리 DB)
	log.Println("모든 데이터베이스 연결 실패. 임시 메모리 DB를 사용합니다.")
	emergencyDSN := ":memory:"
	
	db, err := connectDB("sqlite", emergencyDSN, config)
	if err != nil {
		log.Fatalf("응급 데이터베이스도 연결할 수 없습니다: %v", err)
	}
	
	log.Println("⚠️  임시 메모리 DB 사용 중 (재시작 시 데이터 손실)")
	return createDatabase(db, "sqlite")
}

// 기존 Init 함수도 유지 (하위 호환성)
func Init(driver, dsn string) *Database {
	return InitWithFallback(driver, dsn, "", "")
}

func connectDB(driver, dsn string, config *gorm.Config) (*gorm.DB, error) {
	switch driver {
	case "mysql":
		return initMySQL(dsn, config)
	case "sqlite":
		return initSQLite(dsn, config)
	default:
		return nil, fmt.Errorf("지원하지 않는 데이터베이스 드라이버: %s", driver)
	}
}

func createDatabase(db *gorm.DB, driver string) *Database {
	// 마이그레이션 실행
	err := db.AutoMigrate(&models.User{}, &models.Post{}, &models.EmailVerification{})
	if err != nil {
		log.Printf("⚠️  DB 마이그레이션 실패: %v", err)
		log.Println("기존 테이블을 사용하여 계속 진행합니다.")
	} else {
		log.Printf("✅ %s 데이터베이스 마이그레이션 완료", driver)
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

	db, err := gorm.Open(mysql.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("MySQL 연결 실패: %w", err)
	}

	// MySQL 연결 테스트
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("MySQL 연결 객체 취득 실패: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("MySQL 연결 테스트 실패: %w", err)
	}

	return db, nil
}

func initSQLite(dsn string, config *gorm.Config) (*gorm.DB, error) {
	// 메모리 DB가 아닌 경우 디렉토리 생성
	if dsn != ":memory:" {
		dir := filepath.Dir(dsn)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("SQLite 디렉토리 생성 실패: %w", err)
		}
	}

	db, err := gorm.Open(sqlite.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("SQLite 연결 실패: %w", err)
	}

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

func (d *Database) GetInfo() map[string]interface{} {
	info := map[string]interface{}{
		"driver": d.Driver,
	}

	sqlDB, err := d.DB.DB()
	if err == nil {
		info["stats"] = sqlDB.Stats()
	}

	return info
}