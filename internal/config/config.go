package config

import (
	"fmt"
	"log"
	"os"
	"github.com/joho/godotenv"
)

type Config struct {
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
	Server   ServerConfig
}

type DatabaseConfig struct {
	Primary  DBConnection
	Fallback DBConnection
}

type DBConnection struct {
	Driver string
	DSN    string
	Enable bool
}

type JWTConfig struct {
	Secret string
}

type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

type ServerConfig struct {
	Port    string
	BaseURL string
}

func Load() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Println("환경 변수 파일(.env) 로드 실패:", err)
	}

	return &Config{
		Database: DatabaseConfig{
			Primary:  loadPrimaryDB(),
			Fallback: loadFallbackDB(),
		},
		JWT: JWTConfig{
			Secret: getEnvOrDefault("JWT_SECRET", "default_secret_key"),
		},
		Email: EmailConfig{
			SMTPHost:     getEnvOrDefault("SMTP_HOST", "smtp.gmail.com"),
			SMTPPort:     getEnvOrDefault("SMTP_PORT", "587"),
			SMTPUsername: os.Getenv("SMTP_USERNAME"),
			SMTPPassword: os.Getenv("SMTP_PASSWORD"),
			FromEmail:    os.Getenv("FROM_EMAIL"),
			FromName:     getEnvOrDefault("FROM_NAME", "Your App"),
		},
		Server: ServerConfig{
			Port:    getEnvOrDefault("PORT", "8080"),
			BaseURL: getEnvOrDefault("BASE_URL", "http://localhost:8080"),
		},
	}
}

func loadPrimaryDB() DBConnection {
	driver := getEnvOrDefault("PRIMARY_DB_DRIVER", "mysql")
	enable := getEnvOrDefault("PRIMARY_DB_ENABLE", "true") == "true"
	
	var dsn string
	switch driver {
	case "mysql":
		dsn = buildMySQLDSN()
	case "sqlite":
		dsn = getEnvOrDefault("PRIMARY_SQLITE_PATH", "./data/primary.db")
	default:
		log.Printf("지원하지 않는 주 데이터베이스 드라이버: %s", driver)
		enable = false
	}

	return DBConnection{
		Driver: driver,
		DSN:    dsn,
		Enable: enable,
	}
}

func loadFallbackDB() DBConnection {
	driver := getEnvOrDefault("FALLBACK_DB_DRIVER", "sqlite")
	enable := getEnvOrDefault("FALLBACK_DB_ENABLE", "true") == "true"
	
	var dsn string
	switch driver {
	case "mysql":
		dsn = buildFallbackMySQLDSN()
	case "sqlite":
		dsn = getEnvOrDefault("FALLBACK_SQLITE_PATH", "./data/fallback.db")
	default:
		// 기본 SQLite fallback
		driver = "sqlite"
		dsn = "./data/fallback.db"
	}

	return DBConnection{
		Driver: driver,
		DSN:    dsn,
		Enable: enable,
	}
}

func buildMySQLDSN() string {
	// 기존 DSN이 있으면 우선 사용
	if dsn := os.Getenv("PRIMARY_DB_DSN"); dsn != "" {
		return dsn
	}

	host := getEnvOrDefault("MYSQL_HOST", "localhost")
	port := getEnvOrDefault("MYSQL_PORT", "3306")
	username := os.Getenv("MYSQL_USERNAME")
	password := os.Getenv("MYSQL_PASSWORD")
	database := os.Getenv("MYSQL_DATABASE")
	charset := getEnvOrDefault("MYSQL_CHARSET", "utf8mb4")
	
	if username == "" || password == "" || database == "" {
		return ""
	}
	
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		username, password, host, port, database, charset)
}

func buildFallbackMySQLDSN() string {
	// Fallback MySQL 설정
	if dsn := os.Getenv("FALLBACK_DB_DSN"); dsn != "" {
		return dsn
	}

	host := getEnvOrDefault("FALLBACK_MYSQL_HOST", "localhost")
	port := getEnvOrDefault("FALLBACK_MYSQL_PORT", "3306")
	username := os.Getenv("FALLBACK_MYSQL_USERNAME")
	password := os.Getenv("FALLBACK_MYSQL_PASSWORD")
	database := os.Getenv("FALLBACK_MYSQL_DATABASE")
	charset := getEnvOrDefault("FALLBACK_MYSQL_CHARSET", "utf8mb4")
	
	if username == "" || password == "" || database == "" {
		return ""
	}
	
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=%s&parseTime=True&loc=Local",
		username, password, host, port, database, charset)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}