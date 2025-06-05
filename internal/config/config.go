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
	Driver   string
	DSN      string
	SQLite   SQLiteConfig
	MySQL    MySQLConfig
}

type SQLiteConfig struct {
	Path string
}

type MySQLConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	Database string
	Charset  string
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

	driver := getEnvOrDefault("DB_DRIVER", "sqlite")
	
	var dsn string
	switch driver {
	case "mysql":
		dsn = buildMySQLDSN()
	case "sqlite":
		dsn = getEnvOrDefault("SQLITE_PATH", "./data/app.db")
	default:
		log.Printf("지원하지 않는 데이터베이스 드라이버: %s, SQLite를 사용합니다", driver)
		driver = "sqlite"
		dsn = "./data/app.db"
	}

	return &Config{
		Database: DatabaseConfig{
			Driver: driver,
			DSN:    dsn,
			SQLite: SQLiteConfig{
				Path: getEnvOrDefault("SQLITE_PATH", "./data/app.db"),
			},
			MySQL: MySQLConfig{
				Host:     getEnvOrDefault("MYSQL_HOST", "localhost"),
				Port:     getEnvOrDefault("MYSQL_PORT", "3306"),
				Username: os.Getenv("MYSQL_USERNAME"),
				Password: os.Getenv("MYSQL_PASSWORD"),
				Database: os.Getenv("MYSQL_DATABASE"),
				Charset:  getEnvOrDefault("MYSQL_CHARSET", "utf8mb4"),
			},
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

func buildMySQLDSN() string {
	host := getEnvOrDefault("MYSQL_HOST", "localhost")
	port := getEnvOrDefault("MYSQL_PORT", "3306")
	username := os.Getenv("MYSQL_USERNAME")
	password := os.Getenv("MYSQL_PASSWORD")
	database := os.Getenv("MYSQL_DATABASE")
	charset := getEnvOrDefault("MYSQL_CHARSET", "utf8mb4")
	
	if username == "" || password == "" || database == "" {
		return os.Getenv("DB_DSN")
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
