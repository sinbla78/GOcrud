package config

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

type Config struct {
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
	Server   ServerConfig
}

type DatabaseConfig struct {
	DSN string
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
			DSN: os.Getenv("DB_DSN"),
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

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
