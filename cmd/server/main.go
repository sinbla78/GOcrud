package main

import (
	"log"
	"GOcrud/internal/config"
	"GOcrud/internal/database"
	"GOcrud/internal/routes"
)

func main() {
	cfg := config.Load()
	
	db := database.Init(cfg.Database.Driver, cfg.Database.DSN)
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("데이터베이스 연결 종료 실패: %v", err)
		}
	}()

	if err := db.Ping(); err != nil {
		log.Fatalf("데이터베이스 연결 확인 실패: %v", err)
	}

	log.Printf("사용 중인 데이터베이스: %s", cfg.Database.Driver)
	
	router := routes.SetupRoutes(db.DB, cfg)
	
	log.Printf("서버가 포트 %s에서 시작되었습니다", cfg.Server.Port)
	log.Fatal(router.Run(":" + cfg.Server.Port))
}
