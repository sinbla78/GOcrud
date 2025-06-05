package main

import (
	"GOcrud/internal/config"
	"GOcrud/internal/database"
	"GOcrud/internal/routes"
	"log"
)

func main() {
	// 설정 로드
	cfg := config.Load()

	// 데이터베이스 초기화
	db := database.Init(cfg.Database.DSN)

	// 라우터 설정
	router := routes.SetupRoutes(db, cfg)

	// 서버 시작
	log.Printf("서버가 포트 %s에서 시작되었습니다", cfg.Server.Port)
	log.Fatal(router.Run(":" + cfg.Server.Port))
}
