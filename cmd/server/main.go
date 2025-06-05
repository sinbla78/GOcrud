package main

import (
	"log"
	"GOcrud/internal/config"
	"GOcrud/internal/database"
	"GOcrud/internal/routes"
)

func main() {
	cfg := config.Load()
	
	// Fallback 로직으로 데이터베이스 초기화
	var db *database.Database
	
	if cfg.Database.Primary.Enable {
		// Primary + Fallback 모드
		db = database.InitWithFallback(
			cfg.Database.Primary.Driver,
			cfg.Database.Primary.DSN,
			cfg.Database.Fallback.Driver,
			cfg.Database.Fallback.DSN,
		)
	} else if cfg.Database.Fallback.Enable {
		// Fallback만 사용
		db = database.InitWithFallback(
			cfg.Database.Fallback.Driver,
			cfg.Database.Fallback.DSN,
			"", "",
		)
	} else {
		// 응급 모드 (메모리 SQLite)
		log.Println("⚠️  모든 DB 설정이 비활성화됨. 응급 모드로 실행합니다.")
		db = database.InitWithFallback("sqlite", ":memory:", "", "")
	}

	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("데이터베이스 연결 종료 실패: %v", err)
		}
	}()

	// 데이터베이스 정보 출력
	info := db.GetInfo()
	log.Printf("📊 데이터베이스 정보: %+v", info)
	
	router := routes.SetupRoutes(db.DB, cfg)
	
	log.Printf("🚀 서버가 포트 %s에서 시작되었습니다", cfg.Server.Port)
	log.Fatal(router.Run(":" + cfg.Server.Port))
}