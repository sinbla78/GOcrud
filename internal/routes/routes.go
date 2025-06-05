package routes

import (
	"GOcrud/internal/config"
	"GOcrud/internal/handlers"
	"GOcrud/internal/middleware"
	"GOcrud/internal/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRoutes(db *gorm.DB, cfg *config.Config) *gin.Engine {
	r := gin.Default()
	r.Use(cors.Default())

	// 서비스 초기화
	tokenService := services.NewTokenService(cfg)
	emailService := services.NewEmailService(cfg)

	// 핸들러 초기화
	authHandler := handlers.NewAuthHandler(db, tokenService, emailService)
	userHandler := handlers.NewUserHandler(db)
	postHandler := handlers.NewPostHandler(db)

	// 인증 필요없는 라우트
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hello World from GOcrud!"})
	})
	r.POST("/register", authHandler.Register)
	r.POST("/login", authHandler.Login)
	r.GET("/posts", postHandler.GetPosts)
	r.GET("/posts/:id", postHandler.GetPost)

	// 인증 필요한 라우트
	auth := r.Group("/")
	auth.Use(middleware.AuthMiddleware(tokenService))
	{
		auth.GET("/user", userHandler.GetUserInfo)
		auth.GET("/users", userHandler.GetUsers)
		auth.POST("/posts", postHandler.CreatePost)
	}

	return r
}
