package handlers

import (
	"net/http"

	"GOcrud/internal/models"
	"GOcrud/internal/services"
	"GOcrud/pkg/utils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthHandler struct {
	db           *gorm.DB
	tokenService *services.TokenService
	emailService *services.EmailService
}

func NewAuthHandler(db *gorm.DB, tokenService *services.TokenService, emailService *services.EmailService) *AuthHandler {
	return &AuthHandler{
		db:           db,
		tokenService: tokenService,
		emailService: emailService,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Name     string `json:"name" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터: " + err.Error()})
		return
	}

	// 이메일 중복 체크
	var existing models.User
	if err := h.db.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "이미 존재하는 이메일입니다."})
		return
	}

	// 비밀번호 해싱
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "비밀번호 암호화 실패"})
		return
	}

	// 사용자 생성
	newUser := models.User{
		Name:            req.Name,
		Email:           req.Email,
		Password:        hashedPassword,
		IsEmailVerified: false,
	}

	if err := h.db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 생성 실패"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "회원가입이 완료되었습니다.",
		"user_id": newUser.ID,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터"})
		return
	}

	var user models.User
	if err := h.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "이메일 또는 비밀번호가 잘못되었습니다."})
		return
	}

	if !utils.CheckPasswordHash(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "이메일 또는 비밀번호가 잘못되었습니다."})
		return
	}

	accessToken, refreshToken, err := h.tokenService.GenerateTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"user": gin.H{
			"id":    user.ID,
			"name":  user.Name,
			"email": user.Email,
		},
	})
}
