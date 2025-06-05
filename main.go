package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// User 모델
type User struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `json:"name"`
	Email           string    `gorm:"uniqueIndex" json:"email"`
	Password        string    `json:"-"` // JSON 출력에서 제외
	IsEmailVerified bool      `gorm:"default:false" json:"is_email_verified"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// EmailVerification 모델 - 이메일 인증 토큰 관리
type EmailVerification struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Email     string    `gorm:"index" json:"email"`
	Token     string    `gorm:"uniqueIndex" json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	IsUsed    bool      `gorm:"default:false" json:"is_used"`
	CreatedAt time.Time `json:"created_at"`
}

// Post 모델
type Post struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Title     string    `json:"title"`
	Content   string    `json:"content"`
	UserID    uint      `json:"user_id"`
	User      User      `gorm:"foreignKey:UserID" json:"user"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// JWT Claims 구조체
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

var db *gorm.DB
var jwtSecret []byte

// 이메일 설정 구조체
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
}

var emailConfig EmailConfig

// 데이터베이스 초기화
func initDB() {
	dsn := os.Getenv("DB_DSN")
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("DB 연결 실패:", err)
	}
	
	// 모델 마이그레이션
	db.AutoMigrate(&User{}, &Post{}, &EmailVerification{})
}

// 환경 변수 로드
func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Println("환경 변수 파일(.env) 로드 실패:", err)
	}
	
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(jwtSecret) == 0 {
		log.Println("경고: JWT_SECRET이 설정되지 않았습니다. 기본값 사용")
		jwtSecret = []byte("default_secret_key")
	}
	
	// 이메일 설정 로드
	emailConfig = EmailConfig{
		SMTPHost:     os.Getenv("SMTP_HOST"),
		SMTPPort:     os.Getenv("SMTP_PORT"),
		SMTPUsername: os.Getenv("SMTP_USERNAME"),
		SMTPPassword: os.Getenv("SMTP_PASSWORD"),
		FromEmail:    os.Getenv("FROM_EMAIL"),
		FromName:     os.Getenv("FROM_NAME"),
	}
	
	// 기본값 설정
	if emailConfig.SMTPHost == "" {
		emailConfig.SMTPHost = "smtp.gmail.com"
	}
	if emailConfig.SMTPPort == "" {
		emailConfig.SMTPPort = "587"
	}
	if emailConfig.FromName == "" {
		emailConfig.FromName = "Your App"
	}
}

// 랜덤 토큰 생성
func generateRandomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// 이메일 발송 함수
func sendEmail(to, subject, body string) error {
	from := emailConfig.FromEmail
	password := emailConfig.SMTPPassword
	
	// Gmail SMTP 설정
	smtpHost := emailConfig.SMTPHost
	smtpPort := emailConfig.SMTPPort
	
	message := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n"+
		"%s\r\n", to, subject, body))
	
	auth := smtp.PlainAuth("", from, password, smtpHost)
	
	err := smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{to}, message)
	if err != nil {
		log.Printf("이메일 발송 실패: %v", err)
		return err
	}
	
	log.Printf("이메일 발송 성공: %s", to)
	return nil
}

// 인증 이메일 발송
func sendVerificationEmail(email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", os.Getenv("BASE_URL"), token)
	if os.Getenv("BASE_URL") == "" {
		verificationURL = fmt.Sprintf("http://localhost:8080/verify-email?token=%s", token)
	}
	
	subject := "이메일 인증을 완료해주세요"
	body := fmt.Sprintf(`
		<html>
		<body>
			<h2>이메일 인증</h2>
			<p>안녕하세요!</p>
			<p>회원가입을 완료하려면 아래 링크를 클릭하여 이메일 인증을 완료해주세요.</p>
			<p><a href="%s" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">이메일 인증하기</a></p>
			<p>또는 다음 링크를 복사하여 브라우저에 붙여넣기 하세요:</p>
			<p>%s</p>
			<p>이 링크는 24시간 후에 만료됩니다.</p>
			<p>감사합니다.</p>
		</body>
		</html>
	`, verificationURL, verificationURL)
	
	return sendEmail(email, subject, body)
}

// 비밀번호 해싱 함수
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// 비밀번호 검증 함수
func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// JWT 생성 함수
func generateTokens(userID uint) (string, string, error) {
	// 액세스 토큰 생성
	accessClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 30)), // 30분 유효
		},
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	// 리프레시 토큰 생성
	refreshClaims := Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 7)), // 7일 유효
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString(jwtSecret)
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// 회원가입 (이메일 인증 필요)
func register(c *gin.Context) {
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
	var existing User
	if err := db.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "이미 존재하는 이메일입니다."})
		return
	}

	// 비밀번호 해싱
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "비밀번호 암호화 실패"})
		return
	}

	// 사용자 생성 (이메일 미인증 상태)
	newUser := User{
		Name:            req.Name,
		Email:           req.Email,
		Password:        hashedPassword,
		IsEmailVerified: false,
	}

	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 생성 실패"})
		return
	}

	// 인증 토큰 생성
	token, err := generateRandomToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 토큰 생성 실패"})
		return
	}

	// 인증 정보 저장
	verification := EmailVerification{
		Email:     req.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour * 24), // 24시간 유효
		IsUsed:    false,
	}

	if err := db.Create(&verification).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 정보 저장 실패"})
		return
	}

	// 인증 이메일 발송
	if err := sendVerificationEmail(req.Email, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 이메일 발송 실패"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "회원가입이 완료되었습니다. 이메일을 확인하여 인증을 완료해주세요.",
		"user_id": newUser.ID,
	})
}

// 이메일 인증
func verifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "인증 토큰이 필요합니다."})
		return
	}

	var verification EmailVerification
	if err := db.Where("token = ? AND is_used = false AND expires_at > ?", token, time.Now()).First(&verification).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "유효하지 않거나 만료된 인증 토큰입니다."})
		return
	}

	// 사용자 이메일 인증 상태 업데이트
	if err := db.Model(&User{}).Where("email = ?", verification.Email).Update("is_email_verified", true).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "이메일 인증 처리 실패"})
		return
	}

	// 인증 토큰 사용 처리
	verification.IsUsed = true
	db.Save(&verification)

	c.JSON(http.StatusOK, gin.H{"message": "이메일 인증이 완료되었습니다. 이제 로그인할 수 있습니다."})
}

// 인증 이메일 재발송
func resendVerificationEmail(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "유효한 이메일을 입력해주세요."})
		return
	}

	// 사용자 확인
	var user User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "존재하지 않는 이메일입니다."})
		return
	}

	// 이미 인증된 이메일인지 확인
	if user.IsEmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{"error": "이미 인증된 이메일입니다."})
		return
	}

	// 기존 미사용 토큰들 무효화
	db.Model(&EmailVerification{}).Where("email = ? AND is_used = false", req.Email).Update("is_used", true)

	// 새 인증 토큰 생성
	token, err := generateRandomToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 토큰 생성 실패"})
		return
	}

	// 새 인증 정보 저장
	verification := EmailVerification{
		Email:     req.Email,
		Token:     token,
		ExpiresAt: time.Now().Add(time.Hour * 24),
		IsUsed:    false,
	}

	if err := db.Create(&verification).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 정보 저장 실패"})
		return
	}

	// 인증 이메일 발송
	if err := sendVerificationEmail(req.Email, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "인증 이메일 발송 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "인증 이메일이 재발송되었습니다."})
}

// 로그인 (이메일 인증 확인 포함)
func login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터"})
		return
	}

	var user User
	if err := db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "이메일 또는 비밀번호가 잘못되었습니다."})
		return
	}

	// 이메일 인증 확인
	if !user.IsEmailVerified {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "이메일 인증이 완료되지 않았습니다. 이메일을 확인해주세요.",
			"code": "EMAIL_NOT_VERIFIED",
		})
		return
	}

	if !checkPasswordHash(req.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "이메일 또는 비밀번호가 잘못되었습니다."})
		return
	}

	accessToken, refreshToken, err := generateTokens(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken, 
		"refresh_token": refreshToken, 
		"user": gin.H{
			"id": user.ID,
			"name": user.Name,
			"email": user.Email,
			"is_email_verified": user.IsEmailVerified,
		},
	})
}

// 토큰 재발급
func refreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터"})
		return
	}

	token, err := jwt.ParseWithClaims(req.RefreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "유효하지 않은 리프레시 토큰"})
		return
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "토큰 정보가 유효하지 않습니다."})
		return
	}

	accessToken, refreshToken, err := generateTokens(claims.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "토큰 생성 실패"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

// JWT 인증 미들웨어
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "토큰이 필요합니다"})
			c.Abort()
			return
		}

		// "Bearer " 제거
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "유효하지 않은 토큰"})
			c.Abort()
			return
		}

		claims, _ := token.Claims.(*Claims)
		c.Set("userID", claims.UserID)
		c.Next()
	}
}

// 사용자 정보 조회 핸들러
func getUserInfo(c *gin.Context) {
	userID, _ := c.Get("userID")
	
	var user User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "사용자를 찾을 수 없습니다."})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"id": user.ID,
		"name": user.Name,
		"email": user.Email,
		"is_email_verified": user.IsEmailVerified,
	})
}

// 게시글 작성 핸들러
func createPost(c *gin.Context) {
	userID, _ := c.Get("userID")
	
	var req struct {
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "제목과 내용은 필수입니다."})
		return
	}
	
	post := Post{
		Title:   req.Title,
		Content: req.Content,
		UserID:  userID.(uint),
	}
	
	if err := db.Create(&post).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 작성 실패"})
		return
	}
	
	c.JSON(http.StatusCreated, gin.H{
		"message": "게시글이 작성되었습니다.",
		"post_id": post.ID,
	})
}

// 게시글 목록 조회 핸들러
func getPosts(c *gin.Context) {
	var posts []Post
	
	// 페이지네이션
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	offset := (page - 1) * perPage
	
	// 게시글 조회 시 작성자 정보 포함
	if err := db.Preload("User").
		Select("posts.*, users.name").
		Joins("JOIN users ON posts.user_id = users.id").
		Order("posts.created_at DESC").
		Offset(offset).
		Limit(perPage).
		Find(&posts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 목록 조회 실패"})
		return
	}
	
	// 전체 게시글 수 계산
	var total int64
	db.Model(&Post{}).Count(&total)
	
	c.JSON(http.StatusOK, gin.H{
		"posts": posts,
		"meta": gin.H{
			"total":    total,
			"page":     page,
			"per_page": perPage,
			"pages":    (int(total) + perPage - 1) / perPage,
		},
	})
}

// 특정 게시글 조회 핸들러
func getPost(c *gin.Context) {
	id := c.Param("id")
	
	var post Post
	if err := db.Preload("User").First(&post, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "게시글을 찾을 수 없습니다."})
		return
	}
	
	c.JSON(http.StatusOK, post)
}

// 게시글 수정 핸들러
func updatePost(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	
	var post Post
	if err := db.First(&post, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "게시글을 찾을 수 없습니다."})
		return
	}
	
	// 작성자 확인
	if post.UserID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{"error": "자신의 게시글만 수정할 수 있습니다."})
		return
	}
	
	var req struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터"})
		return
	}
	
	// 제목이나 내용이 비어있지 않을 경우에만 업데이트
	if req.Title != "" {
		post.Title = req.Title
	}
	if req.Content != "" {
		post.Content = req.Content
	}
	
	if err := db.Save(&post).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 수정 실패"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "게시글이 수정되었습니다.",
		"post": post,
	})
}

// 게시글 삭제 핸들러
func deletePost(c *gin.Context) {
	id := c.Param("id")
	userID, _ := c.Get("userID")
	
	var post Post
	if err := db.First(&post, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "게시글을 찾을 수 없습니다."})
		return
	}
	
	
	if post.UserID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{"error": "자신의 게시글만 삭제할 수 있습니다."})
		return
	}
	
	if err := db.Delete(&post).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 삭제 실패"})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{"message": "게시글이 삭제되었습니다."})
}

func main() {
	loadEnv()
	initDB()
	r := gin.Default()

	// CORS 허용
	r.Use(cors.Default())

	// 인증 필요없는 API
	r.POST("/register", register)                    // 회원가입
	r.GET("/verify-email", verifyEmail)              // 이메일 인증
	r.POST("/resend-verification", resendVerificationEmail) // 인증 이메일 재발송
	r.POST("/login", login)                          // 로그인
	r.POST("/refresh", refreshToken)                 // 토큰 재발급
	r.GET("/posts", getPosts)                        // 게시글 목록 조회
	r.GET("/posts/:id", getPost)                     // 특정 게시글 조회

	// 인증 필요한 API
	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	auth.GET("/users", func(c *gin.Context) {
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})
	auth.GET("/user", getUserInfo)                   // 사용자 정보 조회
	
	// 게시글 관련 인증 필요 API
	auth.POST("/posts", createPost)                  // 게시글 작성
	auth.PUT("/posts/:id", updatePost)               // 게시글 수정
	auth.DELETE("/posts/:id", deletePost)            // 게시글 삭제

	r.Run(":8080")
}