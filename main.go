package main

import (
	"log"
	"net/http"
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
	ID       uint   `gorm:"primaryKey" json:"id"`
	Name     string `json:"name"`
	Email    string `gorm:"uniqueIndex" json:"email"`
	Password string `json:"-"` // JSON 출력에서만 제외하고 DB에는 저장됨
}

// Post 모델 추가
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

// 데이터베이스 초기화
func initDB() {
	dsn := os.Getenv("DB_DSN")
	var err error
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("DB 연결 실패:", err)
	}
	
	// 모델 마이그레이션
	db.AutoMigrate(&User{}, &Post{})
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
		jwtSecret = []byte("default_secret_key") // 기본값 설정
	}
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

// 회원가입
func register(c *gin.Context) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "잘못된 입력 데이터"})
		return
	}

	// 이메일 중복 체크
	var existing User
	if err := db.Where("email = ?", req.Email).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "이미 존재하는 이메일입니다."})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "비밀번호 암호화 실패"})
		return
	}

	newUser := User{
		Name:     req.Name,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "사용자 생성 실패"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "회원가입 성공", "user_id": newUser.ID})
}

// 로그인
func login(c *gin.Context) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
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

	// 디버그 로그 추가
	log.Printf("로그인 시도: 이메일=%s, DB에 저장된 해시=%s", req.Email, user.Password)

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
	
	// 작성자 확인
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
	r.POST("/register", register)
	r.POST("/login", login)
	r.POST("/refresh", refreshToken)
	r.GET("/posts", getPosts)      // 게시글 목록 조회 - 인증 불필요
	r.GET("/posts/:id", getPost)   // 특정 게시글 조회 - 인증 불필요

	// 인증 필요한 API
	auth := r.Group("/")
	auth.Use(AuthMiddleware())
	auth.GET("/users", func(c *gin.Context) {
		var users []User
		db.Find(&users)
		c.JSON(http.StatusOK, users)
	})
	auth.GET("/user", getUserInfo)
	
	// 게시글 관련 인증 필요 API
	auth.POST("/posts", createPost)            // 게시글 작성
	auth.PUT("/posts/:id", updatePost)         // 게시글 수정
	auth.DELETE("/posts/:id", deletePost)      // 게시글 삭제

	r.Run(":8080")
}