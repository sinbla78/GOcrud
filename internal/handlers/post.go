package handlers

import (
	"GOcrud/internal/models"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PostHandler struct {
	db *gorm.DB
}

func NewPostHandler(db *gorm.DB) *PostHandler {
	return &PostHandler{db: db}
}

func (h *PostHandler) CreatePost(c *gin.Context) {
	userID, _ := c.Get("userID")

	var req struct {
		Title   string `json:"title" binding:"required"`
		Content string `json:"content" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "제목과 내용은 필수입니다."})
		return
	}

	post := models.Post{
		Title:   req.Title,
		Content: req.Content,
		UserID:  userID.(uint),
	}

	if err := h.db.Create(&post).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 작성 실패"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "게시글이 작성되었습니다.",
		"post_id": post.ID,
	})
}

func (h *PostHandler) GetPosts(c *gin.Context) {
	var posts []models.Post

	// 페이지네이션
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "10"))
	offset := (page - 1) * perPage

	// 게시글 조회 시 작성자 정보 포함
	if err := h.db.Preload("User").
		Order("posts.created_at DESC").
		Offset(offset).
		Limit(perPage).
		Find(&posts).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "게시글 목록 조회 실패"})
		return
	}

	// 전체 게시글 수 계산
	var total int64
	h.db.Model(&models.Post{}).Count(&total)

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

func (h *PostHandler) GetPost(c *gin.Context) {
	id := c.Param("id")

	var post models.Post
	if err := h.db.Preload("User").First(&post, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "게시글을 찾을 수 없습니다."})
		return
	}

	c.JSON(http.StatusOK, post)
}
