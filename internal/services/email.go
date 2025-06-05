package services

import (
	"GOcrud/internal/config"
	"fmt"
	"log"
	"net/smtp"
)

type EmailService struct {
	config  *config.EmailConfig
	baseURL string
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		config:  &cfg.Email,
		baseURL: cfg.Server.BaseURL,
	}
}

func (s *EmailService) SendEmail(to, subject, body string) error {
	message := []byte(fmt.Sprintf("To: %s\r\n"+
		"Subject: %s\r\n"+
		"MIME-version: 1.0;\r\n"+
		"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n"+
		"%s\r\n", to, subject, body))

	auth := smtp.PlainAuth("", s.config.FromEmail, s.config.SMTPPassword, s.config.SMTPHost)

	err := smtp.SendMail(s.config.SMTPHost+":"+s.config.SMTPPort, auth, s.config.FromEmail, []string{to}, message)
	if err != nil {
		log.Printf("이메일 발송 실패: %v", err)
		return err
	}

	log.Printf("이메일 발송 성공: %s", to)
	return nil
}

func (s *EmailService) SendVerificationEmail(email, token string) error {
	verificationURL := fmt.Sprintf("%s/verify-email?token=%s", s.baseURL, token)

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

	return s.SendEmail(email, subject, body)
}
