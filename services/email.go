package services

import (
	"log"
	"os"
	"strconv"

	"gopkg.in/gomail.v2"
)

func SendEmail(to, subject, body string) error {
	host := os.Getenv("SMTP_HOST")
	portStr := os.Getenv("SMTP_PORT")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")

	port, err := strconv.Atoi(portStr)
	if err != nil {
		port = 2525
	}

	m := gomail.NewMessage()
	m.SetHeader("From", "noreply@sauth.com")
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	d := gomail.NewDialer(host, port, user, pass)

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Could not send email to %s: %v", to, err)
		return err
	}

	return nil
}

func SendVerificationEmail(to, token string) {
	appURL := os.Getenv("APP_URL")
	link := appURL + "/verify-email?token=" + token

	log.Printf("\n=================================\n")
	log.Printf("DEVELOPER MODE: Verification Link for %s\n%s\n", to, link)
	log.Printf("=================================\n")

	body := `<h1>Welcome!</h1>
		<p>Please verify your email address by clicking the link below:</p>
		<a href="` + link + `">Verify Email</a>`

	// Fire and forget, or handle errors gracefully in real prod
	go SendEmail(to, "Verify your email", body)
}

func SendPasswordResetEmail(to, token string) {
	appURL := os.Getenv("APP_URL")
	link := appURL + "/reset-password?token=" + token

	log.Printf("\n=================================\n")
	log.Printf("DEVELOPER MODE: Password Reset Link for %s\n%s\n", to, link)
	log.Printf("=================================\n")

	body := `<h1>Password Reset Request</h1>
		<p>You requested a password reset. Click the link below to set a new password:</p>
		<a href="` + link + `">Reset Password</a>
		<p>If you did not request this, please ignore this email.</p>`

	go SendEmail(to, "Reset your password", body)
}
