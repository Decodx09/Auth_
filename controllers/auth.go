package controllers

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/Decodx09/sauth/config"
	"github.com/Decodx09/sauth/models"
	"github.com/Decodx09/sauth/services"
	"github.com/Decodx09/sauth/utils"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
)

var validate = validator.New()

type RegisterInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

func Register(c *fiber.Ctx) error {
	var input RegisterInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	hash, err := utils.HashPassword(input.Password)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	verifyToken, _ := utils.GenerateRandomToken(32)
	verifyExpiry := time.Now().Add(24 * time.Hour)

	// Check total users to see if we assign admin role
	var count int
	countQuery := "SELECT COUNT(*) FROM users"
	if err := config.DB.QueryRow(countQuery).Scan(&count); err != nil {
		log.Printf("Query error on count users: %v", err)
	}

	role := "user"
	if count == 0 {
		role = "admin"
	}

	// Raw SQL command for insertion
	insertQuery := `INSERT INTO users 
					(email, password_hash, verify_token, verify_token_expiry, role, is_active, is_verified) 
					VALUES (?, ?, ?, ?, ?, 1, 0)`

	_, err = config.DB.Exec(insertQuery, input.Email, hash, verifyToken, verifyExpiry, role)
	if err != nil {
		log.Printf("Insert user error: %v", err)
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email already exists or database constraint failed"})
	}

	services.SendVerificationEmail(input.Email, verifyToken)

	return c.Status(http.StatusCreated).JSON(fiber.Map{"message": "Registration successful. Please check your email to verify your account."})
}

type LoginInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func Login(c *fiber.Ctx) error {
	var input LoginInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user models.User
	// Raw SQL query to fetch matching user data
	selectQuery := `SELECT id, password_hash, is_verified, is_active, role FROM users WHERE email = ?`

	err := config.DB.QueryRow(selectQuery, input.Email).Scan(
		&user.ID,
		&user.PasswordHash,
		&user.IsVerified,
		&user.IsActive,
		&user.Role,
	)

	if err == sql.ErrNoRows {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	} else if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if !utils.CheckPasswordHash(input.Password, user.PasswordHash) {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	if !user.IsVerified {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Please verify your email first"})
	}

	if !user.IsActive {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Account is deactivated. Please reactivate your account."})
	}

	payload := utils.TokenPayload{
		UserID: user.ID,
		Role:   user.Role,
	}

	accessToken, err := utils.GenerateAccessToken(payload)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate access token"})
	}

	refreshTokenString, _ := utils.GenerateRandomToken(64)
	deviceInfo := string(c.Request().Header.UserAgent())
	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	// Raw SQL command to insert the session
	insertSession := `INSERT INTO sessions (user_id, refresh_token, device_info, expires_at, is_active) 
					  VALUES (?, ?, ?, ?, 1)`

	_, err = config.DB.Exec(insertSession, user.ID, refreshTokenString, deviceInfo, expiresAt)
	if err != nil {
		log.Printf("Insert session error: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create active session"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"access_token":  accessToken,
		"refresh_token": refreshTokenString,
	})
}

type RefreshInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func RefreshToken(c *fiber.Ctx) error {
	var input RefreshInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var session models.Session
	var user models.User

	// Raw join SQL query                                                                                                      
	selectQuery := `SELECT s.id, s.user_id, s.expires_at, u.is_active, u.role
					FROM sessions s
					JOIN users u ON s.user_id = u.id
					WHERE s.refresh_token = ? AND s.is_active = 1`

	err := config.DB.QueryRow(selectQuery, input.RefreshToken).Scan(
		&session.ID,
		&session.UserID,
		&session.ExpiresAt,
		&user.IsActive,
		&user.Role,
	)

	if err == sql.ErrNoRows {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired refresh token"})
	} else if err != nil {
		log.Printf("Join query error: %v", err)
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Database error"})
	}

	if session.ExpiresAt.Before(time.Now()) {
		// Raw SQL command to expire session
		deactivateQuery := `UPDATE sessions SET is_active = 0 WHERE id = ?`
		config.DB.Exec(deactivateQuery, session.ID)

		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Refresh token has expired"})
	}

	if !user.IsActive {
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "Account deactivated"})
	}

	payload := utils.TokenPayload{
		UserID: session.UserID,
		Role:   user.Role,
	}

	accessToken, err := utils.GenerateAccessToken(payload)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate access token"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{
		"access_token": accessToken,
	})
}

func VerifyEmail(c *fiber.Ctx) error {
	token := c.Query("token")
	if token == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Token is required"})
	}

	var userID uint
	var expiry time.Time

	queryToken := `SELECT id, verify_token_expiry FROM users WHERE verify_token = ? LIMIT 1`
	err := config.DB.QueryRow(queryToken, token).Scan(&userID, &expiry)

	if err == sql.ErrNoRows {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid token"})
	}

	if expiry.Before(time.Now()) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Token expired"})
	}

	updateQuery := `UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = ?`
	_, err = config.DB.Exec(updateQuery, userID)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to verify account"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Email successfully verified. You may now log in."})
}

type ForgotPasswordInput struct {
	Email string `json:"email" validate:"required,email"`
}

func ForgotPassword(c *fiber.Ctx) error {
	var input ForgotPasswordInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var id int
	err := config.DB.QueryRow("SELECT id FROM users WHERE email = ?", input.Email).Scan(&id)

	// Execute silently to prevent email sniffing if user not found
	if err == nil {
		resetToken, _ := utils.GenerateRandomToken(32)
		expiry := time.Now().Add(1 * time.Hour)

		updateRaw := `UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?`
		config.DB.Exec(updateRaw, resetToken, expiry, id)

		services.SendPasswordResetEmail(input.Email, resetToken)
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "If that email exists, a password reset link has been sent."})
}

type ResetPasswordInput struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

func ResetPassword(c *fiber.Ctx) error {
	var input ResetPasswordInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var userID uint
	var expiry time.Time

	findUser := `SELECT id, reset_token_expiry FROM users WHERE reset_token = ? LIMIT 1`
	err := config.DB.QueryRow(findUser, input.Token).Scan(&userID, &expiry)

	if err == sql.ErrNoRows {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid token"})
	}

	if expiry.Before(time.Now()) {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Token expired"})
	}

	hash, err := utils.HashPassword(input.NewPassword)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	applyReset := `UPDATE users SET password_hash = ?, reset_token = NULL WHERE id = ?`
	config.DB.Exec(applyReset, hash, userID)

	// Invalidate all active sessions utilizing raw SQL command directly hitting foreign key link
	invalidateSessions := `UPDATE sessions SET is_active = 0 WHERE user_id = ?`
	config.DB.Exec(invalidateSessions, userID)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Password successfully reset"})
}

type ReactivateInput struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func ReactivateAccount(c *fiber.Ctx) error {
	var input ReactivateInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var user models.User
	query := `SELECT id, password_hash, is_active FROM users WHERE email = ?`

	err := config.DB.QueryRow(query, input.Email).Scan(&user.ID, &user.PasswordHash, &user.IsActive)
	if err == sql.ErrNoRows {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	if !utils.CheckPasswordHash(input.Password, user.PasswordHash) {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
	}

	if user.IsActive {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Account is already active"})
	}

	reactivateQuery := `UPDATE users SET is_active = 1 WHERE id = ?`
	config.DB.Exec(reactivateQuery, user.ID)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Account successfully reactivated!"})
}
