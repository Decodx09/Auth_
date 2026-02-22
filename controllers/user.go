package controllers

import (
	"fmt"
	"net/http"

	"github.com/Decodx09/sauth/config"
	"github.com/Decodx09/sauth/models"
	"github.com/Decodx09/sauth/utils"
	"github.com/gofiber/fiber/v2"
)

func getUserID(c *fiber.Ctx) (uint, error) {
	id := c.Locals("user_id")
	if id == nil {
		return 0, fmt.Errorf("user not found in context")
	}
	return id.(uint), nil
}

type LogoutInput struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

func Logout(c *fiber.Ctx) error {
	var input LogoutInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, _ := getUserID(c)

	query := `UPDATE sessions SET is_active = 0 WHERE user_id = ? AND refresh_token = ?`
	config.DB.Exec(query, userID, input.RefreshToken)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Successfully logged out from current session"})
}

func LogoutAll(c *fiber.Ctx) error {
	userID, _ := getUserID(c)

	query := `UPDATE sessions SET is_active = 0 WHERE user_id = ?`
	config.DB.Exec(query, userID)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Successfully logged out across all devices"})
}

func GetProfile(c *fiber.Ctx) error {
	userID, _ := getUserID(c)

	var user models.User
	query := `SELECT id, email, is_verified, is_active, role FROM users WHERE id = ? LIMIT 1`
	err := config.DB.QueryRow(query, userID).Scan(
		&user.ID,
		&user.Email,
		&user.IsVerified,
		&user.IsActive,
		&user.Role,
	)

	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"user": user})
}

type UpdateProfileInput struct {
	Role string `json:"role"`
}

func UpdateProfile(c *fiber.Ctx) error {
	userID, _ := getUserID(c)

	var user models.User
	query := `SELECT id, email, role FROM users WHERE id = ? LIMIT 1`
	err := config.DB.QueryRow(query, userID).Scan(&user.ID, &user.Email, &user.Role)

	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Profile updated", "user": user})
}

type ChangePasswordInput struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

func ChangePassword(c *fiber.Ctx) error {
	var input ChangePasswordInput
	if err := c.BodyParser(&input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := validate.Struct(input); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	userID, _ := getUserID(c)

	var currentHash string
	hashQuery := `SELECT password_hash FROM users WHERE id = ? LIMIT 1`
	err := config.DB.QueryRow(hashQuery, userID).Scan(&currentHash)

	if err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	if !utils.CheckPasswordHash(input.OldPassword, currentHash) {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Incorrect old password"})
	}

	newHash, err := utils.HashPassword(input.NewPassword)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	updateQuery := `UPDATE users SET password_hash = ? WHERE id = ?`
	config.DB.Exec(updateQuery, newHash, userID)

	logoutQuery := `UPDATE sessions SET is_active = 0 WHERE user_id = ?`
	config.DB.Exec(logoutQuery, userID)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Password changed successfully. You have been logged out from all devices."})
}

func DeactivateAccount(c *fiber.Ctx) error {
	userID, _ := getUserID(c)

	checkUser := `SELECT id FROM users WHERE id = ? LIMIT 1`
	var id uint
	if err := config.DB.QueryRow(checkUser, userID).Scan(&id); err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	deactivateQuery := `UPDATE users SET is_active = 0 WHERE id = ?`
	config.DB.Exec(deactivateQuery, userID)

	logoutQuery := `UPDATE sessions SET is_active = 0 WHERE user_id = ?`
	config.DB.Exec(logoutQuery, userID)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "Account deactivated. You can no longer log in until reactivated however you are now logged out."})
}

func ForceLogoutAllUsers(c *fiber.Ctx) error {
	query := `UPDATE sessions SET is_active = 0 WHERE is_active = 1`
	config.DB.Exec(query)

	return c.Status(http.StatusOK).JSON(fiber.Map{"message": "All users have been forcefully logged out"})
}
