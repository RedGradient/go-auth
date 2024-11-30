package handler

import (
    "errors"
    "fmt"
    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
    "go-auth/config"
    "go-auth/model"
    "go-auth/email"
    "go-auth/service"
    "golang.org/x/crypto/bcrypt"
    "log"
    "time"
)


type RefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}
var (
	ErrInvalidGUID       = errors.New("invalid GUID length")
	ErrTokenGeneration   = errors.New("failed to generate token pair")
	ErrHashingToken      = errors.New("failed to hash token")
	ErrSavingTokenToDB   = errors.New("failed to save refresh token")
)


type TokenController struct {
    TokenService *service.TokenService
    EmailSender email.EmailSender
}

func (tc *TokenController) TokenHandler(c *fiber.Ctx) error {
    // Generate token pair
    guid := c.Query("guid", "")
    accessToken, refreshToken, err := tc.generateAndSaveTokens(c.IP(), guid)
    if err != nil {
		status, message := errorToHTTPStatus(err)
		return c.Status(status).JSON(fiber.Map{"error": message})
	}

    // Return token pair
    tokens := fiber.Map{
        "access_token":  accessToken,
        "refresh_token": refreshToken,
    }
    return c.Status(fiber.StatusOK).JSON(tokens)
}

func (tc *TokenController) RefreshHandler(c *fiber.Ctx) error {
    // Get token from request
    var refreshRequest RefreshRequest
    err := c.BodyParser(&refreshRequest)
    if err != nil {
        return err
    }

    // Validation
    token, err := tc.validateRefreshToken(c, refreshRequest.RefreshToken)
    if err != nil {
        return err
    }

    claims := token.Claims.(jwt.MapClaims)

    // Check if Refresh token received from unknown IP
    if c.IP() != claims["ip"].(string) {
        addr := "username@example.com"
        message := "Access from unknown IP: " + c.IP()
        err = tc.EmailSender.Send(addr, "Security alert", message)
        if err != nil {
            log.Printf("Security alert cannot be sent to %s", addr)
        }
    }

    // Generate new Access & Refresh tokens
    guid := claims["guid"].(string)
    newAccessToken, newRefreshToken, err := tc.generateAndSaveTokens(c.IP(), guid)
    if err != nil {
		status, message := errorToHTTPStatus(err)
		return c.Status(status).JSON(fiber.Map{"error": message})
	}

    // Get all Refresh tokens where Guid == claim.Guid
    userTokens, err := tc.TokenService.GetTokensByGuid(guid)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Internal server error"})
    }
    var refreshToken model.RefreshTokenModel
    for _, tokenModel := range userTokens {
        if verifyTokenHash(token.Raw, tokenModel.RefreshTokenHash) {
            refreshToken = tokenModel
            break
        }
    }

    // Check if token is revoked
    if refreshToken.Revoked {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Refresh token is revoked"})
    }

    // Return token pair
    tokens := fiber.Map{
        "access_token":  newAccessToken,
        "refresh_token": newRefreshToken,
    }

    return c.Status(fiber.StatusOK).JSON(tokens)
}

func (tc *TokenController) validateRefreshToken(c *fiber.Ctx, tokenToValidate string) (*jwt.Token, error) {
    token, err := jwt.Parse(tokenToValidate, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unsupported signing method")
        }
        return config.JwtSecret, nil
    })
    if err != nil || !token.Valid {
        return token, c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid or expired refresh token"})
    }

    return token, nil
}

func (tc *TokenController) generateAndSaveTokens(ip string, guid string) (string, string, error) {
    // `guid` should not be empty
    if len(guid) != 16 {
        return "", "", fmt.Errorf("%w: got length %d, expected 16", ErrInvalidGUID, len(guid))
    }

    // Generate token pair
    accessToken, refreshToken, err := generateTokenPair(guid, ip)
    if err != nil {
        return "", "", fmt.Errorf("%w: %v", ErrTokenGeneration, err)
    }

    // Save Refresh token hash to database
    hash, err := hashToken(refreshToken)
    if err != nil {
        return "", "", fmt.Errorf("%w: %v", ErrHashingToken, err)
    }

    // Save Refresh token to the database
    err = tc.TokenService.CreateRefreshToken(guid, hash)
    if err != nil {
        return "", "", fmt.Errorf("%w: GUID %s, %v", ErrSavingTokenToDB, guid, err)
    }

    return accessToken, refreshToken, nil
}

func generateAccessToken(guid string, ip string, minutes time.Duration) (string, error) {
    claims := jwt.MapClaims{
        "guid": guid,
        "type": "access",
        "ip": ip,
        "exp": time.Now().Add(time.Minute * minutes).Unix(),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
    return token.SignedString(config.JwtSecret)
}

func generateRefreshToken(guid string, ip string, minutes time.Duration) (string, error) {
    claims := jwt.MapClaims{
        "guid": guid,
        "ip": ip,
        "type": "refresh",
        "exp": time.Now().Add(time.Minute * minutes).Unix(),
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(config.JwtSecret)
}

func generateTokenPair(guid string, ip string) (string, string, error) {
    accessToken, err := generateAccessToken(guid, ip, 15)
    if err != nil {
        return "", "", err
    }

    const FourDaysInMinutes = 4320
    refreshToken, err := generateRefreshToken(guid, ip, FourDaysInMinutes)
    if err != nil {
        return "", "", err
    }

    return accessToken, refreshToken, nil
}

func hashToken(token string) (string, error) {
    // bcrypt has limitation for string length: 72 bytes
    const BcryptLimit = 72
    hash, err := bcrypt.GenerateFromPassword([]byte(token)[:BcryptLimit], bcrypt.DefaultCost)
    if err != nil {
        return "", err
    }

    return string(hash), nil
}

func verifyTokenHash(token, hash string) bool {
    const BcryptLimit = 72
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(token)[:BcryptLimit])
    return err == nil
}

func errorToHTTPStatus(err error) (int, string) {
	switch {
	case errors.Is(err, ErrInvalidGUID):
		return fiber.StatusBadRequest, "GUID must be 16 characters long"
	case errors.Is(err, ErrTokenGeneration):
		return fiber.StatusInternalServerError, "Error generating tokens"
	case errors.Is(err, ErrHashingToken):
		return fiber.StatusInternalServerError, "Error hashing token"
	case errors.Is(err, ErrSavingTokenToDB):
		return fiber.StatusInternalServerError, "Error saving token to database"
	default:
		// Неизвестная ошибка
		return fiber.StatusInternalServerError, "Unexpected error occurred"
	}
}