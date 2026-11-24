package auth

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager handles JWT token generation and validation
type TokenManager struct {
	secretFile string
	secret     []byte
}

// GASPClaims represents the JWT claims for GASP tokens
type GASPClaims struct {
	TokenID  uint64 `json:"token_id"`
	Username string `json:"username"`
	ClientIP string `json:"client_ip"`
	jwt.RegisteredClaims
}

const (
	// tokenIssuer and tokenAudience are set on every token and required on
	// validation, so a token signed for another service with the same key
	// is not accepted here.
	tokenIssuer   = "gasp"
	tokenAudience = "gasp"

	minSecretLength = 32
)

// NewTokenManager creates a new token manager
func NewTokenManager(secretFile string) *TokenManager {
	return &TokenManager{
		secretFile: secretFile,
	}
}

// LoadSecret loads the JWT secret from file. The file must not be readable
// or writable by group or others, and must hold at least 32 bytes besides
// surrounding whitespace.
func (tm *TokenManager) LoadSecret() error {
	info, err := os.Stat(tm.secretFile)
	if err != nil {
		return fmt.Errorf("failed to read JWT secret: %w", err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("JWT secret file %s has permissions %#o; run chmod 600 on it", tm.secretFile, perm)
	}

	data, err := os.ReadFile(tm.secretFile)
	if err != nil {
		return fmt.Errorf("failed to read JWT secret: %w", err)
	}

	// A trailing newline from echo or openssl shouldn't count toward the
	// minimum. The bytes are still used as written, so existing secret
	// files keep producing the same signatures.
	if len(bytes.TrimSpace(data)) < minSecretLength {
		return fmt.Errorf("JWT secret must be at least %d bytes", minSecretLength)
	}

	tm.secret = data
	return nil
}

// GenerateToken generates a JWT token for a session
func (tm *TokenManager) GenerateToken(session *Session) (string, error) {
	claims := GASPClaims{
		TokenID:  session.TokenID,
		Username: session.Username,
		ClientIP: session.ClientIP,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(session.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
			Subject:   session.Username,
			Issuer:    tokenIssuer,
			Audience:  jwt.ClaimStrings{tokenAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(tm.secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
func (tm *TokenManager) ValidateToken(tokenString string) (*GASPClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &GASPClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return tm.secret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(tokenIssuer),
		jwt.WithAudience(tokenAudience),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*GASPClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// GenerateSecret generates a new random JWT secret
func GenerateSecret() ([]byte, error) {
	secret := make([]byte, 64)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}
	return secret, nil
}
