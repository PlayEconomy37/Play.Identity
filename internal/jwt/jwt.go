package jwt

import (
	"crypto/rsa"
	"strconv"
	"sync"
	"time"

	"github.com/PlayEconomy37/Play.Common/common"
	"github.com/pascaldekloe/jwt"
)

var (
	loadRsaKeyOnce         sync.Once
	createAccessTokenError error
	rsaPrivateKey          *rsa.PrivateKey
)

// CreateAccessToken generates a new JWT access token valid for 24 hours
func CreateAccessToken(userID int64, privateKey string) (string, error) {
	loadRsaKeyOnce.Do(func() {
		rsaPrivateKey, createAccessTokenError = common.LoadRsaPrivateKey(privateKey)
	})

	if createAccessTokenError != nil {
		return "", createAccessTokenError
	}

	// Create a JWT claims struct containing the user ID as the subject, with an issued
	// time of now and validity window of the next 24 hours. We also set the issuer and
	// audience to a unique identifier for our application.
	var claims jwt.Claims
	claims.Subject = strconv.FormatInt(userID, 10)
	claims.Issued = jwt.NewNumericTime(time.Now())
	claims.NotBefore = jwt.NewNumericTime(time.Now())
	claims.Expires = jwt.NewNumericTime(time.Now().Add(24 * time.Hour))
	claims.Issuer = "http://localhost:4445"
	claims.Audiences = []string{"http://localhost:3000"}

	// Sign the JWT claims using the HMAC-SHA256 algorithm and the secret key from the
	// application config. This returns a []byte slice containing the JWT as a base64-
	// encoded string.
	jwtBytes, createAccessTokenError := claims.RSASign(jwt.RS256, rsaPrivateKey)
	if createAccessTokenError != nil {
		return "", createAccessTokenError
	}

	return string(jwtBytes), nil
}
