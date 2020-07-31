package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

const secret string = "newSecretToken"

func CreateNewRefreshToken(guid *string, tokenId *string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := make(jwt.MapClaims)

	claims["guid"] = guid
	claims["type"] = "refresh"
	claims["tid"] = tokenId
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	token.Claims = claims

	return token.SignedString([]byte(secret))
}

func CreateNewAccessToken(guid *string, tokenId *string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := make(jwt.MapClaims)

	claims["guid"] = guid
	claims["type"] = "access"
	claims["tid"] = tokenId
	claims["exp"] = time.Now().Add(time.Minute * 15).Unix()
	token.Claims = claims

	return token.SignedString([]byte(secret))
}
