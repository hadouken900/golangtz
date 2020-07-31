package controllers

import (
	"context"
	"fmt"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"io"
	"medods/db"
	"medods/model"
	"medods/tokens"
	"net/http"
	"time"
)

const secret string = "newSecretToken"

var GetTokens = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "application/json")

	guid := r.URL.Query().Get("guid")

	if guid == "" {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_guid"}`)
		return
	}

	currTime := time.Now().String()

	accessTokenString, err := tokens.CreateNewAccessToken(&guid, &currTime)
	refreshTokenString, err := tokens.CreateNewRefreshToken(&guid, &currTime)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"token_generation_failed"}`)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(refreshTokenString), 5)

	user := model.User{
		GUID:         guid,
		RefreshToken: string(hash),
		TokenID:      currTime,
	}

	db, _ := db.GetDBCollection()
	var res model.User
	err = db.FindOne(context.TODO(), bson.D{{"guid", user.GUID}}).Decode(&res)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			db.InsertOne(context.TODO(), user)
			io.WriteString(w, `create new user : `+user.GUID)

		} else {

			io.WriteString(w, err.Error())
		}

	} else {
		db.InsertOne(context.TODO(), user)
		io.WriteString(w, `add new refresh token to : `+user.GUID)
	}

	io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
	io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)

})

var Refresh = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	acceptTokenString, _ := jwtmiddleware.FromAuthHeader(r)
	refreshTokenString := r.URL.Query().Get("ref")
	claimsAcc := jwt.MapClaims{}
	claimsRef := jwt.MapClaims{}
	acceptToken, err := jwt.ParseWithClaims(acceptTokenString, claimsAcc, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		io.WriteString(w, "bad accept token")
	}
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, claimsRef, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		io.WriteString(w, "put refresh token in ?ref=")
	}

	if claimsAcc["tid"] == claimsRef["tid"] && claimsAcc["guid"] == claimsRef["guid"] && acceptToken.Valid && refreshToken.Valid {
		guid := fmt.Sprintf("%v", claimsRef["guid"])
		currTime := time.Now().String()

		db, _ := db.GetDBCollection()
		var res model.User
		db.FindOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}}).Decode(&res)
		err = bcrypt.CompareHashAndPassword([]byte(res.RefreshToken), []byte(refreshTokenString))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"error":"bad refresh token"}`)
			return
		}
		db.DeleteOne(context.TODO(), bson.D{{"tokenid", res.TokenID}})

		accessTokenString, _ := tokens.CreateNewAccessToken(&guid, &currTime)
		refreshTokenString, _ := tokens.CreateNewRefreshToken(&guid, &currTime)

		user := model.User{
			GUID:         guid,
			TokenID:      currTime,
			RefreshToken: refreshTokenString,
		}

		db.InsertOne(context.TODO(), user)

		io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
		io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)

		return
	} else {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Println("invalid tokens")

		for key, val := range claimsAcc {

			fmt.Printf("Key: %v, value: %v\n", key, val)
		}
		fmt.Println()
		for key, val := range claimsRef {

			fmt.Printf("Key: %v, value: %v\n", key, val)
		}
	}

})

var DeleteOne = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	accToken, _ := jwtmiddleware.FromAuthHeader(r)
	claimsAcc := jwt.MapClaims{}
	token, _ := jwt.ParseWithClaims(accToken, claimsAcc, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	refreshTokenString := r.URL.Query().Get("ref")
	claimsRef := jwt.MapClaims{}
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, claimsRef, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	db, _ := db.GetDBCollection()
	var res model.User
	db.FindOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}}).Decode(&res)
	fmt.Println(res.RefreshToken)
	fmt.Println(refreshTokenString)
	fmt.Println(res.TokenID)
	fmt.Println(claimsRef["tid"])
	fmt.Println(res.GUID)

	err = bcrypt.CompareHashAndPassword([]byte(res.RefreshToken), []byte(refreshToken.Raw))

	if err == nil && token.Valid && claimsAcc["guid"] == claimsRef["guid"] {
		db.DeleteOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}})
		io.WriteString(w, "refresh token was deleted")
	} else {
		io.WriteString(w, "you are not allowed to do this operation")
	}

})

var DeleteAll = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	guid := r.URL.Query().Get("guid")

	accToken, _ := jwtmiddleware.FromAuthHeader(r)
	claimsAcc := jwt.MapClaims{}
	token, _ := jwt.ParseWithClaims(accToken, claimsAcc, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	if claimsAcc["guid"] == guid && token.Valid {
		db, _ := db.GetDBCollection()
		_, err := db.DeleteMany(context.TODO(), bson.D{{"guid", guid}})

		if err != nil {
			io.WriteString(w, err.Error())
			return
		}

		io.WriteString(w, "refresh tokens of guid : "+guid+" was deleted")

	} else {
		io.WriteString(w, "you are not allowed to do this operation")
	}

})
