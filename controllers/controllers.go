package controllers

import (
	"context"
	"fmt"
	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
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
		io.WriteString(w, "example : ?guid=")
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

	ctx := context.Background()

	col, base, _ := db.GetDBCollectionAndBase(ctx)
	defer base.Client().Disconnect(ctx)
	var res model.User

	//starting tx
	err = base.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			fmt.Println(err)
			return err
		}

		err = col.FindOne(context.TODO(), bson.D{{"guid", user.GUID}}).Decode(&res)
		if err != nil {
			if err.Error() == "mongo: no documents in result" {
				_, err := col.InsertOne(context.TODO(), user)

				if err != nil {
					sessionContext.AbortTransaction(sessionContext)
					io.WriteString(w, "tx aborted")
				}

				io.WriteString(w, `create new user : `+user.GUID)

				io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
				io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)
				sessionContext.CommitTransaction(sessionContext)
				fmt.Println("Tx completed")
				return nil

			}

		} else {
			_, err := col.InsertOne(context.TODO(), user)
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				io.WriteString(w, "tx aborted")
			}
			io.WriteString(w, `add new refresh token to : `+user.GUID)

			io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
			io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)
			sessionContext.CommitTransaction(sessionContext)
			fmt.Println("tx completed")
			return nil
		}
		return nil
	})
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
		ctx := context.Background()

		col, base, _ := db.GetDBCollectionAndBase(ctx)
		defer base.Client().Disconnect(ctx)

		var res model.User

		err = base.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()
			if err != nil {
				fmt.Println(err)
				return err
			}

			col.FindOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}}).Decode(&res)
			err = bcrypt.CompareHashAndPassword([]byte(res.RefreshToken), []byte(refreshTokenString))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				io.WriteString(w, `{"error":"bad refresh token"}`)
				return nil
			}
			_, err = col.DeleteOne(context.TODO(), bson.D{{"tokenid", res.TokenID}})
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				io.WriteString(w, "tx aborted")
			}
			accessTokenString, _ := tokens.CreateNewAccessToken(&guid, &currTime)
			refreshTokenString, _ := tokens.CreateNewRefreshToken(&guid, &currTime)

			hash, _ := bcrypt.GenerateFromPassword([]byte(refreshTokenString), 5)

			fmt.Println("create new hash :")
			fmt.Println(string(hash))

			user := model.User{
				GUID:         guid,
				TokenID:      currTime,
				RefreshToken: string(hash),
			}

			_, err = col.InsertOne(context.TODO(), user)
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				io.WriteString(w, "tx aborted")
			}

			io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
			io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)
			sessionContext.CommitTransaction(sessionContext)
			return nil
		})
	} else {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "bad pair of tokens")
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
	_, err := jwt.ParseWithClaims(refreshTokenString, claimsRef, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		io.WriteString(w, "bad refresh token")
	}

	ctx := context.Background()
	col, base, _ := db.GetDBCollectionAndBase(ctx)
	defer base.Client().Disconnect(ctx)
	var res model.User

	err = base.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
		err := sessionContext.StartTransaction()
		if err != nil {
			fmt.Println(err)
			return err
		}
		col.FindOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}}).Decode(&res)

		err = bcrypt.CompareHashAndPassword([]byte(res.RefreshToken), []byte(refreshTokenString))

		if err == nil && token.Valid && claimsAcc["guid"] == claimsRef["guid"] {
			_, err = col.DeleteOne(context.TODO(), bson.D{{"tokenid", claimsRef["tid"]}})
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				io.WriteString(w, "tx aborted")
			}
			sessionContext.CommitTransaction(sessionContext)
			io.WriteString(w, "refresh token was deleted")
			return nil
		} else {
			io.WriteString(w, "you are not allowed to do this operation")
			fmt.Printf("%v", claimsRef["guid"])
			fmt.Printf("%v", claimsAcc["guid"])
			fmt.Println(err.Error())
			fmt.Println(res.RefreshToken)
			fmt.Println(refreshTokenString)

			return nil
		}
	})
})

var DeleteAll = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")

	guid := r.URL.Query().Get("guid")

	accToken, _ := jwtmiddleware.FromAuthHeader(r)
	claimsAcc := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accToken, claimsAcc, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		io.WriteString(w, "bad accept token")
	}

	if claimsAcc["guid"] == guid && token.Valid {

		ctx := context.Background()
		col, base, _ := db.GetDBCollectionAndBase(ctx)
		defer base.Client().Disconnect(ctx)

		err = base.Client().UseSession(ctx, func(sessionContext mongo.SessionContext) error {
			err := sessionContext.StartTransaction()
			if err != nil {
				fmt.Println(err)
				return err
			}
			_, err = col.DeleteMany(context.TODO(), bson.D{{"guid", guid}})
			if err != nil {
				sessionContext.AbortTransaction(sessionContext)
				io.WriteString(w, "tx aborted")

			}

			sessionContext.CommitTransaction(sessionContext)
			io.WriteString(w, "refresh tokens of guid : "+guid+" was deleted")
			return nil

		})
	} else {
		io.WriteString(w, "you are not allowed to do this operation")
	}

})
