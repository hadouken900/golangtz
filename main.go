package main

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"

	//"context"
	//"fmt"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"

	"golang.org/x/crypto/bcrypt"

	"io"
	//"log"

	//"log"
	"net/http"
	"time"

	"github.com/auth0/go-jwt-middleware"
	"github.com/gorilla/mux"
	//"github.com/google/uuid"
)

const secret string = "newSecretToken"

type User struct {
	GUID         string `json:"guid"`
	RefreshToken string `json:"refreshtoken"`
}

func main() {

	r := mux.NewRouter()

	r.Handle("/", AuthMiddleware(http.FileServer(http.Dir("./views"))))

	r.Handle("/get-tokens", GetTokens).Methods("GET")
	r.Handle("/refresh", NotImplemented).Methods("GET")
	r.Handle("/delete-one", NotImplemented).Methods("GET")
	r.Handle("/delete-all", NotImplemented).Methods("GET")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	http.ListenAndServe(":8080", r)

}

func AuthMiddleware(server http.Handler) http.Handler {

	jwtMiddleware := jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return []byte(secret), nil
		},
		SigningMethod: jwt.SigningMethodHS512,
	})
	return jwtMiddleware.Handler(server)
}

var GetTokens = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

	w.Header().Add("Content-Type", "application/json")

	guid := r.URL.Query().Get("guid")

	if guid == "" {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid_guid"}`)
		return
	}

	accessTokenString, err := createNewAccessToken(&guid)
	refreshTokenString, err := createNewRefreshToken(&guid)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"token_generation_failed"}`)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(refreshTokenString), 5)

	user := User{
		GUID:         guid,
		RefreshToken: string(hash),
	}

	db, _ := GetDBCollection()
	var res User
	err = db.FindOne(context.TODO(), bson.D{{"guid", user.GUID}}).Decode(&res)
	if err != nil {
		if err.Error() == "mongo: no documents in result" {
			db.InsertOne(context.TODO(), user)
			io.WriteString(w, `create new user : `+user.GUID)

		} else {

			log.Fatal(err)
		}

	} else {
		db.InsertOne(context.TODO(), user)
		io.WriteString(w, `add new refresh token to : `+user.GUID)
	}

	io.WriteString(w, `{"access token":"`+accessTokenString+`"}`+"\n")
	io.WriteString(w, `{"refresh token":"`+refreshTokenString+`"}`)

})

func createNewRefreshToken(guid *string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := make(jwt.MapClaims)

	claims["guid"] = guid
	claims["type"] = "refresh"
	claims["iat"] = time.Now()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	token.Claims = claims
	return token.SignedString([]byte(secret))
}

func createNewAccessToken(guid *string) (string, error) {

	token := jwt.New(jwt.SigningMethodHS512)
	claims := make(jwt.MapClaims)

	claims["guid"] = guid
	claims["type"] = "access"
	claims["iat"] = time.Now()
	claims["exp"] = time.Now().Add(time.Minute).Unix()
	token.Claims = claims
	return token.SignedString([]byte(secret))
}

var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
})

func GetDBCollection() (*mongo.Collection, error) {

	// Create client
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://127.0.0.1:27017"))
	if err != nil {
		log.Fatal(err)
	}

	// Create connect
	err = client.Connect(context.TODO())
	if err != nil {
		log.Fatal(err)
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database("test").Collection("users")

	fmt.Println("Connected to MongoDB!")
	return collection, nil
}
