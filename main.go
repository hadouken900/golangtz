package main

import (
	"net/http"
	"os"

	"medods/controllers"

	"github.com/auth0/go-jwt-middleware"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

const secret string = "newSecretToken"

func main() {

	r := mux.NewRouter()

	r.Handle("/", http.FileServer(http.Dir("./views")))

	r.Handle("/get-tokens", controllers.GetTokens).Methods("GET")
	r.Handle("/refresh", AuthMiddleware(controllers.Refresh)).Methods("GET")
	r.Handle("/delete-one", AuthMiddleware(controllers.DeleteOne)).Methods("DELETE")
	r.Handle("/delete-all", AuthMiddleware(controllers.DeleteAll)).Methods("DELETE")


	port , err:= os.LookupEnv("PORT")
	if err == false {
		port = "5000"
	}
	http.ListenAndServe(":"+port, r)

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

var NotImplemented = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Not implemented"))
})
