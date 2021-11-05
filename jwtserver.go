package main

import (
	"fmt"
	"net/http"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
)

var symmetricKey = []byte("secretkey")

func generateJwt() (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"authorized": true,
		"user": "Reese Krome",
		"nbf": time.Now().Unix(),
	})

	tokenString, err := token.SignedString(symmetricKey)
	if (err != nil) {
		fmt.Printf("Error: %s\n", err.Error())
		return "", err
	}

	return tokenString, nil
}

func secret(response http.ResponseWriter, request *http.Request) {
	fmt.Fprintf(response, "Super Secret Informtion");
}

func token(response http.ResponseWriter, request *http.Request) {
	token, err := generateJwt();
	if (err != nil) {
		// Return 500
	}
	fmt.Fprintf(response, "Token=%s\n", token)
}

func authorize(handler func(response http.ResponseWriter, request *http.Request)) http.HandlerFunc {
	return func (response http.ResponseWriter, request *http.Request) {
		if request.Header["Token"] != nil {
			token, err := jwt.Parse(request.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Failed to parse JWT.")
				}
				return symmetricKey, nil
			})

			if (err != nil) {
				fmt.Fprintf(response, err.Error())
			}

			if token.Valid {
				handler(response, request)
			}

		} else {
			fmt.Fprintf(response, "Not authorized.\n")
		}
	}
}

func main() {
	fmt.Printf("Starting JWT Server... \n")

	http.HandleFunc("/token", token)
	http.HandleFunc("/secret", authorize(secret))
	
	port := "8000"
	error := http.ListenAndServe("localhost:"+port,nil)
	if error != nil {
		fmt.Printf("Error: %s\n", error)
	}	
}