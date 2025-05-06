// This is a simple example of how to implement a web3 login endpoint using the siwe-go library.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spruceid/siwe-go"
)

const port = ":8080"

func main() {
	http.HandleFunc("/api/v1/auth/web3:login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		err := Web3Login(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := http.ListenAndServe(port, nil)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

// verifyWalletSignature verifies the signature of a wallet address
func verifyWalletSignature(messageStr string, sig string) (jwt.MapClaims, error) {

	message, err := siwe.ParseMessage(messageStr)
	if err != nil {
		err = fmt.Errorf("parse message err: %v", err)
		return nil, err
	}

	verify, err := message.ValidNow()
	if err != nil {
		err = fmt.Errorf("verify message err: %v", err)
		return nil, err
	}

	if !verify {
		err = fmt.Errorf("verify message fail: %v", err)
		return nil, err
	}

	publicKey, err := message.VerifyEIP191(sig)

	if err != nil {
		err = fmt.Errorf("verifyEIP191 err: %v", err)
		return nil, err
	}

	pubBytes := crypto.FromECDSAPub(publicKey)
	publicKeyString := hexutil.Encode(pubBytes)

	// Return the verified claims
	claims := jwt.MapClaims{
		"web3_pub_key": publicKeyString,
	}
	return claims, nil
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

func Web3Login(w http.ResponseWriter, r *http.Request) error {
	// Parse the login request body
	req := new(LoginRequest)

	// 解析 JSON 請求體
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(req)
	if err != nil {
		return errors.New("invalid request body")
	}

	// Verify the signature
	claims, err := verifyWalletSignature(req.Message, req.Signature)
	if err != nil {
		return errors.New(err.Error())
	}

	// Generate a JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		return errors.New("error creating JWT token")
	}

	// Set the JWT token in the response header
	http.SetCookie(w, &http.Cookie{
		Name:    "jwt_token",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 24),
	})

	// Return a success response
	w.WriteHeader(http.StatusOK)
	return nil
}
