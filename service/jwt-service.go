package service

import (
	"math/big"
	"os"
	"time"

	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

type JWTService interface {
	GenerateToken(UserID string, Email string, Profile string, Jk string, telephone string, pin string, name string) string
	ValidateToken(token string) (*jwt.Token, error)
	ValidateTokenGoogle(token string) (*jwt.Token, error)
}

type jwtCustomClaim struct {
	UserID  string `json:"userid"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Profile string `json:"profile"`
	Telp    string `json:"telp"`
	Pin     string `json:"pin"`
	Jk      string `json:"jk"`
	jwt.StandardClaims
}

type jwtService struct {
	secretKey string
	issuer    string
}

// NewJWTService method is creates a new instance of JWTService
func NewJWTService() JWTService {
	return &jwtService{
		issuer:    "aminivan",
		secretKey: getSecretKey(),
	}
}

func getSecretKey() string {
	secretKey := os.Getenv("JWT_SECRET")
	if secretKey != "" {
		secretKey = "aminivan"
	}
	return secretKey
}

func (j *jwtService) GenerateToken(UserID string, Email string, Profile string, Jk string, Telephone string, Pin string, Name string) string {
	claims := &jwtCustomClaim{
		UserID,
		Name,
		Email,
		Profile,
		Telephone,
		Pin,
		Jk,
		jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(0, 3, 0).Unix(),
			Issuer:    j.issuer,
			IssuedAt:  time.Now().Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	t, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		panic(err)
	}
	return t
}

func (j *jwtService) ValidateToken(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t_ *jwt.Token) (interface{}, error) {
		if _, ok := t_.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method %v", t_.Header["alg"])
		}
		return []byte(j.secretKey), nil
	})
}

func (j *jwtService) ValidateTokenGoogle(token string) (*jwt.Token, error) {
	return jwt.Parse(token, func(t_ *jwt.Token) (interface{}, error) {
		switch t_.Header["alg"] {
		case "HS256":
			if _, ok := t_.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method %v", t_.Header["alg"])
			}
			return []byte(j.secretKey), nil
		case "RS256":
			publicKey, err := loadRSAPublicKeyFromGoogle()
			if err != nil {
				return nil, err
			}
			return publicKey, nil
		default:
			return nil, fmt.Errorf("Unsupported signing method %v", t_.Header["alg"])
		}
	})
}

func loadRSAPublicKeyFromGoogle() (*rsa.PublicKey, error) {
	// Fetch the JSON Web Key Set from Google
	resp, err := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse the JSON Web Key Set
	var jwks struct {
		Keys []struct {
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, err
	}

	// Find the RSA public key with the matching "kid"
	for _, key := range jwks.Keys {
		if key.Alg == "RS256" && key.Kid == "05150a1320b9395b05716877376928509bab44ac" {
			// Parse the RSA public key components
			nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				return nil, err
			}
			eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				return nil, err
			}

			// Create the RSA public key structure
			publicKey := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nBytes),
				E: int(new(big.Int).SetBytes(eBytes).Int64()),
			}

			return publicKey, nil
		}
	}

	return nil, errors.New("RSA public key not found for the specified key ID")
}
