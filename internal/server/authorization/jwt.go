package authorization

import (
	"crypto/ecdsa"
	"errors"
	"os"

	"github.com/glimesh/broadcast-box/internal/environment"
	"github.com/glimesh/broadcast-box/internal/ip"
	"github.com/golang-jwt/jwt/v5"
)

var ErrAuthorizationNotReady = errors.New("authorization is not initialized")

type JwtPayload struct {
	SessionId      string `json:"sessionId"`
	LhUserId       string `json:"lhUserId"`
	AccessType     string `json:"accessType"`
	WHEPAccessType string `json:"whepAccessType"`
	WorkerIp       string `json:"workerIp"`

	jwt.RegisteredClaims
}

type jwtVerifier struct {
	publicKey         *ecdsa.PublicKey
	advertisedIPs     map[string]struct{}
	advertisedAddress string
}

var cachedVerifier *jwtVerifier

// IsJwtEnabled reports whether the process is configured for JWT stream auth.
// When the key is absent, callers retain the legacy stream-key authorization
// path; when it is present, startup must initialize a valid verifier.
func IsJwtEnabled() bool {
	return environment.SanitizeValue(os.Getenv(environment.JWTPublicKey)) != ""
}

func Initialize() error {
	cachedVerifier = nil

	publicKeyPEM := environment.SanitizeValue(os.Getenv(environment.JWTPublicKey))
	if publicKeyPEM == "" {
		return errors.New("JWT_PUBLIC_KEY is required")
	}

	publicKey, err := jwt.ParseECPublicKeyFromPEM([]byte(publicKeyPEM))
	if err != nil {
		return errors.New("JWT_PUBLIC_KEY is invalid")
	}

	advertisedIPs, err := ip.ResolveAdvertisedIPs()
	if err != nil || len(advertisedIPs) == 0 {
		return errors.New("advertised public IP is unavailable")
	}

	cachedVerifier = &jwtVerifier{
		publicKey:         publicKey,
		advertisedIPs:     makeIPSet(advertisedIPs),
		advertisedAddress: advertisedIPs[0],
	}
	return nil
}

// AdvertisedAddress returns the startup-cached address used by worker auth.
func AdvertisedAddress() string {
	if cachedVerifier == nil {
		return ""
	}

	return cachedVerifier.advertisedAddress
}

func VerifyJwtToken(tokenString string) (*JwtPayload, error) {
	verifier := cachedVerifier
	if verifier == nil {
		return nil, ErrAuthorizationNotReady
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&JwtPayload{},
		func(_ *jwt.Token) (any, error) {
			return verifier.publicKey, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
	)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrTokenUnverifiable
	}

	claims, ok := token.Claims.(*JwtPayload)
	if !ok {
		return nil, jwt.ErrTokenInvalidClaims
	}

	if err := validateClaims(claims, verifier.advertisedIPs); err != nil {
		return nil, err
	}

	return claims, nil
}

func validateClaims(claims *JwtPayload, advertisedIPs map[string]struct{}) error {
	if claims.SessionId == "" {
		return errors.New("jwt sessionId is empty")
	}
	if claims.WorkerIp == "" {
		return errors.New("jwt workerIp is empty")
	}
	if claims.ExpiresAt == nil {
		return errors.New("jwt expiry is missing")
	}
	if claims.AccessType != "whip" && claims.AccessType != "whep" {
		return errors.New("jwt accessType is invalid")
	}
	if claims.AccessType == "whep" &&
		claims.WHEPAccessType != WHEPAccessTypeViewer &&
		claims.WHEPAccessType != WHEPAccessTypeEditor {
		return errors.New("jwt whepAccessType is invalid")
	}
	if claims.AccessType == "whip" && claims.WHEPAccessType != "" {
		return errors.New("jwt whepAccessType is not allowed for WHIP")
	}
	if _, ok := advertisedIPs[claims.WorkerIp]; !ok {
		return errors.New("jwt workerIp does not match this worker")
	}

	return nil
}

func makeIPSet(addresses []string) map[string]struct{} {
	result := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		result[address] = struct{}{}
	}
	return result
}
