package casaos

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// CasaOS signs access tokens with ES256 and publishes the public key as JWKS
// at <user-service>/.well-known/jwks.json. Access tokens use the issuer
// "casaos"; refresh tokens ("refresh") are rejected here.
const accessTokenIssuer = "casaos"

var ErrInvalidToken = errors.New("invalid CasaOS token")

type jwksCache struct {
	client  *Client
	mu      sync.Mutex
	key     *ecdsa.PublicKey
	fetched time.Time
}

func (j *jwksCache) get(force bool) (*ecdsa.PublicKey, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.key != nil && !force && time.Since(j.fetched) < 5*time.Minute {
		return j.key, nil
	}
	base, err := j.client.serviceURL("user-service.url")
	if err != nil {
		return nil, err
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := j.client.getJSON(base+"/.well-known/jwks.json", &jwks); err != nil {
		return nil, err
	}
	if len(jwks.Keys) == 0 || jwks.Keys[0].Kty != "EC" || jwks.Keys[0].Crv != "P-256" {
		return nil, errors.New("CasaOS JWKS has no P-256 key")
	}
	x, err1 := base64.RawURLEncoding.DecodeString(jwks.Keys[0].X)
	y, err2 := base64.RawURLEncoding.DecodeString(jwks.Keys[0].Y)
	if err1 != nil || err2 != nil {
		return nil, errors.New("CasaOS JWKS key is not valid base64url")
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("CasaOS JWKS key is not on P-256")
	}
	j.key, j.fetched = key, time.Now()
	return key, nil
}

// VerifyToken checks a CasaOS access token and returns its username.
func (c *Client) VerifyToken(token string) (string, error) {
	key, err := c.jwks.get(false)
	if err != nil {
		return "", err
	}
	user, err := verifyES256(token, key, time.Now())
	if errors.Is(err, errBadSignature) {
		// CasaOS may have rotated its key; retry once with a fresh JWKS.
		if key, kerr := c.jwks.get(true); kerr == nil {
			user, err = verifyES256(token, key, time.Now())
		}
	}
	return user, err
}

var errBadSignature = fmt.Errorf("%w: bad signature", ErrInvalidToken)

func verifyES256(token string, key *ecdsa.PublicKey, now time.Time) (string, error) {
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(token, "Bearer ")), ".")
	if len(parts) != 3 {
		return "", ErrInvalidToken
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := decodeSegment(parts[0], &header); err != nil || header.Alg != "ES256" {
		return "", fmt.Errorf("%w: unsupported algorithm", ErrInvalidToken)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return "", errBadSignature
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return "", errBadSignature
	}
	var claims struct {
		Username  string `json:"username"`
		Issuer    string `json:"iss"`
		ExpiresAt *int64 `json:"exp"`
		NotBefore *int64 `json:"nbf"`
	}
	if err := decodeSegment(parts[1], &claims); err != nil {
		return "", ErrInvalidToken
	}
	if claims.Issuer != accessTokenIssuer {
		return "", fmt.Errorf("%w: not an access token", ErrInvalidToken)
	}
	if claims.ExpiresAt == nil || now.Unix() >= *claims.ExpiresAt {
		return "", fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	if claims.NotBefore != nil && now.Unix() < *claims.NotBefore {
		return "", fmt.Errorf("%w: not valid yet", ErrInvalidToken)
	}
	if claims.Username == "" {
		return "", fmt.Errorf("%w: no username", ErrInvalidToken)
	}
	return claims.Username, nil
}

func decodeSegment(seg string, v any) error {
	data, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
