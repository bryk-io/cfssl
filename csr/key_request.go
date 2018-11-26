package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"github.com/cloudflare/cfssl/log"
)

// A KeyRequest is a generic request for a new key.
type KeyRequest interface {
	Algo() string
	Size() int
	Generate() (crypto.PrivateKey, error)
	SigAlgo() x509.SignatureAlgorithm
}

// A BasicKeyRequest contains the algorithm and key size for a new private key.
type BasicKeyRequest struct {
	A string `json:"algo" yaml:"algo"`
	S int    `json:"size" yaml:"size"`
}

// NewBasicKeyRequest returns a default BasicKeyRequest.
func NewBasicKeyRequest() *BasicKeyRequest {
	return &BasicKeyRequest{"ecdsa", curveP256}
}

// Algo returns the requested key algorithm represented as a string.
func (kr *BasicKeyRequest) Algo() string {
	return kr.A
}

// Size returns the requested key size.
func (kr *BasicKeyRequest) Size() int {
	return kr.S
}

// Generate generates a key as specified in the request. Currently,
// only ECDSA and RSA are supported.
func (kr *BasicKeyRequest) Generate() (crypto.PrivateKey, error) {
	log.Debugf("generate key from request: algo=%s, size=%d", kr.Algo(), kr.Size())
	switch kr.Algo() {
	case "rsa":
		if kr.Size() < 2048 {
			return nil, errors.New("RSA key is too weak")
		}
		if kr.Size() > 8192 {
			return nil, errors.New("RSA key size too large")
		}
		return rsa.GenerateKey(rand.Reader, kr.Size())
	case "ecdsa":
		var curve elliptic.Curve
		switch kr.Size() {
		case curveP256:
			curve = elliptic.P256()
		case curveP384:
			curve = elliptic.P384()
		case curveP521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("invalid curve")
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	default:
		return nil, errors.New("invalid algorithm")
	}
}

// SigAlgo returns an appropriate X.509 signature algorithm given the
// key request's type and size.
func (kr *BasicKeyRequest) SigAlgo() x509.SignatureAlgorithm {
	switch kr.Algo() {
	case "rsa":
		switch {
		case kr.Size() >= 4096:
			return x509.SHA512WithRSA
		case kr.Size() >= 3072:
			return x509.SHA384WithRSA
		case kr.Size() >= 2048:
			return x509.SHA256WithRSA
		default:
			return x509.SHA1WithRSA
		}
	case "ecdsa":
		switch kr.Size() {
		case curveP521:
			return x509.ECDSAWithSHA512
		case curveP384:
			return x509.ECDSAWithSHA384
		case curveP256:
			return x509.ECDSAWithSHA256
		default:
			return x509.ECDSAWithSHA1
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

