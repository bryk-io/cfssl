package csr

import (
	"github.com/cloudflare/cfssl/log"
)

// A Generator is responsible for validating certificate requests.
type Generator struct {
	Validator func(*CertificateRequest) error
}

// ProcessRequest validates and processes the incoming request. It is
// a wrapper around a validator and the ParseRequest function.
func (g *Generator) ProcessRequest(req *CertificateRequest) (csr, key []byte, err error) {
	log.Info("generate received request")
	err = g.Validator(req)
	if err != nil {
		log.Warningf("invalid request: %v", err)
		return nil, nil, err
	}

	csr, key, err = ParseRequest(req)
	if err != nil {
		return nil, nil, err
	}
	return
}
