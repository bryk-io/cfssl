// Package csr implements certificate requests for CFSSL.
package csr

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"strings"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

const (
	curveP256 = 256
	curveP384 = 384
	curveP521 = 521
)

// A Name contains the SubjectInfo fields.
type Name struct {
	C            string // Country
	ST           string // State
	L            string // Locality
	O            string // OrganisationName
	OU           string // OrganisationalUnitName
	SerialNumber string

	// Additional fields
	PC               string `json:"pc,omitempty" yaml:"pc,omitempty"` // PostalCode
	SA               string `json:"sa,omitempty" yaml:"sa,omitempty"` // StringAddress
	Pseudonym        string `json:"pseudonym,omitempty" yaml:"pseudonym,omitempty"`
	UniqueIdentifier string `json:"unique_identifier,omitempty" yaml:"unique_identifier,omitempty"`
	UnstructuredName string `json:"unstructured_name,omitempty" yaml:"unstructured_name,omitempty"`
}

// A CertificateRequest encapsulates the API interface to the
// certificate request functionality.
type CertificateRequest struct {
	CN           string
	Names        []Name           `json:"names" yaml:"names"`
	Hosts        []string         `json:"hosts" yaml:"hosts"`
	KeyRequest   KeyRequest       `json:"key,omitempty" yaml:"key,omitempty"`
	CA           *CAConfig        `json:"ca,omitempty" yaml:"ca,omitempty"`
	SerialNumber string           `json:"serialnumber,omitempty" yaml:"serialnumber,omitempty"`
	Extensions   []Extension `json:"extensions,omitempty" yaml:"extensions,omitempty"`
}

// New returns a new, empty CertificateRequest with a
// BasicKeyRequest.
func New() *CertificateRequest {
	return &CertificateRequest{
		KeyRequest: NewBasicKeyRequest(),
	}
}

// appendIf appends to a if s is not an empty string.
func appendIf(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}

// Name returns the PKIX name for the request.
func (cr *CertificateRequest) Name() pkix.Name {
	var name pkix.Name
	name.CommonName = cr.CN

	var uniqueIDs, pseudonyms, unstructuredNames []string
	for _, n := range cr.Names {
		appendIf(n.C, &name.Country)
		appendIf(n.ST, &name.Province)
		appendIf(n.L, &name.Locality)
		appendIf(n.O, &name.Organization)
		appendIf(n.OU, &name.OrganizationalUnit)

		// Additional fields
		appendIf(n.PC, &name.PostalCode)
		appendIf(n.SA, &name.StreetAddress)
		appendIf(n.UniqueIdentifier, &uniqueIDs)
		appendIf(n.Pseudonym, &pseudonyms)
		appendIf(n.UnstructuredName, &unstructuredNames)
	}
	name.SerialNumber = cr.SerialNumber

	// Add extraName values if required
	if len(uniqueIDs) != 0 {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 45},
			Value: strings.Join(uniqueIDs, "/"),
		})
	}
	if len(pseudonyms) != 0 {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{2, 5, 4, 65},
			Value: strings.Join(pseudonyms, "/"),
		})
	}
	if len(unstructuredNames) != 0 {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 2},
			Value: strings.Join(unstructuredNames, "/"),
		})
	}
	return name
}

// ParseRequest takes a certificate request and generates a key and
// CSR from it. It does no validation -- caveat emptor. It will,
// however, fail if the key request is not valid (i.e., an unsupported
// curve or RSA key size). The lack of validation was specifically
// chosen to allow the end user to define a policy and validate the
// request appropriately before calling this function.
func ParseRequest(req *CertificateRequest) (csr, key []byte, err error) {
	log.Info("received CSR")
	if req.KeyRequest == nil {
		req.KeyRequest = NewBasicKeyRequest()
	}

	log.Infof("generating key: %s-%d", req.KeyRequest.Algo(), req.KeyRequest.Size())
	priv, err := req.KeyRequest.Generate()
	if err != nil {
		err = cferr.Wrap(cferr.PrivateKeyError, cferr.GenerationFailed, err)
		return
	}

	switch priv := priv.(type) {
	case *rsa.PrivateKey:
		key = x509.MarshalPKCS1PrivateKey(priv)
		block := pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	case *ecdsa.PrivateKey:
		key, err = x509.MarshalECPrivateKey(priv)
		if err != nil {
			err = cferr.Wrap(cferr.PrivateKeyError, cferr.Unknown, err)
			return
		}
		block := pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: key,
		}
		key = pem.EncodeToMemory(&block)
	default:
		panic("Generate should have failed to produce a valid key.")
	}

	csr, err = Generate(priv.(crypto.Signer), req)
	if err != nil {
		log.Errorf("failed to generate a CSR: %v", err)
		err = cferr.Wrap(cferr.CSRError, cferr.BadRequest, err)
	}
	return
}

// ExtractCertificateRequest extracts a CertificateRequest from
// x509.Certificate. It is aimed to used for generating a new certificate
// from an existing certificate. For a root certificate, the CA expiry
// length is calculated as the duration between cert.NotAfter and cert.NotBefore.
func ExtractCertificateRequest(cert *x509.Certificate) *CertificateRequest {
	req := New()
	req.CN = cert.Subject.CommonName
	req.Names = getNames(cert.Subject)
	req.Hosts = getHosts(cert)
	req.SerialNumber = cert.Subject.SerialNumber

	// Keep certificate extensions
	for _, e := range cert.Extensions {
		req.Extensions = append(req.Extensions, Extension{
			Id:       e.Id.String(),
			Critical: e.Critical,
			Value:    e.Value,
		})
	}

	if cert.IsCA {
		req.CA = new(CAConfig)
		// CA expiry length is calculated based on the input cert
		// issue date and expiry date.
		req.CA.Expiry = cert.NotAfter.Sub(cert.NotBefore).String()
		req.CA.PathLength = cert.MaxPathLen
		req.CA.PathLenZero = cert.MaxPathLenZero
	}

	return req
}

func getHosts(cert *x509.Certificate) []string {
	var hosts []string
	for _, ip := range cert.IPAddresses {
		hosts = append(hosts, ip.String())
	}
	for _, dns := range cert.DNSNames {
		hosts = append(hosts, dns)
	}
	for _, email := range cert.EmailAddresses {
		hosts = append(hosts, email)
	}

	return hosts
}

// getNames returns an array of Names from the certificate
// It cares about:
//   Country
//   Organization
//   OrganizationalUnit
//   Locality
//   Province
//   PostalCode
//   StreetAddress
func getNames(sub pkix.Name) []Name {
	// anonymous func for finding the max of a list of integers
	max := func(v1 int, vn ...int) (max int) {
		max = v1
		for i := 0; i < len(vn); i++ {
			if vn[i] > max {
				max = vn[i]
			}
		}
		return max
	}

	nc := len(sub.Country)
	norg := len(sub.Organization)
	nou := len(sub.OrganizationalUnit)
	nl := len(sub.Locality)
	np := len(sub.Province)
	npc := len(sub.PostalCode)
	nst := len(sub.StreetAddress)

	n := max(nc, norg, nou, nl, np, npc, nst)

	names := make([]Name, n)
	for i := range names {
		if i < nc {
			names[i].C = sub.Country[i]
		}
		if i < norg {
			names[i].O = sub.Organization[i]
		}
		if i < nou {
			names[i].OU = sub.OrganizationalUnit[i]
		}
		if i < nl {
			names[i].L = sub.Locality[i]
		}
		if i < np {
			names[i].ST = sub.Province[i]
		}
		if i < npc {
			names[i].PC = sub.PostalCode[i]
		}
		if i < nst {
			names[i].SA = sub.StreetAddress[i]
		}
	}
	return names
}

// IsNameEmpty returns true if the name has no identifying information in it.
func IsNameEmpty(n Name) bool {
	empty := func(s string) bool { return strings.TrimSpace(s) == "" }

	if empty(n.C) && empty(n.ST) && empty(n.L) && empty(n.O) && empty(n.OU) {
		return true
	}
	return false
}

// Regenerate uses the provided CSR as a template for signing a new
// CSR using priv.
func Regenerate(priv crypto.Signer, csr []byte) ([]byte, error) {
	req, extra, err := helpers.ParseCSR(csr)
	if err != nil {
		return nil, err
	} else if len(extra) > 0 {
		return nil, errors.New("csr: trailing data in certificate request")
	}

	return x509.CreateCertificateRequest(rand.Reader, req, priv)
}

// Generate creates a new CSR from a CertificateRequest structure and
// an existing key. The KeyRequest field is ignored.
func Generate(priv crypto.Signer, req *CertificateRequest) (csr []byte, err error) {
	sigAlgo := helpers.SignerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
	}

	var tpl = x509.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			err = cferr.Wrap(cferr.CSRError, cferr.GenerationFailed, err)
			return
		}
	}

	if req.Extensions != nil {
		for _, e := range req.Extensions {
			if pe, err := e.toPKIX(); err == nil {
				tpl.ExtraExtensions = append(tpl.ExtraExtensions, pe)
			}
		}
	}

	csr, err = x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		log.Errorf("failed to generate a CSR: %v", err)
		err = cferr.Wrap(cferr.CSRError, cferr.BadRequest, err)
		return
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	log.Info("encoded CSR")
	csr = pem.EncodeToMemory(&block)
	return
}
