package csr

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Extension provides an easy to use representation for extensions included in
// CSR instance. The 'id' attribute can be specified like a simple string of the
// form '1.2.3.4.5', and the 'value' field like a regular string.
type Extension struct {
	Id       string `json:"id"`
	Critical bool   `json:"critical"`
	Value    string `json:"value"`
}

func (e *Extension) toPKIX() (ext pkix.Extension, err error) {
	ext.Id, err = parseObjectIdentifier(e.Id)
	if err != nil {
		return
	}
	ext.Critical = e.Critical
	ext.Value = []byte(e.Value)
	return
}

func parseObjectIdentifier(oidString string) (oid asn1.ObjectIdentifier, err error) {
	validOID, err := regexp.MatchString("\\d(\\.\\d+)*", oidString)
	if err != nil {
		return
	}
	if !validOID {
		err = errors.New("invalid OID")
		return
	}

	segments := strings.Split(oidString, ".")
	oid = make(asn1.ObjectIdentifier, len(segments))
	for i, intString := range segments {
		oid[i], err = strconv.Atoi(intString)
		if err != nil {
			return
		}
	}
	return
}
