// Package registry implements candidate certificate inventory primitives.
// It does not establish certificate trust.
package registry

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

const MaxCertificateInput = 1 << 20

type CertificateRecord struct {
	SchemaVersion string `json:"schemaVersion"`
	FingerprintSHA256 string `json:"fingerprintSHA256"`
	CertificateType string `json:"certificateType"`
	PublicKeyAlgorithm string `json:"publicKeyAlgorithm"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	Subject string `json:"subject"`
	Issuer string `json:"issuer"`
	SerialNumber string `json:"serialNumber"`
	SubjectKeyIdentifier string `json:"subjectKeyIdentifier"`
	AuthorityKeyIdentifier string `json:"authorityKeyIdentifier"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter time.Time `json:"notAfter"`
	IsCA bool `json:"isCA"`
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseCertificate accepts exactly one certificate. It returns owned DER bytes.
// A self-issued or self-signed certificate is never classified as a trusted root.
func ParseCertificate(input []byte) (CertificateRecord, []byte, error) {
	if len(input) == 0 || len(input) > MaxCertificateInput {
		return CertificateRecord{}, nil, errors.New("invalid certificate input size")
	}
	der := input
	trimmed := bytes.TrimSpace(input)
	if bytes.HasPrefix(trimmed, []byte("-----BEGIN ")) {
		// Reject a skipped malformed PEM block or extraneous leading content.
		if !bytes.HasPrefix(trimmed, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(trimmed, []byte("-----BEGIN ")) != 1 {
			return CertificateRecord{}, nil, errors.New("expected exactly one CERTIFICATE PEM block")
		}
		block, rest := pem.Decode(trimmed)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return CertificateRecord{}, nil, errors.New("invalid certificate PEM")
		}
		der = block.Bytes
	}
	cert, err := smx509.ParseCertificate(der)
	if err != nil {
		return CertificateRecord{}, nil, fmt.Errorf("parse X.509 certificate: %w", err)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 || !bytes.Equal(cert.Raw, der) {
		return CertificateRecord{}, nil, errors.New("invalid serial or trailing DER")
	}
	keyAlgorithm := cert.PublicKeyAlgorithm.String()
	sigAlgorithm := cert.SignatureAlgorithm.String()
	// Preserve v0.1 standard-library metadata for already supported certificates.
	if standard, err := x509.ParseCertificate(der); err == nil {
		if standard.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm { keyAlgorithm = standard.PublicKeyAlgorithm.String() }
		if standard.SignatureAlgorithm != x509.UnknownSignatureAlgorithm { sigAlgorithm = standard.SignatureAlgorithm.String() }
	}
	if sm2.IsSM2PublicKey(cert.PublicKey) { keyAlgorithm = "SM2" }
	if cert.SignatureAlgorithm == smx509.SM2WithSM3 { sigAlgorithm = "SM2WithSM3" }
	kind := "END_ENTITY"
	if cert.IsCA {
		kind = "CA_CANDIDATE"
	}
	return CertificateRecord{
		SchemaVersion: "1",
		FingerprintSHA256: digest(der),
		CertificateType: kind,
		PublicKeyAlgorithm: keyAlgorithm,
		SignatureAlgorithm: sigAlgorithm,
		Subject: cert.Subject.String(),
		Issuer: cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.Text(16),
		SubjectKeyIdentifier: hex.EncodeToString(cert.SubjectKeyId),
		AuthorityKeyIdentifier: hex.EncodeToString(cert.AuthorityKeyId),
		NotBefore: cert.NotBefore.UTC(),
		NotAfter: cert.NotAfter.UTC(),
		IsCA: cert.IsCA,
	}, bytes.Clone(der), nil
}
