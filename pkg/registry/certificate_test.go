package registry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func syntheticCA(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{CommonName: "Synthetic Test CA - Not Trusted"},
		NotBefore: now, NotAfter: now.AddDate(1,0,0),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil { t.Fatal(err) }
	return der
}

func TestParseDERPEM(t *testing.T) {
	der := syntheticCA(t)
	p := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	a, owned, err := ParseCertificate(der)
	if err != nil { t.Fatal(err) }
	b, decoded, err := ParseCertificate(p)
	if err != nil { t.Fatal(err) }
	if a != b || !bytes.Equal(decoded, der) || a.FingerprintSHA256 != digest(der) || a.CertificateType != "CA_CANDIDATE" || !a.IsCA {
		t.Fatal("DER and PEM identity mismatch or wrong classification")
	}
	owned[0] ^= 1
	if bytes.Equal(owned, der) { t.Fatal("DER must be independently owned") }
}

func TestRejectInvalidInput(t *testing.T) {
	der := syntheticCA(t)
	p := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	for _, input := range [][]byte{nil, []byte("garbage"), make([]byte, MaxCertificateInput+1), append(bytes.Clone(der),0), append(bytes.Clone(p),p...), append([]byte("prefix\n"),p...), pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:der})} {
		if _,_,err := ParseCertificate(input); err == nil { t.Fatal("invalid input accepted") }
	}
}

func TestImportCandidate(t *testing.T) {
	der := syntheticCA(t)
	p := pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der})
	now := time.Date(2026,1,1,0,0,0,0,time.UTC)
	record, source, _, err := ImportCandidate(p, "https://example.org/ca", now)
	if err != nil { t.Fatal(err) }
	if source.ReviewStatus != "CANDIDATE" || source.RedistributionStatus != "NOT_REVIEWED" || source.CertificateSHA256 != record.FingerprintSHA256 || source.SourceFileSHA256 != digest(p) || source.RecordedAt != now {
		t.Fatal("incorrect candidate metadata")
	}
	for _, u := range []string{"", "file:///tmp/ca", "http://example.org", "https://user@example.org/ca", "https://example.org/#fragment"} {
		if _,_,_,err := ImportCandidate(p,u,now); err == nil { t.Fatal("invalid source accepted") }
	}
}
