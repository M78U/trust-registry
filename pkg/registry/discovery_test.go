package registry

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestSM2ImportAndDiscovery(t *testing.T) {
	s:=newTestStore(t)
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	rootKey,err:=sm2.GenerateKey(rand.Reader)
	if err!=nil { t.Fatal(err) }
	root:=&smx509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic SM2 CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:smx509.KeyUsageCertSign,SignatureAlgorithm:smx509.SM2WithSM3}
	raw,err:=smx509.CreateCertificate(rand.Reader,root,root,&rootKey.PublicKey,rootKey)
	if err!=nil { t.Fatal(err) }
	parsed,err:=smx509.ParseCertificate(raw)
	if err!=nil { t.Fatal(err) }
	rec,der,err:=ParseCertificate(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:raw}))
	if err!=nil || !bytes.Equal(raw,der) || rec.PublicKeyAlgorithm!="SM2" || rec.SignatureAlgorithm!="SM2WithSM3" { t.Fatalf("SM2 metadata: %+v %v",rec,err) }
	if _,err:=s.Import(raw,"https://example.org/synthetic",at);err!=nil { t.Fatal(err) }
	leafKey,err:=sm2.GenerateKey(rand.Reader)
	if err!=nil { t.Fatal(err) }
	leaf:=&smx509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic leaf"},NotBefore:at,NotAfter:at.AddDate(0,1,0),SignatureAlgorithm:smx509.SM2WithSM3,KeyUsage:smx509.KeyUsageDigitalSignature}
	leafDER,err:=smx509.CreateCertificate(rand.Reader,leaf,parsed,&leafKey.PublicKey,rootKey)
	if err!=nil { t.Fatal(err) }
	result,err:=s.DiscoverIssuers(leafDER)
	if err!=nil || result.TrustStatus!="NOT_ESTABLISHED" || len(result.Candidates)!=1 || result.Candidates[0].DirectIssuerStatus!="MATCHED" { t.Fatalf("SM2 relationship: %+v %v",result,err) }
	if _,err:=s.Import(leafDER,"https://example.org/leaf",at);err==nil { t.Fatal("leaf persisted") }
	// Change the signature only; parsing remains valid, but relationship cannot match.
	bad:=bytes.Clone(leafDER)
	bad[len(bad)-1]^=1
	result,err=s.DiscoverIssuers(bad)
	if err!=nil || len(result.Candidates)!=1 || result.Candidates[0].SignatureStatus=="VERIFIED" || result.Candidates[0].DirectIssuerStatus=="MATCHED" { t.Fatalf("tampered signature accepted: %+v %v",result,err) }
}

func TestDiscoverySameNameWrongKey(t *testing.T) {
	s:=newTestStore(t)
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	rootKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	wrongKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	root:=&smx509.Certificate{SerialNumber:big.NewInt(10),Subject:pkix.Name{CommonName:"Same name"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:smx509.KeyUsageCertSign}
	a,err:=smx509.CreateCertificate(rand.Reader,root,root,&rootKey.PublicKey,rootKey)
	if err!=nil { t.Fatal(err) }
	root.SerialNumber=big.NewInt(11)
	b,err:=smx509.CreateCertificate(rand.Reader,root,root,&wrongKey.PublicKey,wrongKey)
	if err!=nil { t.Fatal(err) }
	for _,raw:=range [][]byte{a,b} { if _,err:=s.Import(raw,"https://example.org/synthetic",at);err!=nil { t.Fatal(err) } }
	parent,err:=smx509.ParseCertificate(a)
	if err!=nil { t.Fatal(err) }
	leaf:=&smx509.Certificate{SerialNumber:big.NewInt(12),Subject:pkix.Name{CommonName:"Leaf"},NotBefore:at,NotAfter:at.AddDate(0,1,0)}
	der,err:=smx509.CreateCertificate(rand.Reader,leaf,parent,&wrongKey.PublicKey,rootKey)
	if err!=nil { t.Fatal(err) }
	report,err:=s.DiscoverIssuers(der)
	if err!=nil || len(report.Candidates)!=2 || report.TrustStatus!="NOT_ESTABLISHED" { t.Fatalf("candidates: %+v %v",report,err) }
	for _,c:=range report.Candidates {
		if c.Certificate.FingerprintSHA256==digest(a) {
			if c.DirectIssuerStatus!="MATCHED" || c.SignatureStatus!="VERIFIED" { t.Fatal("actual issuer not matched") }
		} else if c.DirectIssuerStatus=="MATCHED" || c.SignatureStatus=="VERIFIED" { t.Fatal("same-name impostor accepted") }
	}
}
