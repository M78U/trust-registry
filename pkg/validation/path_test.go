package validation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
)

func TestVerifyLocalPathAuthorization(t *testing.T){
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	root:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic local policy root"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,root,root,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	parent,err:=x509.ParseCertificate(der);if err!=nil{t.Fatal(err)}
	lk,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
	leaf:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic signer"},NotBefore:at,NotAfter:at.AddDate(0,1,0),KeyUsage:x509.KeyUsageDigitalSignature}
	raw,err:=x509.CreateCertificate(rand.Reader,leaf,parent,&lk.PublicKey,key);if err!=nil{t.Fatal(err)}
	s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
	imp,err:=s.Import(der,"https://example.org/ca",at);if err!=nil{t.Fatal(err)}
	d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{},Decisions:[]policy.Decision{}}
	fp:=imp.Certificate.FingerprintSHA256
	d.Policy.TrustAnchors=[]string{fp}
	check:=func(want string,when time.Time){
		t.Helper()
		report,err:=VerifyLocalPath(s,d,raw,d.Policy.Purpose,"",when,when)
		if err!=nil||report.Path.PathStatus!=want||report.TrustStatus!=policy.Unknown||report.BusinessPurposeStatus!=policy.Unknown||report.Path.ReleaseAuthenticated||report.Path.RevocationStatus!="NOT_CHECKED"{t.Fatalf("local path: %+v %v",report,err)}
	}
	check("NOT_ESTABLISHED",at)
	d.Reviews=append(d.Reviews,policy.Review{ID:"review-1",ProvenanceID:imp.ProvenanceID,CertificateSHA256:fp,Status:"PROVENANCE_VERIFIED",RecordedAt:at,Evidence:[]string{"synthetic"},ReviewReferences:[]string{"synthetic"}})
	d.Decisions=append(d.Decisions,policy.Decision{ID:"decision-1",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Trusted,RecordedAt:at,EffectiveFrom:at,Reason:"synthetic local approval",EvidenceIDs:[]string{"review-1"},ReviewReferences:[]string{"synthetic"}})
	check("VALID_UNDER_EXPLICIT_CA_SET",at)
	if _,err:=VerifyLocalPath(s,d,raw,"electronic-seal-signing","",at,at);err==nil{t.Fatal("cross-purpose policy accepted")}
	later:=at.Add(time.Hour)
	d.Decisions=append(d.Decisions,policy.Decision{ID:"decision-2",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Suspended,RecordedAt:later,EffectiveFrom:later,Reason:"synthetic suspension",EvidenceIDs:[]string{},ReviewReferences:[]string{"synthetic"}})
	check("NOT_ESTABLISHED",later)
	check("VALID_UNDER_EXPLICIT_CA_SET",at)
}
