package registry

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestVerifyExplicitPath(t *testing.T){
	s:=newTestStore(t)
	at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
	ka,ki,kl:=graphKey(t),graphKey(t),graphKey(t)
	root,pr:=graphCert(t,1,"Root",true,ka,ka,nil)
	inter,pi:=graphCert(t,2,"Intermediate",true,ki,ka,pr)
	leaf,_:=graphCert(t,3,"Leaf",false,kl,ki,pi)
	for _,raw:=range [][]byte{root,inter}{if _,err:=s.Import(raw,"https://example.org/ca",at);err!=nil{t.Fatal(err)}}
	opts:=PathOptions{AnchorFingerprints:[]string{digest(root)},IntermediateFingerprints:[]string{digest(inter)},At:at,Profile:"signature"}
	r,err:=s.VerifyPath(leaf,opts)
	if err!=nil||r.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||r.TrustStatus!="NOT_ESTABLISHED"||r.UsageStatus!="GENERIC_SIGNING_KEY_USAGE_ONLY"||len(r.Chains)!=1||len(r.Chains[0])!=3{t.Fatalf("valid: %+v %v",r,err)}
	for _,kind:=range []string{"empty","missing","expired","wrong-usage","ca-leaf"}{
		o:=opts;raw:=leaf
		switch kind{
		case "empty":o.AnchorFingerprints=nil
		case "missing":o.IntermediateFingerprints=nil
		case "expired":o.At=at.AddDate(2,0,0)
		case "wrong-usage":o.Profile="timestamping"
		case "ca-leaf":raw=inter
		}
		got,err:=s.VerifyPath(raw,o);if err!=nil||got.PathStatus!="NOT_ESTABLISHED"||len(got.Chains)!=0{t.Fatalf("%s: %+v %v",kind,got,err)}
	}
	o:=opts;o.IntermediateFingerprints=[]string{digest(root)}
	if _,err:=s.VerifyPath(leaf,o);err==nil{t.Fatal("duplicate role accepted")}
	o=opts;o.At=time.Time{}
	if _,err:=s.VerifyPath(leaf,o);err==nil{t.Fatal("implicit clock accepted")}
}

func TestVerifySM2Path(t *testing.T){
	s:=newTestStore(t)
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=sm2.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	root:=&smx509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"SM2 CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:smx509.KeyUsageCertSign,SignatureAlgorithm:smx509.SM2WithSM3}
	raw,err:=smx509.CreateCertificate(rand.Reader,root,root,&key.PublicKey,key);if err!=nil{t.Fatal(err)}
	parent,err:=smx509.ParseCertificate(raw);if err!=nil{t.Fatal(err)}
	if _,err:=s.Import(raw,"https://example.org/ca",at);err!=nil{t.Fatal(err)}
	lk,err:=sm2.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
	leaf:=&smx509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"SM2 leaf"},NotBefore:at,NotAfter:at.AddDate(0,1,0),KeyUsage:smx509.KeyUsageDigitalSignature,SignatureAlgorithm:smx509.SM2WithSM3}
	der,err:=smx509.CreateCertificate(rand.Reader,leaf,parent,&lk.PublicKey,key);if err!=nil{t.Fatal(err)}
	r,err:=s.VerifyPath(der,PathOptions{AnchorFingerprints:[]string{digest(raw)},At:at,Profile:"signature"})
	if err!=nil||r.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("SM2: %+v %v",r,err)}
}

func TestVerifyPathLength(t *testing.T){
	s:=newTestStore(t)
	at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
	ka,ki,kl:=graphKey(t),graphKey(t),graphKey(t)
	root:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Zero path root"},NotBefore:at.Add(-time.Hour),NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign,MaxPathLen:0,MaxPathLenZero:true}
	raw,err:=x509.CreateCertificate(rand.Reader,root,root,&ka.PublicKey,ka);if err!=nil{t.Fatal(err)}
	pr,err:=x509.ParseCertificate(raw);if err!=nil{t.Fatal(err)}
	inter,pi:=graphCert(t,2,"Intermediate",true,ki,ka,pr)
	leaf,_:=graphCert(t,3,"Leaf",false,kl,ki,pi)
	for _,v:=range [][]byte{raw,inter}{if _,err:=s.Import(v,"https://example.org/ca",at);err!=nil{t.Fatal(err)}}
	r,err:=s.VerifyPath(leaf,PathOptions{AnchorFingerprints:[]string{digest(raw)},IntermediateFingerprints:[]string{digest(inter)},At:at,Profile:"signature"})
	if err!=nil||r.PathStatus!="NOT_ESTABLISHED"{t.Fatalf("path length: %+v %v",r,err)}
}
