package policy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

func sample(t *testing.T) (*registry.Store,Document,time.Time) {
	t.Helper()
	at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
	key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
	if err!=nil { t.Fatal(err) }
	c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic policy CA"},NotBefore:at,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
	der,err:=x509.CreateCertificate(rand.Reader,c,c,&key.PublicKey,key)
	if err!=nil { t.Fatal(err) }
	s,err:=registry.OpenStore(t.TempDir())
	if err!=nil { t.Fatal(err) }
	imp,err:=s.Import(der,"https://example.org/synthetic",at)
	if err!=nil { t.Fatal(err) }
	p:=Defaults()[0]
	fp:=imp.Certificate.FingerprintSHA256
	p.TrustAnchors=[]string{fp}
	r:=Review{"review-1",imp.ProvenanceID,fp,"PROVENANCE_VERIFIED",at,[]string{"synthetic evidence"},[]string{"synthetic review"}}
	v:=Decision{"decision-1",fp,p.ID,p.Version,"TRUST_ANCHOR",Trusted,at,at,nil,"synthetic local approval",[]string{r.ID},[]string{"synthetic review"}}
	return s,Document{p,[]Review{r},[]Decision{v}},at
}

func TestEmptyDefaults(t *testing.T) {
	at:=time.Now().UTC()
	for _,p:=range Defaults() {
		r,err:=(Document{p,[]Review{},[]Decision{}}).Evaluate(nil,at,at)
		if err!=nil || len(r.LocallyAuthorizedAnchors)!=0 || r.TrustStatus!=Unknown || r.ReleaseAuthenticated { t.Fatalf("empty policy: %+v %v",r,err) }
	}
}

func TestExplicitLocalAuthorization(t *testing.T) {
	s,d,at:=sample(t)
	r,err:=d.Evaluate(s,at,at)
	if err!=nil || len(r.LocallyAuthorizedAnchors)!=1 || r.TrustStatus!=Unknown || r.ReleaseAuthenticated { t.Fatalf("local approval: %+v %v",r,err) }
	d.Decisions=[]Decision{}
	r,err=d.Evaluate(s,at,at)
	if err!=nil || len(r.LocallyAuthorizedAnchors)!=0 { t.Fatalf("candidate promoted: %+v %v",r,err) }
}

func TestLifecycleAndKnowledgeTime(t *testing.T) {
	s,d,at:=sample(t)
	later:=at.Add(time.Hour)
	exp:=later.Add(time.Hour)
	v:=d.Decisions[0]
	v.ID="suspend";v.Status=Suspended;v.RecordedAt=later;v.EffectiveFrom=later;v.EffectiveUntil=&exp;v.EvidenceIDs=[]string{}
	d.Decisions=append(d.Decisions,v)
	for _,tc:=range []struct{at,known time.Time; status string}{{at,at,Trusted},{later,later,Suspended},{exp,exp,Unknown}} {
		r,err:=d.Evaluate(s,tc.at,tc.known)
		if err!=nil || r.AnchorEvaluations[0].Status!=tc.status { t.Fatalf("lifecycle: %+v %v",r,err) }
	}
	// A later-recorded retroactive distrust is excluded from an as-known-then
	// evaluation but included in a retrospective evaluation.
	v.ID="distrust";v.Status=Distrusted;v.EffectiveFrom=at.Add(time.Minute);v.RecordedAt=later;v.EffectiveUntil=nil
	d.Decisions=append(d.Decisions,v)
	check:=at.Add(2*time.Minute)
	a,err:=d.Evaluate(s,check,check)
	if err!=nil || a.AnchorEvaluations[0].Status!=Trusted { t.Fatalf("historical: %+v %v",a,err) }
	b,err:=d.Evaluate(s,check,later)
	if err!=nil || b.AnchorEvaluations[0].Status!=Distrusted { t.Fatalf("retrospective: %+v %v",b,err) }
}

func TestEvidenceRejection(t *testing.T) {
	s,d,at:=sample(t)
	r:=d.Reviews[0];r.ID="reject";r.Status="REVIEW_REJECTED";r.RecordedAt=at.Add(time.Hour)
	d.Reviews=append(d.Reviews,r)
	result,err:=d.Evaluate(s,r.RecordedAt,r.RecordedAt)
	if err!=nil || len(result.LocallyAuthorizedAnchors)!=0 || result.AnchorEvaluations[0].Status!=Unknown { t.Fatalf("rejected evidence: %+v %v",result,err) }
}

func TestRejectInvalidPolicy(t *testing.T) {
	for _,kind:=range []string{"scope","version","fallback","no-evidence","duplicate","conflict","wrong-review","backdate","role","future-review"} {
		t.Run(kind,func(t *testing.T){
			s,d,at:=sample(t)
			switch kind {
			case "scope": d.Decisions[0].PolicyID="cn.timestamping"
			case "version": d.Decisions[0].PolicyVersion++
			case "fallback": d.Policy.Constraints.AllowSystemTrustFallback=true
			case "no-evidence": d.Decisions[0].EvidenceIDs=[]string{}
			case "duplicate": d.Decisions=append(d.Decisions,d.Decisions[0])
			case "conflict": v:=d.Decisions[0];v.ID="conflict";d.Decisions=append(d.Decisions,v)
			case "wrong-review": d.Decisions[0].EvidenceIDs=[]string{"missing"}
			case "backdate": d.Decisions[0].EffectiveFrom=at.Add(-time.Minute)
			case "role": d.Policy.IntermediateCandidates=append(d.Policy.IntermediateCandidates,d.Policy.TrustAnchors[0])
			case "future-review": d.Reviews[0].RecordedAt=at.Add(time.Minute)
			}
			if _,err:=d.Evaluate(s,at,at);err==nil { t.Fatal("invalid policy accepted") }
		})
	}
}

func TestEvaluateAgainstSharedIndex(t *testing.T){
 s,d,at:=sample(t)
 i,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
 a,err:=d.Evaluate(s,at,at);if err!=nil{t.Fatal(err)}
 b,err:=d.EvaluateAgainst(i,at,at);if err!=nil||len(a.AnchorEvaluations)!=1||len(b.AnchorEvaluations)!=1||a.AnchorEvaluations[0]!=b.AnchorEvaluations[0]{t.Fatal(a,b,err)}
 if _,err:=d.EvaluateAgainst(nil,at,at);err==nil{t.Fatal("missing inventory accepted")}
 if _,err:=d.EvaluateAgainst(i,at,at.Add(-time.Second));err==nil{t.Fatal("bad cutoff")}
}
