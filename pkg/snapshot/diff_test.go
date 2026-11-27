package snapshot

import (
 "bytes"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "math/big"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
)
func TestPinnedDiffAndConsumerImpact(t *testing.T){
 s,docs,o:=fixture(t)
 previous,pr,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 rows,err:=s.List();if err!=nil||len(rows)!=1{t.Fatal(rows,err)}
 root:=rows[0].FingerprintSHA256
 rootDER,err:=s.ReadCertificateDER(root);if err!=nil{t.Fatal(err)}
 later:=o.CreatedAt.Add(time.Hour)
 if _,err:=s.Import(rootDER,"https://example.org/second-observation",later);err!=nil{t.Fatal(err)}
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 child:=&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic intermediate"},NotBefore:later,NotAfter:later.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 issuer:=*child;issuer.Subject=pkix.Name{CommonName:"Synthetic issuer"}
 der,err:=x509.CreateCertificate(rand.Reader,child,&issuer,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 imported,err:=s.Import(der,"https://example.org/intermediate",later);if err!=nil{t.Fatal(err)}
 d:=policy.Document{Policy:docs[0].Policy,Reviews:[]policy.Review{},Decisions:[]policy.Decision{}}
 d.Policy.Version++
 d.Policy.IntermediateCandidates=[]string{imported.Certificate.FingerprintSHA256}
 docs=append(docs,d)
 o.Sequence++;o.CreatedAt=later
 next,nr,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 opts:=DiffOptions{PreviousSHA256:pr.SnapshotSHA256,NextSHA256:nr.SnapshotSHA256,RequirePublicationTransition:true}
 v,err:=Compare(previous,next,opts)
 if err!=nil||len(v.CertificateChanges)!=2||len(v.PolicyChanges)!=1||len(v.Impact.AddedEligibleCandidates)!=1||v.Impact.AddedEligibleCandidates[0]!=imported.Certificate.FingerprintSHA256||v.Transition==nil||v.ReleaseAuthenticated||v.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(v,err)}
 if v.PolicyChanges[0].Change!="ADDED"||len(v.PolicyChanges[0].AddedIntermediateDeclarations)!=1{t.Fatal(v.PolicyChanges)}
 for _,c:=range v.CertificateChanges{if c.SHA256==root&&(c.Change!="PROVENANCE_CHANGED"||len(c.AddedProvenanceIDs)!=1||c.ConsumerEligibleAfter){t.Fatal(c)}}
 again,err:=Compare(previous,next,opts);if err!=nil{t.Fatal(err)}
 a,_:=canonical(v);b,_:=canonical(again);if !bytes.Equal(a,b){t.Fatal("nondeterministic diff")}
 opts.NextSHA256=strings.Repeat("0",64);if _,err:=Compare(previous,next,opts);err==nil{t.Fatal("wrong pin")}
 opts.NextSHA256=nr.SnapshotSHA256;if _,err:=Compare(previous,append(bytes.Clone(next),'\n'),opts);err==nil{t.Fatal("tampered snapshot")}
 opts.PreviousSHA256=nr.SnapshotSHA256;opts.NextSHA256=pr.SnapshotSHA256;if _,err:=Compare(next,previous,opts);err==nil{t.Fatal("backward sequence")}
}
func TestDiffDecisionDescriptors(t *testing.T){
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 d:=policy.Document{Decisions:[]policy.Decision{{ID:"event",CertificateSHA256:strings.Repeat("a",64),Status:policy.Suspended,RecordedAt:at,EffectiveFrom:at}}}
 _,before,err:=eventDescriptors(d);if err!=nil{t.Fatal(err)}
 d.Decisions[0].Status=policy.Distrusted
 _,after,err:=eventDescriptors(d);if err!=nil{t.Fatal(err)}
 budget:=1
 rows,err:=eventChanges(before,after,&budget)
 if err!=nil||len(rows)!=1||rows[0].Change!="MODIFIED"||rows[0].Before.Status!=policy.Suspended||rows[0].After.Status!=policy.Distrusted||budget!=0{t.Fatal(rows,err)}
 if _,err:=eventChanges(before,after,&budget);err==nil{t.Fatal("budget ignored")}
}
