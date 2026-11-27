package snapshot

import (
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "math/big"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/revocation"
)

func TestPathImpactIsolatesEvidenceAndSnapshot(t *testing.T){
 at:=time.Date(2026,1,2,0,0,0,0,time.UTC)
 start:=at.Add(-time.Hour)
 key:=func()*ecdsa.PrivateKey{k,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)};return k}
 issue:=func(c,parent *x509.Certificate,k,signer *ecdsa.PrivateKey)([]byte,*x509.Certificate){
  t.Helper();if parent==nil{parent=c};raw,e:=x509.CreateCertificate(rand.Reader,c,parent,&k.PublicKey,signer);if e!=nil{t.Fatal(e)}
  parsed,e:=x509.ParseCertificate(raw);if e!=nil{t.Fatal(e)};return raw,parsed
 }
 rk,lk:=key(),key()
 root,rc:=issue(&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic root"},NotBefore:start,NotAfter:at.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign},nil,rk,rk)
 leaf,_:=issue(&x509.Certificate{SerialNumber:big.NewInt(2),Subject:pkix.Name{CommonName:"Synthetic signer"},NotBefore:start,NotAfter:at.AddDate(0,1,0),KeyUsage:x509.KeyUsageDigitalSignature},rc,lk,rk)
 s,e:=registry.OpenStore(t.TempDir());if e!=nil{t.Fatal(e)}
 imp,e:=s.Import(root,"https://example.org/root",start);if e!=nil{t.Fatal(e)}
 fp:=imp.Certificate.FingerprintSHA256
 d:=policy.Document{Policy:policy.Defaults()[0],Reviews:[]policy.Review{{ID:"review",ProvenanceID:imp.ProvenanceID,CertificateSHA256:fp,Status:"PROVENANCE_VERIFIED",RecordedAt:start,Evidence:[]string{"synthetic"},ReviewReferences:[]string{"synthetic"}}},Decisions:[]policy.Decision{}}
 d.Policy.TrustAnchors=[]string{fp}
 d.Decisions=append(d.Decisions,policy.Decision{ID:"allow",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Trusted,RecordedAt:start,EffectiveFrom:start,Reason:"synthetic",EvidenceIDs:[]string{"review"},ReviewReferences:[]string{"synthetic"}})
 o:=Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:start,ExpiresAt:at.AddDate(0,1,0)}
 old,pr,e:=Build(s,[]policy.Document{d},o);if e!=nil{t.Fatal(e)}
 o.Sequence++;o.CreatedAt=at
 next,nr,e:=Build(s,[]policy.Document{d},o);if e!=nil{t.Fatal(e)}
 makeStore:=func()*revocation.EvidenceStore{t.Helper();v,e:=revocation.OpenEvidenceStore(filepath.Join(t.TempDir(),"evidence"));if e!=nil{t.Fatal(e)};if e=v.Init();e!=nil{t.Fatal(e)};return v}
 base,replacement:=makeStore(),makeStore()
 crl,e:=x509.CreateRevocationList(rand.Reader,&x509.RevocationList{Number:big.NewInt(1),ThisUpdate:at.Add(-time.Minute),NextUpdate:at.Add(time.Hour),RevokedCertificateEntries:[]x509.RevocationListEntry{{SerialNumber:big.NewInt(2),RevocationTime:start,ReasonCode:1}}},rc,rk);if e!=nil{t.Fatal(e)}
 if _,e=replacement.Import("CRL",crl,at,"synthetic");e!=nil{t.Fatal(e)}
 opts:=PathImpactOptions{PreviousSHA256:pr.SnapshotSHA256,NextSHA256:nr.SnapshotSHA256,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Purpose:d.Policy.Purpose,Point:EvaluationPoint{At:at,KnownAt:at},Evidence:base,NextEvidence:replacement}
 report,e:=ComparePath(old,next,leaf,opts)
 if e!=nil||report.Previous.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||report.Next.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"||report.SnapshotImpact.PathChange!="PATH_STATUS_UNCHANGED"||report.SnapshotImpact.RevocationChanged||report.EvidenceImpact==nil||!report.EvidenceImpact.RevocationChanged||!report.EvidenceImpact.ObservationRecordsChanged||!report.EvidenceImpact.PairResultsChanged||report.NextWithReplacementEvidence.RevocationStatus!="REVOKED_IN_SUPPLIED_EVIDENCE"||report.TrustStatus!="NOT_ESTABLISHED"||report.ReleaseAuthenticated{t.Fatal(report,e)}
 d.Decisions=append(d.Decisions,policy.Decision{ID:"suspend",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Suspended,RecordedAt:at,EffectiveFrom:at,Reason:"synthetic suspension",EvidenceIDs:[]string{},ReviewReferences:[]string{"synthetic"}})
 next,nr,e=Build(s,[]policy.Document{d},o);if e!=nil{t.Fatal(e)}
 opts.NextSHA256=nr.SnapshotSHA256;opts.NextEvidence=nil
 report,e=ComparePath(old,next,leaf,opts)
 if e!=nil||report.SnapshotImpact.PathChange!="TECHNICAL_PATH_LOST"||len(report.SnapshotImpact.RemovedAuthorizedAnchors)!=1||len(report.SnapshotImpact.RemovedChains)!=1||report.Next.RevocationStatus!="NO_VALID_PATH"{t.Fatal(report,e)}
 opts.PolicyVersion++;if _,e:=ComparePath(old,next,leaf,opts);e==nil{t.Fatal("missing exact policy accepted")}
 opts.PolicyVersion--;opts.NextSHA256=strings.Repeat("0",64);if _,e:=ComparePath(old,next,leaf,opts);e==nil{t.Fatal("wrong pin")}
 opts.NextSHA256=nr.SnapshotSHA256;opts.Evidence=nil;opts.NextEvidence=replacement
 if _,e:=ComparePath(old,next,leaf,opts);e==nil{t.Fatal("replacement without baseline")}
}
