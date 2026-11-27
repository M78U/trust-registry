package snapshot

import (
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
)

func TestAuthorizationImpactSeparatesTimeAndSnapshot(t *testing.T){
 s,docs,o:=fixture(t)
 rows,err:=s.List();if err!=nil||len(rows)!=1{t.Fatal(rows,err)}
 fp:=rows[0].FingerprintSHA256
 provenance,err:=s.Provenance(fp);if err!=nil||len(provenance)!=1{t.Fatal(provenance,err)}
 d:=&docs[0]
 d.Policy.TrustAnchors=[]string{fp}
 start:=o.CreatedAt
 end:=start.Add(2*time.Hour)
 d.Reviews=[]policy.Review{{ID:"review-1",ProvenanceID:provenance[0].ID,CertificateSHA256:fp,Status:"PROVENANCE_VERIFIED",RecordedAt:start,Evidence:[]string{"synthetic"},ReviewReferences:[]string{"review"}}}
 d.Decisions=[]policy.Decision{{ID:"allow",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Trusted,RecordedAt:start,EffectiveFrom:start,EffectiveUntil:&end,Reason:"private approval note",EvidenceIDs:[]string{"review-1"},ReviewReferences:[]string{"review"}}}
 old,pr,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 later:=start.Add(time.Hour)
 d.Decisions=append(d.Decisions,policy.Decision{ID:"distrust",CertificateSHA256:fp,PolicyID:d.Policy.ID,PolicyVersion:d.Policy.Version,Role:"TRUST_ANCHOR",Status:policy.Distrusted,RecordedAt:later,EffectiveFrom:later,Reason:"private restriction note",EvidenceIDs:[]string{},ReviewReferences:[]string{"review"}})
 o.Sequence++;o.CreatedAt=later
 next,nr,err:=Build(s,docs,o);if err!=nil{t.Fatal(err)}
 opts:=AuthorizationImpactOptions{PreviousSHA256:pr.SnapshotSHA256,NextSHA256:nr.SnapshotSHA256,Point:EvaluationPoint{At:later,KnownAt:later}}
 report,err:=CompareAuthorization(old,next,opts)
 if err!=nil||report.SnapshotImpact.AuthorizationLosses!=1||report.ReleaseAuthenticated||report.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(report,err)}
 change:=report.SnapshotImpact.Policies[0].Changes[0]
 if change.Before.Status!=policy.Trusted||change.After.Status!=policy.Distrusted||change.After.ReasonCode!="DISTRUST_APPLICABLE"{t.Fatal(change)}
 opts.Point=EvaluationPoint{At:end,KnownAt:end}
 opts.Baseline=&EvaluationPoint{At:start,KnownAt:start}
 report,err=CompareAuthorization(old,next,opts)
 if err!=nil||report.TimeImpact==nil||report.TimeImpact.AuthorizationLosses!=1||report.SnapshotImpact.AuthorizationLosses!=0{t.Fatal(report,err)}
 if report.TimeImpact.Policies[0].Changes[0].After.ReasonCode!="LATEST_DECISION_EXPIRED"{t.Fatal(report.TimeImpact)}
 raw,err:=canonical(report);if err!=nil||strings.Contains(string(raw),"private restriction note")||strings.Contains(string(raw),"private approval note"){t.Fatal("private reason exported",err)}
 opts.Baseline=nil;opts.Point=EvaluationPoint{At:start,KnownAt:start}
 report,err=CompareAuthorization(old,next,opts)
 if err!=nil||len(report.SnapshotImpact.Policies)!=0||report.SnapshotImpact.AfterSnapshotWindow!="KNOWLEDGE_TIME_BEFORE_SNAPSHOT_CREATION"{t.Fatal(report,err)}
 opts.NextSHA256=strings.Repeat("0",64)
 if _,err:=CompareAuthorization(old,next,opts);err==nil{t.Fatal("wrong pin")}
 opts.NextSHA256=nr.SnapshotSHA256;opts.Point=EvaluationPoint{At:later,KnownAt:start}
 if _,err:=CompareAuthorization(old,next,opts);err==nil{t.Fatal("invalid knowledge cutoff")}
}
func TestAuthorizationImpactScopeAndValidity(t *testing.T){
 key:=policyKey{"test",1}
 fp:=strings.Repeat("a",64)
 a:=evaluatedSnapshot{policies:map[policyKey]evaluatedPolicy{key:{scope:PolicyScope{"document-signing","CN"},anchors:map[string]AuthorizationState{fp:{Status:policy.Trusted,CertificateValidity:"WITHIN_VALIDITY"}},authorized:1}}}
 b:=evaluatedSnapshot{policies:map[policyKey]evaluatedPolicy{key:{scope:PolicyScope{"document-signing","CN"},anchors:map[string]AuthorizationState{fp:{Status:policy.Trusted,CertificateValidity:"EXPIRED"}},authorized:1}}}
 c:=authorizationComparison("test",a,b)
 if c.AuthorizationLosses!=0||c.Policies[0].Changes[0].Change!="CERTIFICATE_VALIDITY_CHANGED"{t.Fatal(c)}
 y:=b.policies[key];y.scope.Purpose="timestamping";b.policies[key]=y
 c=authorizationComparison("test",a,b)
 if !c.Policies[0].ScopeChanged||c.Policies[0].Changes[0].Change!="SCOPE_CHANGED"||c.AuthorizationGains!=0{t.Fatal(c)}
}
