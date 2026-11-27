package policy

import (
 "testing"
 "time"
)
func TestHistoryKnowledgeAndExpiry(t *testing.T){
 s,d,at:=sample(t)
 fp:=d.Policy.TrustAnchors[0]
 later:=at.Add(time.Hour);end:=later.Add(time.Hour)
 v:=d.Decisions[0]
 v.ID="suspend";v.Status=Suspended;v.RecordedAt=later;v.EffectiveFrom=later;v.EffectiveUntil=&end;v.EvidenceIDs=[]string{}
 d.Decisions=append(d.Decisions,v)
 before,err:=d.History(s,fp,at,at);if err!=nil||len(before.Decisions)!=1||before.Current.Status!=Trusted{t.Fatalf("past %+v %v",before,err)}
 scheduled,err:=d.History(s,fp,at,later);if err!=nil||len(scheduled.Decisions)!=2||scheduled.Decisions[1].TemporalStatus!="SCHEDULED"{t.Fatalf("scheduled %+v %v",scheduled,err)}
 current,err:=d.History(s,fp,later,later);if err!=nil||current.Current.Status!=Suspended||current.Decisions[0].TemporalStatus!="SUPERSEDED"||current.Decisions[1].TemporalStatus!="LATEST_APPLICABLE"{t.Fatalf("current %+v %v",current,err)}
 expired,err:=d.History(s,fp,end,end);if err!=nil||expired.Current.Status!=Unknown||expired.Decisions[1].TemporalStatus!="LATEST_EXPIRED"||expired.ReleaseAuthenticated||expired.TrustStatus!=Unknown{t.Fatalf("expired %+v %v",expired,err)}
 // Review history is visible only by its recording cutoff.
 review:=d.Reviews[0];review.ID="reject";review.Status="REVIEW_REJECTED";review.RecordedAt=later
 d.Reviews=append(d.Reviews,review)
 r,err:=d.History(s,fp,at,later);if err!=nil||r.Current.Status!=Unknown||len(r.Reviews)!=2||r.Reviews[0].KnowledgeStatus!="SUPERSEDED"||r.Reviews[1].KnowledgeStatus!="LATEST_AS_KNOWN"{t.Fatalf("review history %+v %v",r,err)}
 if _,err:=d.History(s,fp,later,at);err==nil{t.Fatal("invalid cutoff")}
}
