package policy

import (
 "testing"
 "time"
)

func TestRestrictionBlocksScheduledApprovalAndRequiresFreshEvidence(t *testing.T){
 s,d,at:=sample(t)
 fp:=d.Policy.TrustAnchors[0]
 future:=d.Decisions[0];future.ID="future";future.RecordedAt=at.Add(time.Minute);future.EffectiveFrom=at.Add(3*time.Hour)
 d.Decisions=append(d.Decisions,future)
 start:=at.Add(time.Hour);end:=start.Add(time.Hour)
 next,rep,err:=ProposeRestriction(s,d,RestrictionOptions{ID:"incident",CertificateSHA256:fp,Status:Suspended,RecordedAt:start,EffectiveUntil:&end,Reason:"synthetic incident",ReviewReferences:[]string{"incident-1"}})
 if err!=nil||rep.AddedDecisions!=1||len(d.Decisions)!=2||rep.ReleaseAuthenticated{t.Fatalf("proposal %+v %v",rep,err)}
 for _,tc:=range []struct{at time.Time;want string}{{start,Suspended},{end,Unknown},{future.EffectiveFrom,Unknown}}{
  v,err:=next.Evaluate(s,tc.at,tc.at);if err!=nil||v.AnchorEvaluations[0].Status!=tc.want{t.Fatalf("state %+v %v",v,err)}
 }
 // The as-known-then result must remain unchanged.
 historical,err:=next.Evaluate(s,at,at);if err!=nil||historical.AnchorEvaluations[0].Status!=Trusted{t.Fatal(historical,err)}
 // Explicit new decision alone cannot reuse evidence from before restriction.
 reauth:=future;reauth.ID="restore";reauth.RecordedAt=at.Add(4*time.Hour);reauth.EffectiveFrom=reauth.RecordedAt
 next.Decisions=append(next.Decisions,reauth)
 v,err:=next.Evaluate(s,reauth.RecordedAt,reauth.RecordedAt);if err!=nil||v.AnchorEvaluations[0].Status!=Unknown{t.Fatal(v,err)}
 fresh:=next.Reviews[0];fresh.ID="fresh";fresh.RecordedAt=reauth.RecordedAt.Add(time.Minute)
 next.Reviews=append(next.Reviews,fresh)
 reauth.ID="restore-fresh";reauth.RecordedAt=fresh.RecordedAt;reauth.EffectiveFrom=fresh.RecordedAt;reauth.EvidenceIDs=[]string{fresh.ID}
 next.Decisions=append(next.Decisions,reauth)
 v,err=next.Evaluate(s,fresh.RecordedAt,fresh.RecordedAt);if err!=nil||v.AnchorEvaluations[0].Status!=Trusted||v.TrustStatus!=Unknown{t.Fatal(v,err)}
}

func TestCompareRevisionRejectsHistoryRewrite(t *testing.T){
 s,d,at:=sample(t)
 index,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
 for _,kind:=range []string{"delete","change","scope","recorded","positive","expiring-distrust"}{
  raw,err:=DocumentBytes(d);if err!=nil{t.Fatal(err)}
  next,err:=DecodeDocument(raw);if err!=nil{t.Fatal(err)}
  switch kind{
  case "delete":next.Decisions=[]Decision{}
  case "change":next.Decisions[0].Reason="rewritten"
  case "scope":next.Policy.Purpose="timestamping";next.Policy.ID="cn.timestamping";next.Decisions[0].PolicyID=next.Policy.ID
  case "recorded":v:=next.Decisions[0];v.ID="retro";v.Status=Distrusted;v.EffectiveFrom=at.Add(time.Minute);v.EvidenceIDs=[]string{};next.Decisions=append(next.Decisions,v)
  case "positive","expiring-distrust":
   status:=Trusted;if kind=="expiring-distrust"{status=Distrusted}
   until:=at.Add(2*time.Hour)
   if _,_,err:=ProposeRestriction(s,d,RestrictionOptions{ID:"bad",CertificateSHA256:d.Policy.TrustAnchors[0],Status:status,RecordedAt:at.Add(time.Hour),EffectiveUntil:&until,Reason:"bad",ReviewReferences:[]string{"review"}});err==nil{t.Fatal(kind)}
   continue
  }
  if _,err:=CompareRevision(index,d,next);err==nil{t.Fatalf("accepted %s",kind)}
 }
}
