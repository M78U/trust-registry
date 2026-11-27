package registry

import (
 "testing"
 "time"
)

func TestLifecycleBoundaries(t *testing.T){
 s:=newTestStore(t)
 key:=graphKey(t)
 raw,_:=graphCert(t,100,"Lifecycle CA",true,key,key,nil)
 at:=time.Date(2026,1,1,0,0,0,0,time.UTC)
 if _,err:=s.Import(raw,"https://example.org/lifecycle",at);err!=nil{t.Fatal(err)}
 idx,err:=s.BuildIndex();if err!=nil{t.Fatal(err)}
 end:=at.AddDate(1,0,0)
 for _,tc:=range []struct{at time.Time;days int;want string}{
  {at.Add(-time.Nanosecond),30,ValidityNotYetValid},
  {at,30,ValidityCurrent},
  {end.AddDate(0,0,-30).Add(-time.Nanosecond),30,ValidityCurrent},
  {end.AddDate(0,0,-30),30,ValidityExpiring},
  {end,0,ValidityExpiring},
  {end.Add(time.Nanosecond),30,ValidityExpired},
 }{
  r,err:=idx.Lifecycle(LifecycleOptions{tc.at,tc.days})
  if err!=nil||len(r.Certificates)!=1||r.Certificates[0].ValidityStatus!=tc.want||r.Counts[tc.want]!=1||r.ReleaseAuthenticated||r.RevocationStatus!="NOT_CHECKED"||r.TrustStatus!="NOT_ESTABLISHED"{t.Fatalf("%+v %v",r,err)}
 }
 for _,o:=range []LifecycleOptions{{time.Time{},30},{at,-1},{at,366},{at.In(time.FixedZone("offset",0)),30}}{if _,err:=idx.Lifecycle(o);err==nil{t.Fatal("invalid options accepted")}}
 if got:=classifyValidity(CertificateRecord{NotBefore:end,NotAfter:at},LifecycleOptions{at,30});got!=ValidityInvalidInterval{t.Fatal(got)}
}
