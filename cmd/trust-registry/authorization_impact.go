package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
)
func runAuthorizationImpact(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("snapshot authorization-impact",flag.ContinueOnError)
 previous:=f.String("previous","","previous snapshot file")
 priorPin:=f.String("previous-sha256","","independently retained previous digest")
 nextPin:=f.String("snapshot-sha256","","independently retained next digest")
 at:=f.String("at","","evaluation time RFC3339")
 known:=f.String("known-at","","knowledge time RFC3339")
 baseAt:=f.String("baseline-at","","optional earlier evaluation time")
 baseKnown:=f.String("baseline-known-at","","optional earlier knowledge time")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*previous==""||*priorPin==""||*nextPin==""||*at==""||*known==""||(*baseAt=="")!=(*baseKnown==""){return errors.New("previous and next snapshots/pins, at and known-at required; baseline times must be paired")}
 point:=func(a,k string)(snapshot.EvaluationPoint,error){
  t,err:=time.Parse(time.RFC3339Nano,a);if err!=nil{return snapshot.EvaluationPoint{},err}
  v,err:=time.Parse(time.RFC3339Nano,k);if err!=nil{return snapshot.EvaluationPoint{},err}
  return snapshot.EvaluationPoint{At:t.UTC(),KnownAt:v.UTC()},nil
 }
 p,err:=point(*at,*known);if err!=nil{return err}
 o:=snapshot.AuthorizationImpactOptions{PreviousSHA256:*priorPin,NextSHA256:*nextPin,Point:p}
 if *baseAt!=""{v,err:=point(*baseAt,*baseKnown);if err!=nil{return err};o.Baseline=&v}
 a,err:=readSnapshot(*previous);if err!=nil{return err}
 b,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 result,err:=snapshot.CompareAuthorization(a,b,o);if err!=nil{return err}
 return json.NewEncoder(out).Encode(result)
}
