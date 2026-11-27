package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/revocation"
 "github.com/M78U/trust-registry/pkg/snapshot"
)
func runPathImpact(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("snapshot path-impact",flag.ContinueOnError)
 previous:=f.String("previous","","previous snapshot")
 previousPin:=f.String("previous-sha256","","independent previous digest")
 nextPin:=f.String("snapshot-sha256","","independent next digest")
 cert:=f.String("certificate","","local end-entity certificate")
 id:=f.String("policy-id","","exact policy ID in both snapshots")
 version:=f.Int("policy-version",0,"exact policy version in both snapshots")
 purpose:=f.String("purpose","","explicit policy purpose")
 dns:=f.String("dns-name","","DNS name for server authentication only")
 at:=f.String("at","","evaluation time")
 known:=f.String("known-at","","knowledge time")
 evidence:=f.String("revocation-store","","optional shared private evidence directory")
 replacement:=f.String("next-revocation-store","","optional replacement evidence directory")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*previous==""||*previousPin==""||*nextPin==""||*cert==""||*id==""||*version<1||*purpose==""||*at==""||*known==""||*replacement!=""&&*evidence==""{return errors.New("both snapshots/pins, certificate, policy ID/version, purpose and cutoffs required; replacement requires baseline evidence")}
 t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
 k,err:=time.Parse(time.RFC3339Nano,*known);if err!=nil{return err}
 o:=snapshot.PathImpactOptions{PreviousSHA256:*previousPin,NextSHA256:*nextPin,PolicyID:*id,PolicyVersion:*version,Purpose:*purpose,DNSName:*dns,Point:snapshot.EvaluationPoint{At:t.UTC(),KnownAt:k.UTC()}}
 if *evidence!=""{o.Evidence,err=revocation.OpenEvidenceStore(*evidence);if err!=nil{return err}}
 if *replacement!=""{if *replacement==*evidence{o.NextEvidence=o.Evidence}else{o.NextEvidence,err=revocation.OpenEvidenceStore(*replacement);if err!=nil{return err}}}
 a,err:=readSnapshot(*previous);if err!=nil{return err}
 b,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 leaf,err:=readInput(*cert);if err!=nil{return err}
 report,err:=snapshot.ComparePath(a,b,leaf,o);if err!=nil{return err}
 return json.NewEncoder(out).Encode(report)
}
