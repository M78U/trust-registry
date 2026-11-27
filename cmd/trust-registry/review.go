package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
)
func runReview(args []string,out io.Writer)error{
 if len(args)==0{return errors.New("usage: review plan | check | prepare-approval | sign-task | approve-release | authenticate-approval")}
 switch args[0]{case "prepare-approval","sign-task","approve-release","authenticate-approval":return runReviewApproval(args,out)}
 flags:=flag.NewFlagSet("review "+args[0],flag.ContinueOnError)
 dossier:=flags.String("dossier","","local review dossier JSON")
 evidence:=flags.String("evidence","","private artifact directory")
 at:=flags.String("at","","explicit gate time RFC3339")
 if err:=flags.Parse(args[1:]);err!=nil{return err}
 if flags.NArg()!=1{return errors.New("one exact local snapshot required")}
 raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "plan":
  if *dossier!=""||*evidence!=""||*at!=""{return errors.New("plan takes only snapshot")}
  d,err:=review.Plan(raw);if err!=nil{return err}
  enc.SetIndent("","  ");return enc.Encode(d)
 case "check":
  if *dossier==""||*evidence==""||*at==""{return errors.New("dossier, evidence directory and at required")}
  t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
  b,err:=readRevocationFile(*dossier,review.MaxDossierBytes);if err!=nil{return err}
  d,err:=review.DecodeDossier(b);if err!=nil{return err}
  result,err:=review.Check(raw,d,*evidence,t.UTC());if err!=nil{return err}
  if err:=enc.Encode(result);err!=nil{return err}
  if result.Status!="LOCAL_REVIEW_REQUIREMENTS_SATISFIED"{return errors.New("review requirements blocked")}
  return nil
 default:return errors.New("unknown review command")
 }
}
