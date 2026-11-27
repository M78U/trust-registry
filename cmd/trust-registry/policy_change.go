package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/validation"
)

func runPolicyChange(args []string,out io.Writer)error{
 flags:=flag.NewFlagSet("policy "+args[0],flag.ContinueOnError)
 root:=flags.String("registry","registry","local inventory directory")
 switch args[0]{
 case "restrict":
  file:=flags.String("file","","existing local policy document")
  id:=flags.String("id","","new decision ID")
  fp:=flags.String("fingerprint","","declared anchor fingerprint")
  status:=flags.String("status","","SUSPENDED or DISTRUSTED")
  at:=flags.String("at","","explicit immediate restriction time RFC3339")
  until:=flags.String("until","","optional suspension end RFC3339")
  reason:=flags.String("reason","","reason for restriction")
  var refs []string
  flags.Func("review-ref","explicit audit reference (repeatable)",func(v string)error{if v==""||len(refs)>=policy.MaxRecords{return errors.New("invalid review reference")};refs=append(refs,v);return nil})
  if err:=flags.Parse(args[1:]);err!=nil{return err}
  if flags.NArg()!=0||*file==""||*id==""||*fp==""||*status==""||*at==""||*reason==""||len(refs)==0{return errors.New("file, id, fingerprint, status, at, reason and review-ref required")}
  t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
  o:=policy.RestrictionOptions{ID:*id,CertificateSHA256:*fp,Status:*status,RecordedAt:t.UTC(),Reason:*reason,ReviewReferences:refs}
  if *until!=""{u,err:=time.Parse(time.RFC3339Nano,*until);if err!=nil{return err};u=u.UTC();o.EffectiveUntil=&u}
  d,err:=policy.LoadDocument(*file);if err!=nil{return err}
  s,err:=registry.OpenStore(*root);if err!=nil{return err}
  next,_,err:=policy.ProposeRestriction(s,d,o);if err!=nil{return err}
  raw,err:=policy.DocumentBytes(next);if err!=nil{return err}
  // stdout is the proposed document only. Never overwrite input.
  _,err=out.Write(raw);return err
 case "check-transition":
  var before,after []string
  add:=func(dst *[]string)func(string)error{return func(v string)error{if v==""||len(*dst)>=validation.MaxPolicyDocuments{return errors.New("invalid policy file or limit")};*dst=append(*dst,v);return nil}}
  flags.Func("previous","complete prior policy set (repeatable)",add(&before))
  flags.Func("next","complete proposed policy set (repeatable)",add(&after))
  if err:=flags.Parse(args[1:]);err!=nil{return err}
  if flags.NArg()!=0||len(before)==0||len(after)==0{return errors.New("previous and next policy collections required")}
  load:=func(paths []string)([]policy.Document,error){
   docs:=make([]policy.Document,0,len(paths))
   for _,p:=range paths{d,err:=policy.LoadDocument(p);if err!=nil{return nil,err};docs=append(docs,d)}
   return docs,nil
  }
  old,err:=load(before);if err!=nil{return err}
  next,err:=load(after);if err!=nil{return err}
  s,err:=registry.OpenStore(*root);if err!=nil{return err}
  report,err:=validation.ValidateTransition(s,old,next);if err!=nil{return err}
  return json.NewEncoder(out).Encode(report)
 default:return errors.New("unknown policy change command")
 }
}
