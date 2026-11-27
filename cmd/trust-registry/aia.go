package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "os"
 "time"

 "github.com/M78U/trust-registry/pkg/aia"
 "github.com/M78U/trust-registry/pkg/registry"
)

func runAIA(args []string,out io.Writer)error{
 if len(args)==0{return errors.New("usage: aia inspect | fetch | audit | import")}
 flags:=flag.NewFlagSet("aia "+args[0],flag.ContinueOnError)
 source:=flags.String("url","","exact selected HTTPS caIssuers URL")
 candidate:=flags.String("candidate","","local candidate certificate")
 dest:=flags.String("out","","new local download file")
 root:=flags.String("registry","","explicit local candidate inventory")
 if err:=flags.Parse(args[1:]);err!=nil{return err}
 if flags.NArg()!=1{return errors.New("one local certificate required")}
 input,err:=readInput(flags.Arg(0));if err!=nil{return err}
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "inspect":
  if *source!=""||*candidate!=""||*dest!=""||*root!=""{return errors.New("inspect takes only certificate")}
  plan,err:=aia.Inspect(input);if err!=nil{return err};return enc.Encode(plan)
 case "fetch":
  if *source==""||*dest==""||*candidate!=""||*root!=""{return errors.New("fetch requires URL and new output file; no registry import")}
  if _,err:=os.Lstat(*dest);err==nil{return errors.New("output already exists")}else if !os.IsNotExist(err){return err}
  data,report,err:=aia.Fetch(context.Background(),input,*source);if err!=nil{return err}
  f,err:=os.OpenFile(*dest,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
  if _,err=f.Write(data);err==nil{err=f.Sync()}
  closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{_ = os.Remove(*dest);return err}
  return enc.Encode(report)
 case "audit","import":
  if *source==""||*candidate==""||*dest!=""||(args[0]=="import")!=(*root!=""){return errors.New("audit/import require URL and local candidate; import additionally requires registry")}
  raw,err:=readInput(*candidate);if err!=nil{return err}
  report,err:=aia.Audit(input,raw,*source);if err!=nil{return err}
  if args[0]=="audit"{
   if err:=enc.Encode(report);err!=nil{return err}
   if report.Candidate.DirectIssuerStatus!="MATCHED"{return errors.New("candidate issuer not matched")}
   return nil
  }
  if report.Candidate.DirectIssuerStatus!="MATCHED"{return errors.New("candidate issuer not matched")}
  s,err:=registry.OpenStore(*root);if err!=nil{return err}
  result,err:=s.Import(raw,*source,time.Now().UTC());if err!=nil{return err}
  return enc.Encode(struct{Audit aia.Report `json:"audit"`; Import registry.ImportResult `json:"import"`}{report,result})
 default:return errors.New("unknown AIA command")
 }
}
