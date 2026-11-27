package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "os"
 "time"

 "github.com/M78U/trust-registry/pkg/revocation"
)

func readRevocationFile(path string,limit int64)([]byte,error){
 i,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !i.Mode().IsRegular()||i.Size()>limit{return nil,errors.New("invalid evidence file")}
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 opened,err:=f.Stat();if err!=nil{return nil,err}
 if !opened.Mode().IsRegular()||!os.SameFile(i,opened){return nil,errors.New("evidence file changed")}
 data,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
 if int64(len(data))>limit{return nil,errors.New("evidence too large")}
 return data,nil
}
func runRevocation(args []string,out io.Writer)error{
 flags:=flag.NewFlagSet("revocation",flag.ContinueOnError)
 issuer:=flags.String("issuer","","explicit issuer certificate DER or PEM")
 crl:=flags.String("crl","","local DER or PEM CRL bundle")
 at:=flags.String("at","","evaluation time RFC3339")
 known:=flags.String("known-at","","signed evidence issuance cutoff RFC3339")
 var paths []string
 flags.Func("ocsp","local OCSP DER file (repeatable)",func(v string)error{if v==""||len(paths)>=revocation.MaxOCSPResponses{return errors.New("OCSP input limit")};paths=append(paths,v);return nil})
 if err:=flags.Parse(args);err!=nil{return err}
 if flags.NArg()!=1||*issuer==""||*at==""||*known==""||*crl==""&&len(paths)==0{return errors.New("usage: revocation --issuer CERT --at RFC3339 --known-at RFC3339 [--crl FILE] [--ocsp FILE] CERT")}
 t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
 k,err:=time.Parse(time.RFC3339Nano,*known);if err!=nil{return err}
 child,err:=readInput(flags.Arg(0));if err!=nil{return err}
 parent,err:=readInput(*issuer);if err!=nil{return err}
 var cs *revocation.CRLStore
 var osps *revocation.OCSPStore
 if *crl!=""{
  raw,err:=readRevocationFile(*crl,revocation.MaxEvidenceInput);if err!=nil{return err}
  cs,err=revocation.LoadCRLBytes(raw);if err!=nil{return err}
 }
 if len(paths)>0{
  inputs:=[][]byte{}
  for _,path:=range paths{b,err:=readRevocationFile(path,1<<20);if err!=nil{return err};inputs=append(inputs,b)}
  osps,err=revocation.LoadOCSPBytes(inputs);if err!=nil{return err}
 }
 report,err:=revocation.EvaluatePair(child,parent,cs,osps,revocation.Options{At:t.UTC(),KnownAt:k.UTC()});if err!=nil{return err}
 if err:=json.NewEncoder(out).Encode(report);err!=nil{return err}
 // This is an inspection command, not a certificate verification success.
 if report.Status=="REVOKED_IN_SUPPLIED_EVIDENCE"||report.Status=="CONFLICTING_SUPPLIED_EVIDENCE"||report.Status=="INCOMPLETE_SUPPLIED_EVIDENCE"{return errors.New("revocation evidence indicates risk or is incomplete")}
 return nil
}
