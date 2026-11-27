package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/revocation"
)
func runRevocationStore(args []string,out io.Writer)error{
 if len(args)==0{return errors.New("usage: revocation-store init | import | list")}
 flags:=flag.NewFlagSet("revocation-store "+args[0],flag.ContinueOnError)
 dir:=flags.String("store","","private evidence directory")
 kind:=flags.String("kind","","CRL or OCSP (import only)")
 at:=flags.String("recorded-at","","asserted observation time RFC3339 (import only)")
 source:=flags.String("source","","local source label (import only)")
 if err:=flags.Parse(args[1:]);err!=nil{return err}
 if *dir==""{return errors.New("explicit --store required")}
 s,err:=revocation.OpenEvidenceStore(*dir);if err!=nil{return err}
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "init","list":
  if flags.NArg()!=0||*kind!=""||*at!=""||*source!=""{return errors.New("unexpected evidence store arguments")}
  if args[0]=="init"{if err:=s.Init();err!=nil{return err}}
  rows,err:=s.List();if err!=nil{return err}
  return enc.Encode(rows)
 case "import":
  if flags.NArg()!=1||*kind==""||*at==""||*source==""{return errors.New("kind, recorded-at, source and one evidence file required")}
  t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
  limit:=int64(revocation.MaxEvidenceInput);if *kind=="OCSP"{limit=1<<20}
  raw,err:=readRevocationFile(flags.Arg(0),limit);if err!=nil{return err}
  result,err:=s.Import(*kind,raw,t.UTC(),*source);if err!=nil{return err}
  return enc.Encode(result)
 default:return errors.New("unknown evidence store command")
 }
}
