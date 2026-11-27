package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"

 "github.com/M78U/trust-registry/pkg/sources"
)
func runMultiCA(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "multi-ca":
  authority:=f.String("authority","","CFCA, BJCA or GDCA")
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=0{return errors.New("usage: sources multi-ca [--authority CFCA|BJCA|GDCA]")}
  c,err:=sources.MultiCA();if err!=nil{return err}
  c,err=c.Filter(*authority);if err!=nil{return err}
  return enc.Encode(c)
 case "multi-ca-audit":
  id:=f.String("id","","exact research listing ID")
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=1||*id==""{return errors.New("usage: sources multi-ca-audit --id ID FILE")}
  raw,err:=readInput(f.Arg(0));if err!=nil{return err}
  result,err:=sources.AuditMultiCA(*id,raw);if err!=nil{return err}
  return enc.Encode(result)
 default:return errors.New("unknown multi-CA operation")
 }
}
