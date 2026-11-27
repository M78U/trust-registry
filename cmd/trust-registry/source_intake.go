package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/sources"
)

func runSourceIntake(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
 dir:=f.String("dir","","local candidate directory containing ID.cer files")
 if args[0]=="intake-plan"{
  var ids []string
  f.Func("id","selected observed listing ID (repeatable)",func(v string)error{
   if v==""||len(ids)>=sources.MaxIntakeItems{return errors.New("invalid listing ID or batch limit")}
   ids=append(ids,v);return nil
  })
  at:=f.String("recorded-at","","asserted observation time RFC3339")
  legacy:=f.Bool("allow-legacy-only",false,"allow endpoints with no SHA-256 lead")
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=0||*dir==""||*at==""||len(ids)==0{return errors.New("dir, recorded-at and one or more id flags required")}
  t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
  plan,err:=sources.PlanIntake(*dir,ids,t.UTC(),*legacy);if err!=nil{return err}
  raw,err:=sources.IntakePlanBytes(plan);if err!=nil{return err}
  _,err=out.Write(raw);return err
 }
 root:=f.String("registry","","explicit initialized local candidate inventory")
 pin:=f.String("plan-sha256","","independently retained exact plan digest")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*dir==""||*root==""||*pin==""{return errors.New("dir, registry, plan-sha256 and plan file required")}
 raw,err:=readSmall(f.Arg(0),sources.MaxIntakePlanBytes);if err!=nil{return err}
 s,err:=registry.OpenStore(*root);if err!=nil{return err}
 report,err:=sources.ApplyIntake(s,*dir,raw,*pin)
 if report.PlanSHA256!=""{
  if encodeErr:=json.NewEncoder(out).Encode(report);encodeErr!=nil{return encodeErr}
 }
 return err
}
