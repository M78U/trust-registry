package main

import(
 "encoding/json"
 "errors"
 "flag"
 "io"
 "os"
 "path/filepath"
 "sort"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/sources"
)
func runBundle(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
 switch args[0]{
 case "bundle-plan":
  id:=f.String("id","","observed chain listing ID")
  at:=f.String("recorded-at","","asserted observation time RFC3339")
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=1||*id==""||*at==""{return errors.New("id, recorded-at and bundle file required")}
  t,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
  raw,err:=readSmall(f.Arg(0),registry.MaxCertificateBundleBytes);if err!=nil{return err}
  p,err:=sources.PlanBundle(*id,raw,t.UTC());if err!=nil{return err}
  b,err:=sources.BundlePlanBytes(p);if err!=nil{return err}
  _,err=out.Write(b);return err
 case "bundle-export":
  plan:=f.String("plan","","reviewed plan file")
  pin:=f.String("plan-sha256","","independently retained plan hash")
  dest:=f.String("out","","new private archive directory")
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=1||*plan==""||*pin==""||*dest==""{return errors.New("plan, pin, new directory and original bundle required")}
  raw,err:=readSmall(f.Arg(0),registry.MaxCertificateBundleBytes);if err!=nil{return err}
  pb,err:=readSmall(*plan,sources.MaxBundlePlanBytes);if err!=nil{return err}
  files,err:=sources.BundleArchiveFiles(raw,pb,*pin);if err!=nil{return err}
  if err:=os.Mkdir(*dest,0700);err!=nil{return err}
  names:=[]string{};for name:=range files{names=append(names,name)};sort.Strings(names)
  for _,name:=range names{if err:=writeNew(filepath.Join(*dest,name),files[name]);err!=nil{return err}}
  return json.NewEncoder(out).Encode(map[string]any{"status":"PRIVATE_BUNDLE_ARCHIVE_CREATED","planSHA256":*pin,"files":len(files),"trustStatus":"NOT_ESTABLISHED"})
 case "bundle-apply":
  dir:=f.String("archive","","private verified bundle archive")
  root:=f.String("registry","","initialized local registry")
  pin:=f.String("plan-sha256","","independent exact plan hash")
  var selected []string
  f.Func("certificate-sha256","explicit matching DER digest, repeatable",func(v string)error{if v==""||len(selected)>=registry.MaxCertificateBundleMembers{return errors.New("invalid selection")};selected=append(selected,v);return nil})
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=0||*dir==""||*root==""||*pin==""||len(selected)==0{return errors.New("archive, registry, plan pin and explicit member selection required")}
  s,err:=registry.OpenStore(*root);if err!=nil{return err}
  report,err:=sources.ApplyBundleArchive(s,*dir,*pin,selected)
  if report.PlanSHA256!=""{if e:=json.NewEncoder(out).Encode(report);e!=nil{return e}}
  return err
 default:return errors.New("unknown bundle command")
 }
}
