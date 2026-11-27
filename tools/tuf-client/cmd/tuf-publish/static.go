package main

import (
 "encoding/json"
 "errors"
 "flag"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "time"

 tuf "github.com/M78U/trust-registry/tools/tuf-client"
)

func runStatic(command string,f *flag.FlagSet,args []string,out *string)error{
 now:=f.String("now","","explicit current RFC3339 time")
 if command=="static-check"{
  assets:=f.String("assets","","prepared static assets directory")
  manifest:=f.String("manifest","","manifest file outside asset directory")
  pin:=f.String("manifest-sha256","","independently retained manifest pin")
  if err:=f.Parse(args);err!=nil{return err}
  if f.NArg()!=0||*out!=""||*assets==""||*manifest==""||*pin==""||*now==""{return errors.New("static-check requires assets, manifest, pin and current time")}
  at,err:=instant(*now);if err!=nil{return err}
  raw,err:=read(*manifest,tuf.MaxStaticManifestBytes);if err!=nil{return err}
  m,err:=tuf.DecodeStaticManifest(raw,*pin);if err!=nil{return err}
  if err:=tuf.VerifyStaticDirectory(*assets,m,at);err!=nil{return err}
  return json.NewEncoder(os.Stdout).Encode(map[string]any{"status":"LOCAL_STATIC_BYTES_VERIFIED","manifestSHA256":*pin,"sequence":m.Sequence,"deployed":false})
 }
 ledger:=f.String("ledger","","private publication ledger")
 root:=f.String("root-sha256","","initial v1 root pin")
 authority:=f.String("authority","","independent authority file")
 authorityPin:=f.String("authority-sha256","","independent authority pin")
 head:=f.String("expected-head","","independently retained ledger head pin")
 explorer:=f.String("explorer","","fresh built Explorer directory")
 first:=f.Bool("first",false,"explicit first deployment")
 previous:=f.String("previous-manifest","","prior deployed manifest outside assets")
 previousPin:=f.String("previous-manifest-sha256","","independent prior manifest pin")
 manifestOut:=f.String("manifest-out","","new private manifest path outside output assets")
 if err:=f.Parse(args);err!=nil{return err}
 if f.NArg()!=0||*out==""||*manifestOut==""||*now==""||*ledger==""||*authority==""||*authorityPin==""||*head==""||*root==""||*explorer==""||*first&&(*previous!=""||*previousPin!="")||!*first&&(*previous==""||*previousPin==""){return errors.New("explicit ledger, pins, Explorer, new output and manifest paths, first or prior manifest required")}
 abs,err:=filepath.Abs(*out);if err!=nil{return err}
 manifestAbs,err:=filepath.Abs(*manifestOut);if err!=nil{return err}
 rel,err:=filepath.Rel(abs,manifestAbs);if err!=nil{return err}
 if rel!=".."&&!strings.HasPrefix(rel,".."+string(filepath.Separator)){return errors.New("manifest must be outside static assets")}
 if _,err:=os.Lstat(manifestAbs);err==nil{return errors.New("manifest output exists")}else if !os.IsNotExist(err){return err}
 at,err:=instant(*now);if err!=nil{return err}
 a,err:=tuf.LoadReviewAuthority(*authority,*authorityPin);if err!=nil{return err}
 var old []byte
 if !*first{old,err=read(*previous,tuf.MaxStaticManifestBytes);if err!=nil{return err}}
 files,plan,err:=tuf.PrepareStaticPublication(tuf.StaticOptions{LedgerDir:*ledger,InitialRootSHA256:*root,ExpectedHeadSHA256:*head,Authority:a,ExplorerDir:*explorer,At:at,First:*first,PreviousManifest:old,PreviousManifestSHA256:*previousPin});if err!=nil{return err}
 if err:=os.Mkdir(abs,0700);err!=nil{return err}
 names:=[]string{};for name:=range files{if name!="tuf/metadata/timestamp.json"{names=append(names,name)}};sort.Strings(names);names=append(names,"tuf/metadata/timestamp.json")
 for _,name:=range names{path:=filepath.Join(abs,filepath.FromSlash(name));if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return err};if err:=writeNew(path,files[name]);err!=nil{return err}}
 // Check actual wall time as well as the operator's explicit build time.
 if err:=tuf.VerifyStaticDirectory(abs,plan.Manifest,time.Now().UTC());err!=nil{return err}
 raw,err:=tuf.StaticManifestBytes(plan.Manifest);if err!=nil{return err}
 if err:=writeNew(manifestAbs,raw);err!=nil{return err}
 return json.NewEncoder(os.Stdout).Encode(plan)
}
