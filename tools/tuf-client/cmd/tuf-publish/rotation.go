package main

import (
 "encoding/json"
 "errors"
 "flag"
 "os"
 "strings"

 tuf "github.com/M78U/trust-registry/tools/tuf-client"
)
type rootPaths []string
func(p *rootPaths)String()string{return strings.Join(*p,",")}
func(p *rootPaths)Set(v string)error{if v==""||len(*p)>=tuf.MaxRootChain{return errors.New("invalid root chain path or count")};*p=append(*p,v);return nil}
func loadRootChain(p rootPaths)([][]byte,error){
 if len(p)==0||len(p)>tuf.MaxRootChain{return nil,errors.New("explicit ordered root chain required")}
 out:=[][]byte{};for _,path:=range p{b,err:=read(path,512000);if err!=nil{return nil,err};out=append(out,b)}
 return out,nil
}
func runRotation(command string,f *flag.FlagSet,args []string,out *string)error{
 var chainPaths rootPaths
 f.Var(&chainPaths,"root-chain","ordered versioned root files, repeatable")
 pin:=f.String("initial-root-sha256","","independent exact v1 pin")
 current:=f.String("current-root-sha256","","independent current root pin")
 now:=f.String("now","","current RFC3339")
 type roleFlags struct{pub paths;threshold *int}
 all:=map[string]*roleFlags{}
 var oldKeys,newKeys paths
 var expires string
 if command=="rotate-root"{
  f.StringVar(&expires,"expires","","next root expiry")
  f.Var(&oldKeys,"old-root-key","old root PKCS#8 signing keys (repeatable)")
  f.Var(&newKeys,"root-key","new root PKCS#8 signing keys (repeatable)")
  for _,role:=range []string{"root","targets","snapshot","timestamp"}{v:=&roleFlags{};f.Var(&v.pub,role+"-public","repeatable SPKI PEM");v.threshold=f.Int(role+"-threshold",1,"role threshold");all[role]=v}
 }
 if err:=f.Parse(args);err!=nil{return err}
 if f.NArg()!=0||*pin==""||*current==""||*now==""{return errors.New("root chain, both independent pins and current time required")}
 at,err:=instant(*now);if err!=nil{return err}
 chain,err:=loadRootChain(chainPaths);if err!=nil{return err}
 if command=="verify-root-chain"{
  if *out!=""{return errors.New("verify does not write output files")}
  report,err:=tuf.VerifyRootChain(chain,*pin,at);if err!=nil{return err}
  if report.CurrentRootSHA256!=*current{return errors.New("current root pin mismatch")}
  return json.NewEncoder(os.Stdout).Encode(report)
 }
 if *out==""||expires==""{return errors.New("new output file and expiry required")}
 exp,err:=instant(expires);if err!=nil{return err}
 o:=tuf.RotateRootOptions{Now:at,ExpectedCurrentSHA256:*current,Next:tuf.RootOptions{Expires:exp,Roles:map[string]tuf.RoleKeys{}}}
 for role,v:=range all{keys,err:=public(v.pub);if err!=nil{return err};o.Next.Roles[role]=tuf.RoleKeys{PublicKeys:keys,Threshold:*v.threshold}}
 o.OldSigners,err=private(oldKeys);if err!=nil{return err};defer wipe(o.OldSigners)
 o.Next.Signers,err=private(newKeys);if err!=nil{return err};defer wipe(o.Next.Signers)
 raw,report,err:=tuf.RotateRoot(chain,*pin,o);if err!=nil{return err}
 if err:=writeNew(*out,raw);err!=nil{return err}
 return json.NewEncoder(os.Stdout).Encode(report)
}
