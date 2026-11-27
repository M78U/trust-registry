package main

import (
 "encoding/json"
 "errors"
 "flag"
 "os"
 "path/filepath"
 "sort"

 tuf "github.com/M78U/trust-registry/tools/tuf-client"
)

func exportLedger(f *flag.FlagSet,args []string,out *string)error{
 dir:=f.String("ledger","","private publication ledger")
 root:=f.String("root-sha256","","independent initial v1 root pin")
 authority:=f.String("authority-sha256","","independent authority pin")
 expected:=f.String("expected-head","","optional independently retained record pin")
 now:=f.String("now","","current RFC3339 time")
 if err:=f.Parse(args);err!=nil{return err}
 if f.NArg()!=0||*out==""||*dir==""||*root==""||*authority==""||*now==""{return errors.New("ledger, root and authority pins, now and new output directory required")}
 at,err:=instant(*now);if err!=nil{return err}
 repo,receipt,err:=tuf.ExportLedgerHead(*dir,*root,*authority,*expected,at);if err!=nil{return err}
 if err:=os.Mkdir(*out,0700);err!=nil{return err}
 for _,sub:=range []string{"metadata","targets"}{if err:=os.Mkdir(filepath.Join(*out,sub),0700);err!=nil{return err}}
 names:=[]string{};for name:=range repo.Files{names=append(names,name)};sort.Strings(names)
 for _,name:=range names{if err:=writeNew(filepath.Join(*out,filepath.FromSlash(name)),repo.Files[name]);err!=nil{return err}}
 return json.NewEncoder(os.Stdout).Encode(receipt)
}
