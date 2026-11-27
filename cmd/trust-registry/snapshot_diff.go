package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"

 "github.com/M78U/trust-registry/pkg/snapshot"
)
func runSnapshotDiff(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("snapshot diff",flag.ContinueOnError)
 previous:=f.String("previous","","previous snapshot file")
 previousPin:=f.String("previous-sha256","","independent exact previous snapshot digest")
 nextPin:=f.String("snapshot-sha256","","independent exact next snapshot digest")
 strict:=f.Bool("require-transition",false,"also require adjacent append-only publication transition")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*previous==""||*previousPin==""||*nextPin==""{return errors.New("previous snapshot, both independent pins and next snapshot required")}
 a,err:=readSnapshot(*previous);if err!=nil{return err}
 b,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 v,err:=snapshot.Compare(a,b,snapshot.DiffOptions{PreviousSHA256:*previousPin,NextSHA256:*nextPin,RequirePublicationTransition:*strict});if err!=nil{return err}
 return json.NewEncoder(out).Encode(v)
}
