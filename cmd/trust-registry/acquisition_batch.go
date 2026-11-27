package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/sources"
)

func runArchiveBatch(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
 dir:=f.String("archive","","existing private archive directory")
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "archive-fetch-batch":
  var ids []string
  f.Func("id","explicit SHA-256-backed listing ID (repeatable)",func(v string)error{
   if v==""||len(ids)>=sources.MaxArchiveBatch{return errors.New("invalid batch selection")}
   ids=append(ids,v);return nil
  })
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=0||*dir==""||len(ids)==0{return errors.New("archive directory and explicit listing IDs required")}
  ctx,cancel:=context.WithTimeout(context.Background(),5*time.Minute);defer cancel()
  r,err:=sources.AcquireArchivedBatch(ctx,*dir,ids)
  if r.Status!=""{if e:=enc.Encode(r);e!=nil{return e}}
  return err
 case "archive-import-batch":
  root:=f.String("registry","","initialized local candidate inventory")
  var refs []sources.AcquisitionArchiveReference
  f.Func("archive-pin","listing-id=independent-sha256 (repeatable)",func(v string)error{
   id,h,ok:=strings.Cut(v,"=")
   if !ok||id==""||h==""||len(refs)>=sources.MaxArchiveBatch{return errors.New("invalid archive selection")}
   refs=append(refs,sources.AcquisitionArchiveReference{ListingID:id,SHA256:h});return nil
  })
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=0||*dir==""||*root==""||len(refs)==0{return errors.New("archive directory, registry and explicit independent pins required")}
  s,err:=registry.OpenStore(*root);if err!=nil{return err}
  r,err:=sources.ImportArchivedBatch(s,*dir,refs)
  if r.Status!=""{if e:=enc.Encode(r);e!=nil{return e}}
  return err
 default:return errors.New("unknown archive batch operation")
 }
}
