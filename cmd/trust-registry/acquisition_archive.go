package main

import (
 "context"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/sources"
)

func runAcquisitionArchive(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("sources "+args[0],flag.ContinueOnError)
 dir:=f.String("archive","","existing private archive directory")
 id:=f.String("id","","observed listing ID")
 var legacy bool
 var pin,root,dest,recorded string
 if args[0]=="archive-fetch"{f.BoolVar(&legacy,"allow-legacy-only",false,"explicitly allow legacy-only observation")}else if args[0]=="archive-local"{f.StringVar(&recorded,"recorded-at","","explicit local observation time RFC3339")}else{f.StringVar(&pin,"archive-sha256","","independently retained archive digest")}
 if args[0]=="archive-import"{f.StringVar(&root,"registry","","initialized local candidate inventory")}
 if args[0]=="archive-original"{f.StringVar(&dest,"out","","new private original certificate file")}
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if args[0]=="archive-local"{
  if f.NArg()!=1||*dir==""||*id==""||recorded==""{return errors.New("archive, id, recorded-at and one original file required")}
  at,err:=time.Parse(time.RFC3339Nano,recorded);if err!=nil{return err}
  raw,err:=readSmall(f.Arg(0),registry.MaxCertificateInput);if err!=nil{return err}
  r,err:=sources.ArchiveLocalOriginal(*dir,*id,raw,at.UTC());if err!=nil{return err}
  return json.NewEncoder(out).Encode(r)
 }
 if f.NArg()!=0||*dir==""||*id==""||args[0]!="archive-fetch"&&pin==""{return errors.New("archive, id and independent archive pin (except fetch) required")}
 enc:=json.NewEncoder(out)
 switch args[0]{
 case "archive-fetch":
  r,err:=sources.AcquireArchived(context.Background(),*dir,*id,legacy);if err!=nil{return err}
  return enc.Encode(r)
 case "archive-inspect":
  r,report,err:=sources.InspectArchived(*dir,*id,pin);if err!=nil{return err}
  return enc.Encode(struct{Receipt sources.ArchiveReceipt `json:"receipt"`;Report sources.AcquisitionReport `json:"report"`}{r,report})
 case "archive-original":
  if dest==""{return errors.New("new output file required")}
  raw,err:=sources.ArchivedOriginal(*dir,*id,pin);if err!=nil{return err}
  if err:=writeNew(dest,raw);err!=nil{return err}
  return enc.Encode(map[string]any{"status":"PRIVATE_ORIGINAL_EXPORTED","archiveSHA256":pin,"trustStatus":"NOT_ESTABLISHED"})
 case "archive-import":
  if root==""{return errors.New("initialized registry required")}
  s,err:=registry.OpenStore(root);if err!=nil{return err}
  r,err:=sources.ImportArchived(s,*dir,*id,pin)
  if r.Receipt.ArchiveSHA256!=""{if e:=enc.Encode(r);e!=nil{return e}}
  return err
 default:return errors.New("unknown archive operation")
 }
}
