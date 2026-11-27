package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
)
func runReviewWorkspace(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("review "+args[0],flag.ContinueOnError)
 evidence:=f.String("evidence","","existing private evidence directory")
 enc:=json.NewEncoder(out)
 if args[0]=="evidence-add"{
  if err:=f.Parse(args[1:]);err!=nil{return err}
  if f.NArg()!=1||*evidence==""{return errors.New("evidence directory and one local artifact file required")}
  raw,err:=readSmall(f.Arg(0),review.MaxArtifactBytes);if err!=nil{return err}
  h,err:=review.EvidenceArtifact(*evidence,raw);if err!=nil{return err}
  return enc.Encode(map[string]any{"sha256":h,"fileName":h+".evidence","status":"PRIVATE_ARTIFACT_BYTES_STAGED","trustStatus":"NOT_ESTABLISHED"})
 }
 dossier:=f.String("dossier","","existing exact snapshot review dossier")
 pin:=f.String("snapshot-sha256","","independently retained snapshot SHA-256")
 at:=f.String("at","","explicit evaluation time RFC3339")
 dir:=f.String("archive","","private acquisition archive directory")
 var refs []review.ArchiveReference
 f.Func("archive-pin","listing-id=sha256 (repeatable)",func(v string)error{
  id,h,ok:=strings.Cut(v,"=")
  if !ok||id==""||h==""||len(refs)>=review.MaxWorkspaceArchives{return errors.New("invalid archive selection")}
  refs=append(refs,review.ArchiveReference{ListingID:id,SHA256:h});return nil
 })
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*evidence==""||*dossier==""||*pin==""||*at==""{return errors.New("snapshot, snapshot pin, dossier, evidence directory and time required")}
 when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
 raw,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 db,err:=readSmall(*dossier,review.MaxDossierBytes);if err!=nil{return err}
 d,err:=review.DecodeDossier(db);if err!=nil{return err}
 report,err:=review.Workspace(raw,d,review.WorkspaceOptions{SnapshotSHA256:*pin,EvidenceDir:*evidence,ArchiveDir:*dir,Archives:refs,At:when.UTC()})
 if err!=nil{return err}
 return enc.Encode(report)
}
