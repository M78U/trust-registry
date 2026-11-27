package main

import (
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
)
func runReviewReuse(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("review reuse-evidence",flag.ContinueOnError)
 previous:=f.String("previous","","previous snapshot")
 priorPin:=f.String("previous-sha256","","independent prior snapshot digest")
 dossier:=f.String("previous-dossier","","previous review dossier")
 dossierPin:=f.String("previous-dossier-sha256","","prior canonical dossier digest (workspace report)")
 nextPin:=f.String("snapshot-sha256","","independent next snapshot digest")
 evidence:=f.String("evidence","","private evidence directory")
 at:=f.String("at","","explicit evaluation time")
 dest:=f.String("out","","new pending dossier path")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*previous==""||*priorPin==""||*dossier==""||*dossierPin==""||*nextPin==""||*evidence==""||*at==""||*dest==""{return errors.New("previous and next snapshots/pins, previous dossier/pin, evidence, time and new output required")}
 when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err}
 oldRaw,err:=readSnapshot(*previous);if err!=nil{return err}
 nextRaw,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 db,err:=readSmall(*dossier,review.MaxDossierBytes);if err!=nil{return err}
 d,err:=review.DecodeDossier(db);if err!=nil{return err}
 next,report,err:=review.ReuseEvidence(oldRaw,nextRaw,d,review.ReuseOptions{PreviousSnapshotSHA256:*priorPin,PreviousDossierSHA256:*dossierPin,NextSnapshotSHA256:*nextPin,EvidenceDir:*evidence,At:when.UTC()})
 if err!=nil{return err}
 data,err:=review.DossierBytes(next);if err!=nil{return err}
 if err:=writeNew(*dest,data);err!=nil{return err}
 return json.NewEncoder(out).Encode(report)
}
