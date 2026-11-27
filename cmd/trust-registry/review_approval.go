package main

import(
 "crypto/ed25519"
 "crypto/x509"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
)

func runReviewApproval(args []string,out io.Writer)error{
 flags:=flag.NewFlagSet("review "+args[0],flag.ContinueOnError)
 dossier:=flags.String("dossier","","completed private dossier")
 evidence:=flags.String("evidence","","private evidence directory")
 authority:=flags.String("authority","","independently provisioned public role configuration")
 pin:=flags.String("authority-sha256","","independent exact configuration file digest")
 at:=flags.String("at","","explicit current time RFC3339")
 approval:=flags.String("approval","","existing canonical approval file")
 dest:=flags.String("out","","new approval output file")
 until:=flags.String("until","","approval expiration RFC3339 (prepare only)")
 keyPath:=flags.String("key","","offline PKCS#8 Ed25519 private key")
 id:=flags.String("id","","task ID or release approver ID")
 if err:=flags.Parse(args[1:]);err!=nil{return err}
 if flags.NArg()!=1||*dossier==""||*evidence==""||*authority==""||*pin==""||*at==""{return errors.New("snapshot, dossier, evidence, authority, independent authority-sha256 and at required")}
 when,err:=time.Parse(time.RFC3339Nano,*at);if err!=nil{return err};when=when.UTC()
 raw,err:=readSnapshot(flags.Arg(0));if err!=nil{return err}
 db,err:=readSmall(*dossier,review.MaxDossierBytes);if err!=nil{return err}
 d,err:=review.DecodeDossier(db);if err!=nil{return err}
 ab,err:=readSmall(*authority,review.MaxAuthorityBytes);if err!=nil{return err}
 a,err:=review.ParseAuthority(ab,*pin);if err!=nil{return err}
 var v review.Approval
 if args[0]=="prepare-approval"{
  if *dest==""||*until==""||*approval!=""||*keyPath!=""||*id!=""{return errors.New("prepare requires out and until only")}
  end,err:=time.Parse(time.RFC3339Nano,*until);if err!=nil{return err}
  v,err=review.NewApproval(raw,d,*evidence,a,when,end.UTC());if err!=nil{return err}
 }else{
  if *approval==""||*until!=""{return errors.New("existing approval required; until is prepare-only")}
  data,err:=readSmall(*approval,review.MaxApprovalBytes);if err!=nil{return err}
  v,err=review.DecodeApproval(data);if err!=nil{return err}
  if args[0]=="authenticate-approval"{
   if *dest!=""||*keyPath!=""||*id!=""{return errors.New("authenticate does not accept signing options")}
   r,err:=review.Authenticate(raw,d,*evidence,a,v,when);if err!=nil{return err}
   return json.NewEncoder(out).Encode(r)
  }
  if *dest==""||*keyPath==""||*id==""{return errors.New("sign requires new out, key and id")}
  der,err:=readPEM(*keyPath,"PRIVATE KEY");if err!=nil{return err};defer clear(der)
  k,err:=x509.ParsePKCS8PrivateKey(der);if err!=nil{return err}
  key,ok:=k.(ed25519.PrivateKey);if !ok{return errors.New("Ed25519 required")};defer clear(key)
  switch args[0]{
  case "sign-task":v,err=review.SignReview(raw,d,*evidence,a,v,*id,key,when)
  case "approve-release":v,err=review.SignRelease(raw,d,*evidence,a,v,*id,key,when)
  default:return errors.New("unknown review approval command")
  }
  if err!=nil{return err}
 }
 data,err:=review.ApprovalBytes(v);if err!=nil{return err}
 if err:=writeNew(*dest,data);err!=nil{return err}
 return json.NewEncoder(out).Encode(map[string]any{"status":"LOCAL_APPROVAL_FILE_CREATED","snapshotSHA256":v.SnapshotSHA256,"reviewSignatures":len(v.Reviews),"releaseSignatures":len(v.Releases)})
}
