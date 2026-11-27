package main

import (
 "crypto/ed25519"
 "crypto/x509"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/M78U/trust-registry/pkg/snapshot"
)
func runPublicCredential(args []string,out io.Writer)error{
 f:=flag.NewFlagSet("review "+args[0],flag.ContinueOnError)
 dossier:=f.String("dossier","","private dossier")
 evidence:=f.String("evidence","","private evidence directory")
 authority:=f.String("authority","","independent authority file")
 pin:=f.String("authority-sha256","","independent authority pin")
 approval:=f.String("approval","","complete private approval")
 now:=f.String("at","","explicit UTC time")
 initial:=f.String("initial-root-sha256","","independent initial root pin")
 current:=f.String("root-sha256","","current root pin")
 te:=f.String("targets-expires","","exact targets expiry")
 se:=f.String("snapshot-expires","","exact snapshot metadata expiry")
 ts:=f.String("timestamp-expires","","exact timestamp expiry")
 input:=f.String("credential","","existing canonical public credential")
 dest:=f.String("out","","new output file")
 id:=f.String("id","","release approver")
 key:=f.String("key","","PKCS8 Ed25519 release key")
 if err:=f.Parse(args[1:]);err!=nil{return err}
 if f.NArg()!=1||*dossier==""||*evidence==""||*authority==""||*pin==""||*approval==""||*now==""||*dest==""{return errors.New("private approval inputs, current time, snapshot and new output required")}
 at,err:=time.Parse(time.RFC3339Nano,*now);if err!=nil{return err};at=at.UTC()
 raw,err:=readSnapshot(f.Arg(0));if err!=nil{return err}
 db,err:=readSmall(*dossier,review.MaxDossierBytes);if err!=nil{return err}
 d,err:=review.DecodeDossier(db);if err!=nil{return err}
 ab,err:=readSmall(*authority,review.MaxAuthorityBytes);if err!=nil{return err}
 a,err:=review.ParseAuthority(ab,*pin);if err!=nil{return err}
 vb,err:=readSmall(*approval,review.MaxApprovalBytes);if err!=nil{return err}
 v,err:=review.DecodeApproval(vb);if err!=nil{return err}
 var c review.PublicCredential
 switch args[0]{
 case "prepare-public":
  if *input!=""||*id!=""||*key!=""{return errors.New("prepare does not accept existing credential or key")}
  sr,err:=snapshot.Verify(raw,"");if err!=nil{return err}
  b:=review.ReleaseBinding{InitialRootSHA256:*initial,CurrentRootSHA256:*current,SnapshotSHA256:sr.SnapshotSHA256,Sequence:sr.Manifest.Sequence}
  for _,x:=range []struct{s string;t *time.Time}{{*te,&b.TargetsExpires},{*se,&b.SnapshotMetadataExpires},{*ts,&b.TimestampExpires}}{
   t,err:=time.Parse(time.RFC3339Nano,x.s);if err!=nil{return err};*x.t=t.UTC()
  }
  c,err=review.PrepareCredential(raw,d,*evidence,a,v,b,at);if err!=nil{return err}
 case "sign-public":
  if *input==""||*id==""||*key==""||*initial!=""||*current!=""||*te!=""||*se!=""||*ts!=""{return errors.New("sign requires credential, approver and key; binding is immutable")}
  b,err:=readSmall(*input,review.MaxCredentialBytes);if err!=nil{return err}
  c,err=review.DecodeCredential(b);if err!=nil{return err}
  der,err:=readPEM(*key,"PRIVATE KEY");if err!=nil{return err};defer clear(der)
  k,err:=x509.ParsePKCS8PrivateKey(der);if err!=nil{return err}
  priv,ok:=k.(ed25519.PrivateKey);if !ok{return errors.New("Ed25519 required")};defer clear(priv)
  c,err=review.SignCredential(raw,d,*evidence,a,v,c,*id,priv,at);if err!=nil{return err}
 default:return errors.New("unknown credential command")
 }
 data,err:=review.CredentialBytes(c);if err!=nil{return err}
 if err:=writeNew(*dest,data);err!=nil{return err}
 return json.NewEncoder(out).Encode(map[string]any{"status":"PUBLIC_CREDENTIAL_FILE_CREATED","signatures":len(c.Signatures),"snapshotSHA256":c.Binding.SnapshotSHA256})
}
