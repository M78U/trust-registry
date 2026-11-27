package review

import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "sort"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
)

const MaxCredentialBytes=16384
const credentialDomain="M78U Trust Registry public release credential v1\x00"

// ReleaseBinding is the exact public distribution context. Consumers derive
// it from independently verified TUF metadata and target bytes.
type ReleaseBinding struct {
 InitialRootSHA256 string `json:"initialRootSHA256"`
 CurrentRootSHA256 string `json:"currentRootSHA256"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 Sequence uint64 `json:"sequence"`
 TargetsExpires time.Time `json:"targetsExpires"`
 SnapshotMetadataExpires time.Time `json:"snapshotMetadataExpires"`
 TimestampExpires time.Time `json:"timestampExpires"`
}
type PublicCredential struct {
 SchemaVersion string `json:"schemaVersion"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 Binding ReleaseBinding `json:"binding"`
 ApprovalSHA256 string `json:"approvalSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 IssuedAt time.Time `json:"issuedAt"`
 Signatures []ReleaseSignature `json:"signatures"`
}
type CredentialReport struct {
 Status string `json:"status"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 CredentialSHA256 string `json:"credentialSHA256"`
 Approvers []string `json:"approvers"`
 Threshold int `json:"threshold"`
 ReleaseApprovalVerified bool `json:"releaseApprovalVerified"`
 PrivateEvidenceVerified bool `json:"privateEvidenceVerified"`
 TrustStatus string `json:"trustStatus"`
}
func(a *Authority)SHA256()string{if a==nil{return ""};return a.hash}
func CredentialBytes(v PublicCredential)([]byte,error){
 b,err:=json.Marshal(v);if err!=nil{return nil,err}
 b=append(b,'\n')
 if len(b)>MaxCredentialBytes{return nil,errors.New("public credential size limit")}
 return b,nil
}
func DecodeCredential(raw []byte)(PublicCredential,error){
 var v PublicCredential
 if len(raw)==0||len(raw)>MaxCredentialBytes{return v,errors.New("invalid public credential size")}
 if err:=json.Unmarshal(raw,&v);err!=nil{return v,err}
 b,err:=CredentialBytes(v);if err!=nil||!bytes.Equal(b,raw){return PublicCredential{},errors.New("noncanonical public credential")}
 return v,nil
}
func validBinding(b ReleaseBinding)bool{
 return hashPattern.MatchString(b.InitialRootSHA256)&&hashPattern.MatchString(b.CurrentRootSHA256)&&hashPattern.MatchString(b.SnapshotSHA256)&&b.Sequence>0&&validTime(b.TargetsExpires)&&validTime(b.SnapshotMetadataExpires)&&validTime(b.TimestampExpires)&&!b.TargetsExpires.Before(b.SnapshotMetadataExpires)&&!b.SnapshotMetadataExpires.Before(b.TimestampExpires)
}
func credentialHeader(a *Authority,v PublicCredential,b ReleaseBinding,at time.Time)error{
 if err:=a.check();err!=nil{return err}
 if v.SchemaVersion!="1"||v.AuthoritySHA256!=a.hash||!validBinding(b)||v.Binding!=b||!validTime(v.IssuedAt)||!validTime(at)||at.Before(v.IssuedAt)||!at.Before(b.TimestampExpires)||!v.IssuedAt.Before(b.TimestampExpires)||!hashPattern.MatchString(v.ApprovalSHA256)||!hashPattern.MatchString(v.DossierSHA256)||v.Signatures==nil||len(v.Signatures)>MaxAuthorityKeys{return errors.New("public credential binding or validity mismatch")}
 return nil
}
func credentialMessage(v PublicCredential,id string)([]byte,error){
 v.Signatures=[]ReleaseSignature{}
 return message(credentialDomain,struct{Credential PublicCredential;Approver string}{v,id})
}
func verifyCredentialSignatures(a *Authority,v PublicCredential)error{
 last:=""
 for _,s:=range v.Signatures{
  if s.Approver<=last{return errors.New("duplicate or unsorted public approver")}
  m,err:=credentialMessage(v,s.Approver);if err!=nil{return err}
  if err:=a.verify(s.Approver,"RELEASE",m,s.Signature);err!=nil{return err}
  last=s.Approver
 }
 return nil
}
// PrepareCredential first verifies the full private dossier and approvals.
// The public statement intentionally contains no notes, tasks or artifacts.
func PrepareCredential(raw []byte,d Dossier,dir string,a *Authority,v Approval,b ReleaseBinding,at time.Time)(PublicCredential,error){
 auth,err:=Authenticate(raw,d,dir,a,v,at);if err!=nil{return PublicCredential{},err}
 sr,err:=snapshot.Verify(raw,"");if err!=nil{return PublicCredential{},err}
 if b.SnapshotSHA256!=sr.SnapshotSHA256||b.Sequence!=sr.Manifest.Sequence||b.TargetsExpires.After(sr.Manifest.ExpiresAt){return PublicCredential{},errors.New("public distribution differs from reviewed snapshot")}
 c:=PublicCredential{"1",a.hash,b,auth.ApprovalSHA256,auth.Review.DossierSHA256,at,[]ReleaseSignature{}}
 if err:=credentialHeader(a,c,b,at);err!=nil{return PublicCredential{},err}
 return c,nil
}
func SignCredential(raw []byte,d Dossier,dir string,a *Authority,v Approval,c PublicCredential,id string,key ed25519.PrivateKey,at time.Time)(PublicCredential,error){
 auth,err:=Authenticate(raw,d,dir,a,v,at);if err!=nil{return PublicCredential{},err}
 if err:=credentialHeader(a,c,c.Binding,at);err!=nil{return PublicCredential{},err}
 sr,err:=snapshot.Verify(raw,"");if err!=nil{return PublicCredential{},err}
 if c.Binding.SnapshotSHA256!=sr.SnapshotSHA256||c.Binding.Sequence!=sr.Manifest.Sequence||c.Binding.TargetsExpires.After(sr.Manifest.ExpiresAt)||c.ApprovalSHA256!=auth.ApprovalSHA256||c.DossierSHA256!=auth.Review.DossierSHA256||c.IssuedAt.Before(v.ApprovedFrom)||!c.IssuedAt.Before(v.ApprovedUntil){return PublicCredential{},errors.New("credential does not match private approval")}
 if err:=verifyCredentialSignatures(a,c);err!=nil{return PublicCredential{},err}
 if err:=a.signer(id,"RELEASE",key);err!=nil{return PublicCredential{},err}
 for _,s:=range c.Signatures{if s.Approver==id{return PublicCredential{},errors.New("public credential already signed by approver")}}
 m,err:=credentialMessage(c,id);if err!=nil{return PublicCredential{},err}
 c.Signatures=append(append([]ReleaseSignature{},c.Signatures...),ReleaseSignature{id,ed25519.Sign(key,m)})
 sort.Slice(c.Signatures,func(i,j int)bool{return c.Signatures[i].Approver<c.Signatures[j].Approver})
 return c,nil
}
// VerifyCredential proves a threshold of independently pinned release keys
// attested to this exact distribution. It does not validate private evidence.
func VerifyCredential(a *Authority,c PublicCredential,b ReleaseBinding,at time.Time)(CredentialReport,error){
 if err:=credentialHeader(a,c,b,at);err!=nil{return CredentialReport{},err}
 if err:=verifyCredentialSignatures(a,c);err!=nil{return CredentialReport{},err}
 if len(c.Signatures)<a.threshold{return CredentialReport{},errors.New("public release threshold not met")}
 raw,err:=CredentialBytes(c);if err!=nil{return CredentialReport{},err}
 ids:=[]string{};for _,s:=range c.Signatures{ids=append(ids,s.Approver)}
 return CredentialReport{Status:"PINNED_RELEASE_THRESHOLD_VERIFIED",AuthoritySHA256:a.hash,CredentialSHA256:digest(raw),Approvers:ids,Threshold:a.threshold,ReleaseApprovalVerified:true,TrustStatus:"NOT_ESTABLISHED"},nil
}
