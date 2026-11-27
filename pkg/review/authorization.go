package review

import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "errors"
 "fmt"
 "sort"
 "time"

 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/M78U/trust-registry/schemas"
)

const MaxAuthorityKeys=32
const MaxAuthorityBytes=64<<10
const MaxApprovalBytes=2<<20
const reviewDomain="M78U Trust Registry review attestation v1\x00"
const releaseDomain="M78U Trust Registry release approval v1\x00"

type AuthorityKey struct {
 ID string `json:"id"`
 Role string `json:"role"`
 PublicKey []byte `json:"publicKey"`
}
type AuthorityConfig struct {
 SchemaVersion string `json:"schemaVersion"`
 ReleaseThreshold int `json:"releaseThreshold"`
 Keys []AuthorityKey `json:"keys"`
}
// Authority is a detached view of an explicitly pinned key configuration.
// The pin must be independently provisioned; it is not supplied by a bundle.
type Authority struct {
 hash string
 keys map[string]AuthorityKey
 threshold int
}
func ParseAuthority(raw []byte,pin string)(*Authority,error){
 if len(raw)==0||len(raw)>MaxAuthorityBytes||!hashPattern.MatchString(pin)||digest(raw)!=pin{return nil,errors.New("independent authority configuration pin mismatch")}
 if err:=schemas.ValidateJSON(schemas.ReviewAuthority,raw);err!=nil{return nil,err}
 var c AuthorityConfig
 if err:=json.Unmarshal(raw,&c);err!=nil{return nil,err}
 a:=&Authority{hash:pin,keys:map[string]AuthorityKey{},threshold:c.ReleaseThreshold}
 seen:=map[string]bool{};counts:=map[string]int{}
 for _,k:=range c.Keys{
  if !reviewerPattern.MatchString(k.ID)||len(k.PublicKey)!=ed25519.PublicKeySize||a.keys[k.ID].ID!=""||seen[digest(k.PublicKey)]{return nil,errors.New("duplicate or invalid authority identity/key")}
  switch k.Role{case "SOURCE_IDENTITY","REVIEW","RELEASE":default:return nil,errors.New("invalid role")}
  seen[digest(k.PublicKey)]=true;counts[k.Role]++;a.keys[k.ID]=k
 }
 if c.SchemaVersion!="1"||len(c.Keys)>MaxAuthorityKeys||counts["SOURCE_IDENTITY"]==0||counts["REVIEW"]==0||a.threshold<2||a.threshold>counts["RELEASE"]{return nil,errors.New("separate source/review roles and release threshold >=2 required")}
 return a,nil
}
type ReviewSignature struct{
 RequirementID string `json:"requirementId"`
 Reviewer string `json:"reviewer"`
 Signature []byte `json:"signature"`
}
type ReleaseSignature struct{
 Approver string `json:"approver"`
 Signature []byte `json:"signature"`
}
type Approval struct{
 SchemaVersion string `json:"schemaVersion"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 SnapshotSHA256 string `json:"snapshotSHA256"`
 DossierSHA256 string `json:"dossierSHA256"`
 Sequence uint64 `json:"sequence"`
 ApprovedFrom time.Time `json:"approvedFrom"`
 ApprovedUntil time.Time `json:"approvedUntil"`
 Reviews []ReviewSignature `json:"reviews"`
 Releases []ReleaseSignature `json:"releases"`
}
type AuthorizationReport struct{
 Review Report `json:"review"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 ApprovalSHA256 string `json:"approvalSHA256"`
 VerifiedReviewCount int `json:"verifiedReviewCount"`
 ReleaseApprovers []string `json:"releaseApprovers"`
 ReleaseThreshold int `json:"releaseThreshold"`
 Status string `json:"status"`
 LocalReleaseApprovalVerified bool `json:"localReleaseApprovalVerified"`
 ReleaseAuthorized bool `json:"releaseAuthorized"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
func approvalBytes(v Approval)([]byte,error){
 b,err:=json.Marshal(v);if err!=nil{return nil,err}
 b=append(b,'\n');if len(b)>MaxApprovalBytes{return nil,errors.New("approval size limit")};return b,nil
}
func ApprovalBytes(v Approval)([]byte,error){return approvalBytes(v)}
func DecodeApproval(raw []byte)(Approval,error){
 var v Approval
 if len(raw)==0||len(raw)>MaxApprovalBytes{return v,errors.New("invalid approval size")}
 if err:=json.Unmarshal(raw,&v);err!=nil{return v,err}
 b,err:=approvalBytes(v);if err!=nil||!bytes.Equal(b,raw){return Approval{},errors.New("noncanonical approval")}
 return v,nil
}
func (a *Authority)check()error{
 if a==nil||!hashPattern.MatchString(a.hash)||a.threshold<2||len(a.keys)==0{return errors.New("pinned authority required")}
 return nil
}
func reviewRole(kind string)string{if kind=="SOURCE_IDENTITY"{return "SOURCE_IDENTITY"};return "REVIEW"}
func message(domain string,v any)([]byte,error){
 raw,err:=json.Marshal(v);if err!=nil{return nil,err}
 return []byte(domain+digest(raw)),nil
}
func reviewMessage(a *Authority,snapshotHash string,v Attestation)([]byte,error){
 return message(reviewDomain,struct{Authority,Snapshot string; Attestation Attestation}{a.hash,snapshotHash,v})
}
func releaseMessage(v Approval,approver string)([]byte,error){
 // Release signatures are not recursively included. All review signatures,
 // exact time window, sequence and the particular approver are included.
 v.Releases=[]ReleaseSignature{}
 return message(releaseDomain,struct{Approval Approval; Approver string}{v,approver})
}
func (a *Authority)signer(id,role string,key ed25519.PrivateKey)error{
 if err:=a.check();err!=nil{return err}
 k,ok:=a.keys[id]
 if !ok||k.Role!=role||len(key)!=ed25519.PrivateKeySize||!bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()),key)||!bytes.Equal(k.PublicKey,key.Public().(ed25519.PublicKey)){return errors.New("private key does not match pinned identity and role")}
 return nil
}
func (a *Authority)verify(id,role string,msg,sig []byte)error{
 k,ok:=a.keys[id]
 if !ok||k.Role!=role||len(sig)!=ed25519.SignatureSize||!ed25519.Verify(ed25519.PublicKey(k.PublicKey),msg,sig){return errors.New("signature or pinned role mismatch")}
 return nil
}
func selectReview(d Dossier,id string)(Attestation,error){
 var v Attestation;n:=0
 for _,row:=range d.Reviews{if row.Requirement.ID==id{v=row;n++}}
 if n!=1||v.Status!="APPROVED"{return Attestation{},errors.New("exact approved review task required")}
 return v,nil
}
// NewApproval checks the complete local dossier and creates an empty signed
// approval collection. No private key is generated, stored or transmitted.
func NewApproval(raw []byte,d Dossier,dir string,a *Authority,from,until time.Time)(Approval,error){
 if err:=a.check();err!=nil{return Approval{},err}
 r,err:=Check(raw,d,dir,from);if err!=nil{return Approval{},err}
 if r.Status!="LOCAL_REVIEW_REQUIREMENTS_SATISFIED"{return Approval{},errors.New("local review gate blocked")}
 sr,err:=snapshot.Verify(raw,"");if err!=nil{return Approval{},err}
 if !validTime(until)||!until.After(from)||until.After(sr.Manifest.ExpiresAt)||until.Sub(from)>24*time.Hour{return Approval{},errors.New("approval window must be positive, <=24h and within snapshot expiry")}
 return Approval{"1",a.hash,r.SnapshotSHA256,r.DossierSHA256,r.Sequence,from,until,[]ReviewSignature{},[]ReleaseSignature{}},nil
}
func checkHeader(raw []byte,d Dossier,dir string,a *Authority,v Approval,at time.Time)(Report,error){
 if err:=a.check();err!=nil{return Report{},err}
 if !validTime(at)||!validTime(v.ApprovedFrom)||!validTime(v.ApprovedUntil)||at.Before(v.ApprovedFrom)||!at.Before(v.ApprovedUntil)||!v.ApprovedUntil.After(v.ApprovedFrom)||v.ApprovedUntil.Sub(v.ApprovedFrom)>24*time.Hour||v.SchemaVersion!="1"||v.AuthoritySHA256!=a.hash||v.Reviews==nil||v.Releases==nil||len(v.Reviews)>MaxTasks||len(v.Releases)>MaxAuthorityKeys{return Report{},errors.New("invalid or expired approval header")}
 r,err:=Check(raw,d,dir,v.ApprovedFrom);if err!=nil{return Report{},err}
 if r.Status!="LOCAL_REVIEW_REQUIREMENTS_SATISFIED"||v.SnapshotSHA256!=r.SnapshotSHA256||v.DossierSHA256!=r.DossierSHA256||v.Sequence!=r.Sequence{return Report{},errors.New("approval does not match complete reviewed snapshot")}
 sr,err:=snapshot.Verify(raw,"");if err!=nil{return Report{},err}
 if v.ApprovedUntil.After(sr.Manifest.ExpiresAt){return Report{},errors.New("approval exceeds snapshot expiry")}
 return r,nil
}
func verifyReviews(a *Authority,d Dossier,v Approval,complete bool)error{
 if len(v.Reviews)>len(d.Reviews)||complete&&len(v.Reviews)!=len(d.Reviews){return errors.New("review signature membership mismatch")}
 byID:=map[string]Attestation{}
 for _,r:=range d.Reviews{byID[r.Requirement.ID]=r}
 last:=""
 for _,s:=range v.Reviews{
  row,ok:=byID[s.RequirementID]
  if !ok||row.Status!="APPROVED"||row.Reviewer!=s.Reviewer||s.RequirementID<=last{return errors.New("unknown, duplicate, unsorted or mismatched review signature")}
  msg,err:=reviewMessage(a,v.SnapshotSHA256,row);if err!=nil{return err}
  if err:=a.verify(s.Reviewer,reviewRole(row.Requirement.Kind),msg,s.Signature);err!=nil{return fmt.Errorf("review %s: %w",s.RequirementID,err)}
  last=s.RequirementID
 }
 return nil
}
func verifyReleases(a *Authority,v Approval)error{
 last:=""
 for _,s:=range v.Releases{
  if s.Approver<=last{return errors.New("duplicate or unsorted release signature")}
  msg,err:=releaseMessage(v,s.Approver);if err!=nil{return err}
  if err:=a.verify(s.Approver,"RELEASE",msg,s.Signature);err!=nil{return err}
  last=s.Approver
 }
 return nil
}
// SignReview adds one exact approved task signature. Once a release approval
// exists the review signature set is immutable. Signers must read evidence.
func SignReview(raw []byte,d Dossier,dir string,a *Authority,v Approval,task string,key ed25519.PrivateKey,at time.Time)(Approval,error){
 if _,err:=checkHeader(raw,d,dir,a,v,at);err!=nil{return Approval{},err}
 if len(v.Releases)!=0{return Approval{},errors.New("release signatures already present")}
 if err:=verifyReviews(a,d,v,false);err!=nil{return Approval{},err}
 row,err:=selectReview(d,task);if err!=nil{return Approval{},err}
 if err:=a.signer(row.Reviewer,reviewRole(row.Requirement.Kind),key);err!=nil{return Approval{},err}
 for _,s:=range v.Reviews{if s.RequirementID==task{return Approval{},errors.New("task already signed")}}
 msg,err:=reviewMessage(a,v.SnapshotSHA256,row);if err!=nil{return Approval{},err}
 v.Reviews=append(append([]ReviewSignature{},v.Reviews...),ReviewSignature{task,row.Reviewer,ed25519.Sign(key,msg)})
 sort.Slice(v.Reviews,func(i,j int)bool{return v.Reviews[i].RequirementID<v.Reviews[j].RequirementID})
 return v,nil
}
func SignRelease(raw []byte,d Dossier,dir string,a *Authority,v Approval,id string,key ed25519.PrivateKey,at time.Time)(Approval,error){
 if _,err:=checkHeader(raw,d,dir,a,v,at);err!=nil{return Approval{},err}
 if err:=verifyReviews(a,d,v,true);err!=nil{return Approval{},err}
 if err:=verifyReleases(a,v);err!=nil{return Approval{},err}
 if err:=a.signer(id,"RELEASE",key);err!=nil{return Approval{},err}
 for _,s:=range v.Releases{if s.Approver==id{return Approval{},errors.New("approver already signed")}}
 msg,err:=releaseMessage(v,id);if err!=nil{return Approval{},err}
 v.Releases=append(append([]ReleaseSignature{},v.Releases...),ReleaseSignature{id,ed25519.Sign(key,msg)})
 sort.Slice(v.Releases,func(i,j int)bool{return v.Releases[i].Approver<v.Releases[j].Approver})
 return v,nil
}
// Authenticate verifies local role-key approvals, not a TUF release or
// reviewer real-world identity. No rollback state or publishing side effect.
func Authenticate(raw []byte,d Dossier,dir string,a *Authority,v Approval,at time.Time)(AuthorizationReport,error){
 r,err:=checkHeader(raw,d,dir,a,v,at);if err!=nil{return AuthorizationReport{},err}
 if err:=verifyReviews(a,d,v,true);err!=nil{return AuthorizationReport{},err}
 if err:=verifyReleases(a,v);err!=nil{return AuthorizationReport{},err}
 if len(v.Releases)<a.threshold{return AuthorizationReport{},errors.New("release approval threshold not met")}
 data,err:=approvalBytes(v);if err!=nil{return AuthorizationReport{},err}
 ids:=[]string{};for _,s:=range v.Releases{ids=append(ids,s.Approver)}
 r.ReviewerAuthentication="VERIFIED_UNDER_PINNED_ROLE_KEYS"
 return AuthorizationReport{Review:r,AuthoritySHA256:a.hash,ApprovalSHA256:digest(data),VerifiedReviewCount:len(v.Reviews),ReleaseApprovers:ids,ReleaseThreshold:a.threshold,Status:"LOCAL_THRESHOLD_APPROVAL_VERIFIED",LocalReleaseApprovalVerified:true,TrustStatus:"NOT_ESTABLISHED"},nil
}
