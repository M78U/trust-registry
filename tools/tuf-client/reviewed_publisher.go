package tufclient

import (
 "crypto/ed25519"
 "errors"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)
type ReviewedPublishOptions struct{
 Publish PublishOptions
 Authority *review.Authority
 Dossier review.Dossier
 EvidenceDir string
 Approval review.Approval
 PreviousSnapshot []byte
 PreviousSHA256 string
 Bootstrap bool
}
type ReviewedPublicationReport struct{
 Authorization review.AuthorizationReport `json:"authorization"`
 Transition snapshot.PublicationTransition `json:"transition"`
 RootSHA256 string `json:"rootSHA256"`
 TargetSHA256 string `json:"targetSHA256"`
 Version int64 `json:"version"`
 Status string `json:"status"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
// checkRoleSeparation uses decoded raw public keys, not metadata key IDs
// alone. Reject aliases, unreferenced root keys and non-Ed25519 keys.
func checkRoleSeparation(rootBytes []byte,pin string,a *review.Authority)error{
 if len(rootBytes)==0||len(rootBytes)>maxRoot||!hashPattern.MatchString(pin)||digest(rootBytes)!=pin{return errors.New("root pin mismatch")}
 root,err:=metadata.Root().FromBytes(rootBytes);if err!=nil{return err}
 if root.Signed.Version!=1||!root.Signed.ConsistentSnapshot||len(root.Signed.Roles)!=4||len(root.Signed.Keys)>64{return errors.New("strict four-role initial root required")}
 if err:=root.VerifyDelegate(metadata.ROOT,root);err!=nil{return err}
 usedIDs:=map[string]bool{}
 usedKeys:=map[string]bool{}
 for _,role:=range roles{
  v:=root.Signed.Roles[role]
  if v==nil||v.Threshold<1||v.Threshold>len(v.KeyIDs)||len(v.KeyIDs)>16{return errors.New("invalid root role configuration")}
  for _,id:=range v.KeyIDs{
   k:=root.Signed.Keys[id]
   if k==nil||usedIDs[id]||k.Type!=metadata.KeyTypeEd25519||k.Scheme!=metadata.KeySchemeEd25519{return errors.New("missing, reused or unsupported root role key")}
   expected,err:=k.ID();if err!=nil||expected!=id{return errors.New("noncanonical root key identity")}
   pk,err:=k.ToPublicKey();if err!=nil{return err}
   pub,ok:=pk.(ed25519.PublicKey)
   if !ok||len(pub)!=ed25519.PublicKeySize||usedKeys[digest(pub)]{return errors.New("duplicate or invalid raw role key")}
   if err:=a.RequireDisjointKey(pub);err!=nil{return err}
   usedIDs[id]=true;usedKeys[digest(pub)]=true
  }
 }
 if len(usedIDs)!=len(root.Signed.Keys){return errors.New("unreferenced root keys")}
 return nil
}
// BuildReviewedRepository is an opt-in strict local staging path. The old
// research builder is deliberately not a release authority. Protect keys,
// pins and baseline independently; never serve research outputs to clients.
func BuildReviewedRepository(rootBytes,raw []byte,o ReviewedPublishOptions)(Repository,ReviewedPublicationReport,error){
 if err:=checkRoleSeparation(rootBytes,o.Publish.RootSHA256,o.Authority);err!=nil{return Repository{},ReviewedPublicationReport{},err}
 auth,err:=review.Authenticate(raw,o.Dossier,o.EvidenceDir,o.Authority,o.Approval,o.Publish.Now);if err!=nil{return Repository{},ReviewedPublicationReport{},err}
 transition,err:=snapshot.CheckPublicationTransition(o.PreviousSnapshot,raw,o.PreviousSHA256,o.Bootstrap);if err!=nil{return Repository{},ReviewedPublicationReport{},err}
 if !auth.LocalReleaseApprovalVerified||auth.Review.SnapshotSHA256!=transition.NextSHA256||o.Publish.Version<1||uint64(o.Publish.Version)!=transition.NextSequence{return Repository{},ReviewedPublicationReport{},errors.New("approval, transition and TUF sequence mismatch")}
 repo,err:=BuildRepository(rootBytes,raw,o.Publish);if err!=nil{return Repository{},ReviewedPublicationReport{},err}
 return repo,ReviewedPublicationReport{Authorization:auth,Transition:transition,RootSHA256:repo.RootSHA256,TargetSHA256:repo.TargetSHA256,Version:repo.Version,Status:"REVIEWED_LOCAL_PUBLICATION_CANDIDATE",TrustStatus:"NOT_ESTABLISHED"},nil
}
