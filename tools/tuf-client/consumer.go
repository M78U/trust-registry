package tufclient

import (
 "errors"
 "time"

 "github.com/M78U/trust-registry/pkg/policy"
 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/review"
 "github.com/M78U/trust-registry/pkg/revocation"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/M78U/trust-registry/pkg/validation"
)

const MaxConsumerSessionDuration=15*time.Minute

type ConsumerOptions struct{
 StateDir string
 InitialRootSHA256 string
 Authority *review.Authority
 // Optional independently retained checkpoint (not persisted by SDK).
 MinimumSequence uint64
 ExpectedSnapshotSHA256 string
}
type ConsumerInfo struct{
 SnapshotSHA256 string `json:"snapshotSHA256"`
 Sequence uint64 `json:"sequence"`
 InitialRootSHA256 string `json:"initialRootSHA256"`
 RootVersion int64 `json:"rootVersion"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 CredentialSHA256 string `json:"credentialSHA256"`
 VerifiedAt time.Time `json:"verifiedAt"`
 SessionExpiresAt time.Time `json:"sessionExpiresAt"`
 TUFTargetAuthenticated bool `json:"tufTargetAuthenticated"`
 ReleaseApprovalVerified bool `json:"releaseApprovalVerified"`
 PrivateEvidenceVerified bool `json:"privateEvidenceVerified"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
type ConsumerSession struct{
 view *snapshot.Loaded
 raw []byte
 info ConsumerInfo
}

// OpenConsumer requires strict local TUF installation and independent review
// authority. It never fetches, falls back, resets state or exposes the view.
func OpenConsumer(o ConsumerOptions)(*ConsumerSession,error){
 if o.Authority==nil||!hashPattern.MatchString(o.InitialRootSHA256)||!hashPattern.MatchString(o.Authority.SHA256())||o.ExpectedSnapshotSHA256!=""&&!hashPattern.MatchString(o.ExpectedSnapshotSHA256){return nil,errors.New("independent root/authority and valid optional snapshot pin required")}
 var raw []byte
 v,r,err:=loadInstalledCapture(o.StateDir,o.InitialRootSHA256,o.Authority,&raw)
 if err!=nil{return nil,err}
 return newConsumerSession(o,v,r,raw,time.Now().UTC())
}
func newConsumerSession(o ConsumerOptions,v *snapshot.Loaded,r Report,raw []byte,now time.Time)(*ConsumerSession,error){
 a:=r.ReleaseApproval
 if v==nil||o.Authority==nil||!r.TUFTargetAuthenticated||a==nil||!a.ReleaseApprovalVerified||a.AuthoritySHA256!=o.Authority.SHA256()||!hashPattern.MatchString(a.CredentialSHA256)||r.OfflineVerification==nil||r.ApplicationRollbackStatus!="LOCAL_INSTALLED_RECORD"||r.Registry.Manifest.Sequence==0||r.RootVersion<1||len(raw)==0||len(raw)>snapshot.MaxEnvelopeBytes||digest(raw)!=r.Registry.SnapshotSHA256{return nil,errors.New("strict authenticated installed view required")}
 if r.Registry.Manifest.Sequence<o.MinimumSequence||o.ExpectedSnapshotSHA256!=""&&r.Registry.SnapshotSHA256!=o.ExpectedSnapshotSHA256{return nil,errors.New("installed snapshot does not satisfy independent checkpoint")}
 verified:=r.OfflineVerification.VerifiedAt
 expires:=r.OfflineVerification.ValidUntil
 if limit:=verified.Add(MaxConsumerSessionDuration);limit.Before(expires){expires=limit}
 s:=&ConsumerSession{view:v,raw:raw,info:ConsumerInfo{SnapshotSHA256:r.Registry.SnapshotSHA256,Sequence:r.Registry.Manifest.Sequence,InitialRootSHA256:o.InitialRootSHA256,RootVersion:r.RootVersion,AuthoritySHA256:a.AuthoritySHA256,CredentialSHA256:a.CredentialSHA256,VerifiedAt:verified,SessionExpiresAt:expires,TUFTargetAuthenticated:true,ReleaseApprovalVerified:true,TrustStatus:"NOT_ESTABLISHED"}}
 if err:=s.checkAt(now);err!=nil{return nil,err}
 return s,nil
}
func(s *ConsumerSession)checkAt(now time.Time)error{
 if s==nil||s.view==nil||len(s.raw)==0||!s.info.TUFTargetAuthenticated||!s.info.ReleaseApprovalVerified||!validTime(now)||!validTime(s.info.VerifiedAt)||!validTime(s.info.SessionExpiresAt)||now.Before(s.info.VerifiedAt)||!now.Before(s.info.SessionExpiresAt){return errors.New("consumer session invalid or expired; reopen strict installed state")}
 return nil
}
func(s *ConsumerSession)check()error{return s.checkAt(time.Now().UTC())}

// Info is a value copy. Authentication describes distribution only.
func(s *ConsumerSession)Info()(ConsumerInfo,error){
 if err:=s.check();err!=nil{return ConsumerInfo{},err}
 return s.info,nil
}
func sessionResult[T any](s *ConsumerSession,run func()(T,error))(T,error){
 var zero T
 if err:=s.check();err!=nil{return zero,err}
 value,err:=run();if err!=nil{return zero,err}
 if err:=s.check();err!=nil{return zero,err}
 return value,nil
}
func(s *ConsumerSession)Find(fp string)(registry.CertificateRecord,error){
 return sessionResult(s,func()(registry.CertificateRecord,error){return s.view.Find(fp)})
}
func(s *ConsumerSession)Search(q registry.Query)(registry.SearchResult,error){
 return sessionResult(s,func()(registry.SearchResult,error){return s.view.Search(q)})
}
func(s *ConsumerSession)Provenance(fp string)([]registry.ProvenanceEntry,error){
 return sessionResult(s,func()([]registry.ProvenanceEntry,error){return s.view.Provenance(fp)})
}
func(s *ConsumerSession)DiscoverIssuers(input []byte)(registry.DiscoveryReport,error){
 return sessionResult(s,func()(registry.DiscoveryReport,error){return s.view.DiscoverIssuers(input)})
}
// CandidateBundle preserves the existing untrusted candidate interchange
// format. Distribution authentication is separate in Info, never a trust anchor.
func(s *ConsumerSession)CandidateBundle(input []byte)([]byte,error){
 return sessionResult(s,func()([]byte,error){return s.view.CandidateBundle(input)})
}
func(s *ConsumerSession)EvaluatePolicy(id string,version int,p snapshot.EvaluationPoint)(policy.Evaluation,error){
 return sessionResult(s,func()(policy.Evaluation,error){return s.view.EvaluatePolicy(id,version,p.At,p.KnownAt)})
}
func(s *ConsumerSession)VerifyPath(input []byte,id string,version int,purpose,dns string,p snapshot.EvaluationPoint)(validation.LocalPathReport,error){
 return sessionResult(s,func()(validation.LocalPathReport,error){return s.view.VerifyLocalPath(input,id,version,purpose,dns,p.At,p.KnownAt)})
}
func(s *ConsumerSession)VerifyPathWithRevocation(input []byte,id string,version int,purpose,dns string,p snapshot.EvaluationPoint,evidence *revocation.EvidenceStore)(validation.LocalPathWithRevocationReport,error){
 return sessionResult(s,func()(validation.LocalPathWithRevocationReport,error){return s.view.VerifyLocalPathWithRevocation(input,id,version,purpose,dns,p.At,p.KnownAt,evidence)})
}

func(s *ConsumerSession)checkNext(next *ConsumerSession)error{
 if err:=s.check();err!=nil{return err}
 if err:=next.check();err!=nil{return err}
 if s.info.InitialRootSHA256!=next.info.InitialRootSHA256||s.info.AuthoritySHA256!=next.info.AuthoritySHA256||next.info.Sequence<=s.info.Sequence||next.info.RootVersion<s.info.RootVersion{return errors.New("newer live session with same independent root and authority required")}
 return nil
}
func(s *ConsumerSession)checkComparisonPoint(next *ConsumerSession,p snapshot.EvaluationPoint)error{
 if p.KnownAt.After(s.info.VerifiedAt)||p.KnownAt.After(next.info.VerifiedAt){return errors.New("comparison knowledge cutoff exceeds either verified session time")}
 return nil
}
// Diff and impact methods require two still-live sessions. No historical
// installed-record fallback or bypass of metadata expiry is provided.
func(s *ConsumerSession)Diff(next *ConsumerSession,strict bool)(snapshot.DiffReport,error){
 return sessionResult(s,func()(snapshot.DiffReport,error){
  if err:=s.checkNext(next);err!=nil{return snapshot.DiffReport{},err}
  r,err:=snapshot.Compare(s.raw,next.raw,snapshot.DiffOptions{PreviousSHA256:s.info.SnapshotSHA256,NextSHA256:next.info.SnapshotSHA256,RequirePublicationTransition:strict})
  if err!=nil{return snapshot.DiffReport{},err}
  if err:=next.check();err!=nil{return snapshot.DiffReport{},err}
  return r,nil
 })
}
func(s *ConsumerSession)AuthorizationImpact(next *ConsumerSession,p snapshot.EvaluationPoint,baseline *snapshot.EvaluationPoint)(snapshot.AuthorizationImpactReport,error){
 return sessionResult(s,func()(snapshot.AuthorizationImpactReport,error){
  if err:=s.checkNext(next);err!=nil{return snapshot.AuthorizationImpactReport{},err}
  if err:=s.checkComparisonPoint(next,p);err!=nil{return snapshot.AuthorizationImpactReport{},err}
  if baseline!=nil{if err:=s.checkComparisonPoint(next,*baseline);err!=nil{return snapshot.AuthorizationImpactReport{},err}}
  r,err:=snapshot.CompareAuthorization(s.raw,next.raw,snapshot.AuthorizationImpactOptions{PreviousSHA256:s.info.SnapshotSHA256,NextSHA256:next.info.SnapshotSHA256,Point:p,Baseline:baseline})
  if err!=nil{return snapshot.AuthorizationImpactReport{},err}
  if err:=next.check();err!=nil{return snapshot.AuthorizationImpactReport{},err}
  return r,nil
 })
}
func(s *ConsumerSession)PathImpact(next *ConsumerSession,input []byte,o snapshot.PathImpactOptions)(snapshot.PathImpactReport,error){
 return sessionResult(s,func()(snapshot.PathImpactReport,error){
  if err:=s.checkNext(next);err!=nil{return snapshot.PathImpactReport{},err}
  if err:=s.checkComparisonPoint(next,o.Point);err!=nil{return snapshot.PathImpactReport{},err}
  // Callers must not supply alternate pins through the SDK.
  if o.PreviousSHA256!=""||o.NextSHA256!=""{return snapshot.PathImpactReport{},errors.New("session comparison derives snapshot pins internally")}
  o.PreviousSHA256=s.info.SnapshotSHA256;o.NextSHA256=next.info.SnapshotSHA256
  r,err:=snapshot.ComparePath(s.raw,next.raw,input,o)
  if err!=nil{return snapshot.PathImpactReport{},err}
  if err:=next.check();err!=nil{return snapshot.PathImpactReport{},err}
  return r,nil
 })
}
