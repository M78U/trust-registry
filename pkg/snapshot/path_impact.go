package snapshot

import (
 "bytes"
 "errors"
 "fmt"
 "sort"
 "strings"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/revocation"
 "github.com/M78U/trust-registry/pkg/validation"
)

const MaxPathImpactChains=256
const MaxPathImpactChainDepth=64
const MaxPathImpactReportBytes=4<<20

type PathImpactOptions struct{
 PreviousSHA256 string
 NextSHA256 string
 PolicyID string
 PolicyVersion int
 Purpose string
 DNSName string
 Point EvaluationPoint
 // Optional baseline evidence, shared across both snapshot evaluations.
 Evidence *revocation.EvidenceStore
 // Optional independently supplied replacement evidence, on next only.
 NextEvidence *revocation.EvidenceStore
}
type ImpactObservation struct{
 SHA256 string `json:"sha256"`
 Kind string `json:"kind"`
 RecordSHA256 string `json:"recordSHA256"`
}
type ImpactPair struct{
 CertificateSHA256 string `json:"certificateSHA256"`
 IssuerSHA256 string `json:"issuerSHA256"`
 Status string `json:"status"`
 HistoricalRevokedIndication bool `json:"historicalRevokedIndication"`
}
type ImpactChain struct{
 SHA256 string `json:"sha256"`
 Certificates []string `json:"certificates"`
 RevocationStatus string `json:"revocationStatus"`
 HistoricalRevokedIndication bool `json:"historicalRevokedIndication"`
}
type PathImpactState struct{
 SnapshotSHA256 string `json:"snapshotSHA256"`
 Sequence uint64 `json:"sequence"`
 SnapshotWindow string `json:"snapshotWindow"`
 PathStatus string `json:"pathStatus"`
 UsageStatus string `json:"usageStatus"`
 RevocationStatus string `json:"revocationStatus"`
 HistoricalRevokedIndication bool `json:"historicalRevokedIndication"`
 LocallyAuthorizedAnchors []string `json:"locallyAuthorizedAnchors"`
 IntermediateCandidates []string `json:"intermediateCandidates"`
 Chains []ImpactChain `json:"chains"`
 Pairs []ImpactPair `json:"pairs"`
 Observations []ImpactObservation `json:"observations"`
}
type PathImpactDelta struct{
 Kind string `json:"kind"`
 PathChange string `json:"pathChange"`
 UsageChanged bool `json:"usageChanged"`
 RevocationChanged bool `json:"revocationChanged"`
 AddedAuthorizedAnchors []string `json:"addedAuthorizedAnchors"`
 RemovedAuthorizedAnchors []string `json:"removedAuthorizedAnchors"`
 AddedIntermediateCandidates []string `json:"addedIntermediateCandidates"`
 RemovedIntermediateCandidates []string `json:"removedIntermediateCandidates"`
 AddedChains []string `json:"addedChains"`
 RemovedChains []string `json:"removedChains"`
 ChangedChainRevocation []string `json:"changedChainRevocation"`
 PairResultsChanged bool `json:"pairResultsChanged"`
 ObservationRecordsChanged bool `json:"observationRecordsChanged"`
}
type PathImpactReport struct{
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 LeafSHA256 string `json:"leafSHA256"`
 PolicyID string `json:"policyId"`
 PolicyVersion int `json:"policyVersion"`
 Purpose string `json:"purpose"`
 Jurisdiction string `json:"jurisdiction"`
 Point EvaluationPoint `json:"point"`
 Previous PathImpactState `json:"previous"`
 Next PathImpactState `json:"next"`
 NextWithReplacementEvidence *PathImpactState `json:"nextWithReplacementEvidence,omitempty"`
 SnapshotImpact PathImpactDelta `json:"snapshotImpact"`
 EvidenceImpact *PathImpactDelta `json:"evidenceImpact,omitempty"`
 ReevaluateAffectedPaths bool `json:"reevaluateAffectedPaths"`
 BusinessPurposeStatus string `json:"businessPurposeStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}

func impactChainID(chain []string)(string,error){
 if len(chain)<2||len(chain)>MaxPathImpactChainDepth{return "",errors.New("path impact chain depth limit")}
 seen:=map[string]bool{}
 for _,fp:=range chain{if !hashPattern.MatchString(fp)||seen[fp]{return "",errors.New("invalid chain identity")};seen[fp]=true}
 raw,err:=canonical(chain);if err!=nil{return "",err};return digest(raw),nil
}
func summarizeImpact(local validation.LocalPathReport,rv *validation.PathRevocation,r Report,p EvaluationPoint,leaf string)(PathImpactState,error){
 if local.Path.LeafSHA256!=leaf{return PathImpactState{},errors.New("path leaf identity mismatch")}
 if len(local.Path.Chains)>MaxPathImpactChains{return PathImpactState{},errors.New("path impact chain limit")}
 out:=PathImpactState{SnapshotSHA256:r.SnapshotSHA256,Sequence:r.Manifest.Sequence,SnapshotWindow:snapshotWindow(r.Manifest,p.KnownAt),PathStatus:local.Path.PathStatus,UsageStatus:local.Path.UsageStatus,RevocationStatus:"NOT_CHECKED",LocallyAuthorizedAnchors:append([]string{},local.Policy.LocallyAuthorizedAnchors...),IntermediateCandidates:append([]string{},local.Policy.IntermediateCandidates...),Chains:[]ImpactChain{},Pairs:[]ImpactPair{},Observations:[]ImpactObservation{}}
 sort.Strings(out.LocallyAuthorizedAnchors);sort.Strings(out.IntermediateCandidates)
 byChain:=map[string]validation.ChainRevocation{}
 if rv!=nil{
  out.RevocationStatus=rv.Status;out.HistoricalRevokedIndication=rv.HistoricalRevokedIndication
  for _,c:=range rv.Chains{id,err:=impactChainID(c.ChainSHA256);if err!=nil{return PathImpactState{},err};if _,ok:=byChain[id];ok{return PathImpactState{},errors.New("duplicate revocation chain")};byChain[id]=c}
  for _,v:=range rv.Pairs{out.Pairs=append(out.Pairs,ImpactPair{v.CertificateSHA256,v.IssuerSHA256,v.Status,len(v.HistoricalIndications)>0})}
  for _,v:=range rv.Observations{raw,err:=canonical(v);if err!=nil{return PathImpactState{},err};out.Observations=append(out.Observations,ImpactObservation{v.SHA256,v.Kind,digest(raw)})}
 }
 seen:=map[string]bool{}
 for _,c:=range local.Path.Chains{
  id,err:=impactChainID(c);if err!=nil{return PathImpactState{},err}
  if seen[id]||c[0]!=leaf{return PathImpactState{},errors.New("duplicate or mismatched verified chain")}
  seen[id]=true
  row:=ImpactChain{SHA256:id,Certificates:append([]string{},c...),RevocationStatus:"NOT_CHECKED"}
  if rv!=nil{v,ok:=byChain[id];if !ok{return PathImpactState{},errors.New("missing chain evidence result")};row.RevocationStatus=v.Status;row.HistoricalRevokedIndication=v.HistoricalRevokedIndication}
  out.Chains=append(out.Chains,row)
 }
 if rv!=nil&&len(byChain)!=len(seen){return PathImpactState{},errors.New("unexpected chain evidence result")}
 sort.Slice(out.Chains,func(i,j int)bool{return out.Chains[i].SHA256<out.Chains[j].SHA256})
 sort.Slice(out.Pairs,func(i,j int)bool{a,b:=out.Pairs[i],out.Pairs[j];if a.CertificateSHA256==b.CertificateSHA256{return a.IssuerSHA256<b.IssuerSHA256};return a.CertificateSHA256<b.CertificateSHA256})
 sort.Slice(out.Observations,func(i,j int)bool{return out.Observations[i].SHA256<out.Observations[j].SHA256})
 return out,nil
}
func impactDelta(kind string,a,b PathImpactState)PathImpactDelta{
 d:=PathImpactDelta{Kind:kind,PathChange:"PATH_STATUS_UNCHANGED",UsageChanged:a.UsageStatus!=b.UsageStatus,RevocationChanged:a.RevocationStatus!=b.RevocationStatus||a.HistoricalRevokedIndication!=b.HistoricalRevokedIndication,ChangedChainRevocation:[]string{}}
 switch{
 case a.PathStatus=="VALID_UNDER_EXPLICIT_CA_SET"&&b.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET":d.PathChange="TECHNICAL_PATH_LOST"
 case a.PathStatus!="VALID_UNDER_EXPLICIT_CA_SET"&&b.PathStatus=="VALID_UNDER_EXPLICIT_CA_SET":d.PathChange="TECHNICAL_PATH_GAINED"
 case a.PathStatus!=b.PathStatus:d.PathChange="PATH_STATUS_CHANGED"
 }
 d.AddedAuthorizedAnchors,d.RemovedAuthorizedAnchors=addedRemoved(a.LocallyAuthorizedAnchors,b.LocallyAuthorizedAnchors)
 d.AddedIntermediateCandidates,d.RemovedIntermediateCandidates=addedRemoved(a.IntermediateCandidates,b.IntermediateCandidates)
 old,next:=map[string]ImpactChain{},map[string]ImpactChain{}
 oldIDs,newIDs:=[]string{},[]string{}
 for _,c:=range a.Chains{old[c.SHA256]=c;oldIDs=append(oldIDs,c.SHA256)}
 for _,c:=range b.Chains{next[c.SHA256]=c;newIDs=append(newIDs,c.SHA256)}
 d.AddedChains,d.RemovedChains=addedRemoved(oldIDs,newIDs)
 for _,id:=range unionKeys(old,next){x,ok:=old[id];y,exists:=next[id];if ok&&exists&&(x.RevocationStatus!=y.RevocationStatus||x.HistoricalRevokedIndication!=y.HistoricalRevokedIndication){d.ChangedChainRevocation=append(d.ChangedChainRevocation,id)}}
 if d.PathChange=="PATH_STATUS_UNCHANGED"&&(len(d.AddedChains)>0||len(d.RemovedChains)>0){d.PathChange="TECHNICAL_CHAIN_SET_CHANGED"}
 // These structs contain only strings and booleans; compare normalized
 // sorted arrays, not private raw evidence or arbitrary reason text.
 d.PairResultsChanged=len(a.Pairs)!=len(b.Pairs)
 if !d.PairResultsChanged{for i,v:=range a.Pairs{if v!=b.Pairs[i]{d.PairResultsChanged=true;break}}}
 d.ObservationRecordsChanged=len(a.Observations)!=len(b.Observations)
 if !d.ObservationRecordsChanged{for i,v:=range a.Observations{if v!=b.Observations[i]{d.ObservationRecordsChanged=true;break}}}
 return d
}

// ComparePath verifies a single supplied end-entity certificate under the
// same explicit policy ID/version, scope and cutoffs in both snapshots.
// Evidence observations are private and separate from the snapshot.
func ComparePath(previous,next,input []byte,o PathImpactOptions)(PathImpactReport,error){
 if !validPoint(o.Point)||o.PolicyID==""||o.PolicyVersion<1||o.Purpose==""||(o.NextEvidence!=nil&&o.Evidence==nil){return PathImpactReport{},errors.New("explicit policy, valid cutoffs and baseline evidence before replacement required")}
 if (o.Purpose=="server-authentication")!=(strings.TrimSpace(o.DNSName)!="")||len(o.DNSName)>253{return PathImpactReport{},errors.New("DNS name required only for server-authentication")}
 leaf,der,err:=registry.ParseCertificate(input);if err!=nil{return PathImpactReport{},err}
 if leaf.IsCA{return PathImpactReport{},errors.New("end-entity certificate required")}
 // Use normalized detached DER for all evaluations.
 input=bytes.Clone(der)
 a,ar,err:=loadImpact(previous,o.PreviousSHA256,o.Point.KnownAt);if err!=nil{return PathImpactReport{},fmt.Errorf("previous: %w",err)}
 b,br,err:=loadImpact(next,o.NextSHA256,o.Point.KnownAt);if err!=nil{return PathImpactReport{},fmt.Errorf("next: %w",err)}
 if br.Manifest.Sequence<=ar.Manifest.Sequence||!br.Manifest.CreatedAt.After(ar.Manifest.CreatedAt){return PathImpactReport{},errors.New("next sequence and creation time must increase")}
 ad,err:=a.Policy(o.PolicyID,o.PolicyVersion);if err!=nil{return PathImpactReport{},fmt.Errorf("previous policy: %w",err)}
 bd,err:=b.Policy(o.PolicyID,o.PolicyVersion);if err!=nil{return PathImpactReport{},fmt.Errorf("next policy: %w",err)}
 if ad.Policy.Purpose!=o.Purpose||bd.Policy.Purpose!=o.Purpose||ad.Policy.Jurisdiction!=bd.Policy.Jurisdiction{return PathImpactReport{},errors.New("exact same policy scope required")}
 var base,replacement *revocation.EvidenceSet
 if o.Evidence!=nil{base,err=o.Evidence.Load(o.Point.KnownAt);if err!=nil{return PathImpactReport{},err}}
 if o.NextEvidence!=nil{
  if o.NextEvidence==o.Evidence{replacement=base}else{replacement,err=o.NextEvidence.Load(o.Point.KnownAt);if err!=nil{return PathImpactReport{},err}}
 }
 run:=func(v *Loaded,r Report,set *revocation.EvidenceSet)(PathImpactState,error){
  var state PathImpactState
  d,err:=v.Policy(o.PolicyID,o.PolicyVersion);if err!=nil{return state,err}
  err=v.withStore(func(s *registry.Store)error{
   if set==nil{
    local,e:=validation.VerifyLocalPath(s,d,input,o.Purpose,o.DNSName,o.Point.At,o.Point.KnownAt);if e!=nil{return e}
    state,e=summarizeImpact(local,nil,r,o.Point,leaf.FingerprintSHA256);return e
   }
   report,e:=validation.VerifyLocalPathWithEvidence(s,d,input,o.Purpose,o.DNSName,o.Point.At,o.Point.KnownAt,set);if e!=nil{return e}
   state,e=summarizeImpact(report.LocalPathReport,&report.Revocation,r,o.Point,leaf.FingerprintSHA256);return e
  })
  return state,err
 }
 before,err:=run(a,ar,base);if err!=nil{return PathImpactReport{},err}
 after,err:=run(b,br,base);if err!=nil{return PathImpactReport{},err}
 result:=PathImpactReport{SchemaVersion:"1",Kind:"LOCAL_CERTIFICATE_PATH_IMPACT",LeafSHA256:leaf.FingerprintSHA256,PolicyID:o.PolicyID,PolicyVersion:o.PolicyVersion,Purpose:o.Purpose,Jurisdiction:ad.Policy.Jurisdiction,Point:o.Point,Previous:before,Next:after,SnapshotImpact:impactDelta("SAME_EVIDENCE_DIFFERENT_SNAPSHOT",before,after),ReevaluateAffectedPaths:true,BusinessPurposeStatus:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
 if replacement!=nil{
  changed,err:=run(b,br,replacement);if err!=nil{return PathImpactReport{},err}
  result.NextWithReplacementEvidence=&changed
  delta:=impactDelta("SAME_SNAPSHOT_DIFFERENT_EVIDENCE",after,changed);result.EvidenceImpact=&delta
 }
 raw,err:=canonical(result);if err!=nil{return PathImpactReport{},err}
 if len(raw)>MaxPathImpactReportBytes{return PathImpactReport{},errors.New("path impact report size limit")}
 return result,nil
}
