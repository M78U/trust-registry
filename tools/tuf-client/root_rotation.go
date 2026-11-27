package tufclient

import (
 "bytes"
 "crypto/ed25519"
 "errors"
 "fmt"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/sigstore/sigstore/pkg/signature"
 "github.com/theupdateframework/go-tuf/v2/metadata"
 "github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

const MaxRootChain=33

type RootChainReport struct{
 InitialRootSHA256 string `json:"initialRootSHA256"`
 CurrentRootSHA256 string `json:"currentRootSHA256"`
 RootVersion int64 `json:"rootVersion"`
 RootSHA256 []string `json:"rootSHA256"`
 ExpiresAt time.Time `json:"expiresAt"`
 Status string `json:"status"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
 TrustStatus string `json:"trustStatus"`
}
type RotateRootOptions struct{
 Now time.Time
 Next RootOptions
 OldSigners []ed25519.PrivateKey
 // Explicit independent pin of the existing full chain's latest root.
 ExpectedCurrentSHA256 string
}

// strictRootProfile checks all key material, not just IDs. When authority is
// provided, require disjoint keys from the review authority for every root.
func strictRootProfile(root *metadata.Metadata[metadata.RootType],authority *review.Authority)error{
 if root==nil||root.Signed.Type!=metadata.ROOT||root.Signed.Version<1||!root.Signed.ConsistentSnapshot||len(root.Signed.Roles)!=4||len(root.Signed.Keys)>64||!validTime(root.Signed.Expires.UTC()){return errors.New("invalid four-role root profile")}
 seenIDs,seenKeys:=map[string]bool{},map[string]bool{}
 for _,role:=range roles{
  r:=root.Signed.Roles[role]
  if r==nil||r.Threshold<1||r.Threshold>len(r.KeyIDs)||len(r.KeyIDs)>16{return errors.New("invalid root role threshold")}
  for _,id:=range r.KeyIDs{
   k:=root.Signed.Keys[id]
   if k==nil||seenIDs[id]||k.Type!=metadata.KeyTypeEd25519||k.Scheme!=metadata.KeySchemeEd25519{return errors.New("invalid or reused root key")}
   expected,err:=k.ID();if err!=nil||expected!=id{return errors.New("root key identity mismatch")}
   pk,err:=k.ToPublicKey();if err!=nil{return err}
   pub,ok:=pk.(ed25519.PublicKey)
   if !ok||len(pub)!=ed25519.PublicKeySize||seenKeys[digest(pub)]{return errors.New("duplicate or invalid raw root key")}
   if authority!=nil{if err:=authority.RequireDisjointKey(pub);err!=nil{return err}}
   seenIDs[id]=true;seenKeys[digest(pub)]=true
  }
 }
 if len(seenIDs)!=len(root.Signed.Keys){return errors.New("unreferenced root keys")}
 return nil
}

// rootChain starts at the exact independently pinned v1 bytes and delegates
// each sequential old/new threshold check to go-tuf. Intermediate expiry is
// intentionally not checked, per TUF; final expiry is checked by the caller.
func rootChain(chain [][]byte,pin string,at time.Time)(*trustedmetadata.TrustedMetadata,RootChainReport,error){
 return validateRootChain(chain,pin,at,true)
}

// Only the root-update stage may traverse an expired current head.
func validateRootChain(chain [][]byte,pin string,at time.Time,requireCurrent bool)(*trustedmetadata.TrustedMetadata,RootChainReport,error){
 if !validTime(at)||!hashPattern.MatchString(pin)||len(chain)<1||len(chain)>MaxRootChain||digest(chain[0])!=pin{return nil,RootChainReport{},errors.New("invalid pinned root chain or time")}
 for _,v:=range chain{if len(v)==0||len(v)>maxRoot{return nil,RootChainReport{},errors.New("root metadata size limit")}}
 tr,err:=trustedmetadata.New(chain[0]);if err!=nil{return nil,RootChainReport{},err}
 tr.RefTime=at
 if tr.Root.Signed.Version!=1{return nil,RootChainReport{},errors.New("initial root must be version one")}
 if err:=strictRootProfile(tr.Root,nil);err!=nil{return nil,RootChainReport{},err}
 hashes:=[]string{pin}
 for i,raw:=range chain[1:]{
  root,err:=tr.UpdateRoot(raw);if err!=nil{return nil,RootChainReport{},err}
  if root.Signed.Version!=int64(i+2){return nil,RootChainReport{},errors.New("nonconsecutive root version")}
  if err:=strictRootProfile(root,nil);err!=nil{return nil,RootChainReport{},err}
  hashes=append(hashes,digest(raw))
 }
 if requireCurrent&&!tr.Root.Signed.Expires.After(at){return nil,RootChainReport{},errors.New("current root expired")}
 return tr,RootChainReport{InitialRootSHA256:pin,CurrentRootSHA256:hashes[len(hashes)-1],RootVersion:tr.Root.Signed.Version,RootSHA256:hashes,ExpiresAt:tr.Root.Signed.Expires.UTC(),Status:"PINNED_ROOT_CHAIN_VERIFIED",TrustStatus:"NOT_ESTABLISHED"},nil
}
func VerifyRootChain(chain [][]byte,pin string,at time.Time)(RootChainReport,error){
 _,r,err:=rootChain(chain,pin,at);return r,err
}

// RotateRoot creates a fresh next root with a new explicit four-role config.
// Old and new root thresholds are both required; overlapping authorized root
// signers sign only once. Old root must still be current for local creation.
func RotateRoot(chain [][]byte,pin string,o RotateRootOptions)([]byte,RootChainReport,error){
 tr,report,err:=rootChain(chain,pin,o.Now);if err!=nil{return nil,RootChainReport{},err}
 if len(chain)>=MaxRootChain||o.ExpectedCurrentSHA256!=report.CurrentRootSHA256||!o.Next.Expires.After(o.Now){return nil,RootChainReport{},errors.New("current head pin, chain capacity and future root expiry required")}
 next,err:=newRoot(o.Next);if err!=nil{return nil,RootChainReport{},err}
 next.Signed.Version=tr.Root.Signed.Version+1
 if err:=strictRootProfile(next,nil);err!=nil{return nil,RootChainReport{},err}
 if err:=signRole(next,tr.Root,metadata.ROOT,o.OldSigners);err!=nil{return nil,RootChainReport{},err}
 old:=map[string]bool{}
 for _,k:=range o.OldSigners{id,err:=signerID(k);if err!=nil{return nil,RootChainReport{},err};old[id]=true}
 role:=next.Signed.Roles[metadata.ROOT]
 allowed:=map[string]bool{};for _,id:=range role.KeyIDs{allowed[id]=true}
 seen:=map[string]bool{}
 if len(o.Next.Signers)<role.Threshold||len(o.Next.Signers)>16{return nil,RootChainReport{},errors.New("new root signer threshold")}
 for _,key:=range o.Next.Signers{
  id,err:=signerID(key);if err!=nil{return nil,RootChainReport{},err}
  if seen[id]||!allowed[id]{return nil,RootChainReport{},errors.New("duplicate or unauthorized new root signer")}
  seen[id]=true
  if old[id]{continue}
  signer,err:=signature.LoadED25519Signer(key);if err!=nil{return nil,RootChainReport{},err}
  if _,err:=next.Sign(signer);err!=nil{return nil,RootChainReport{},err}
 }
 if err:=next.VerifyDelegate(metadata.ROOT,next);err!=nil{return nil,RootChainReport{},err}
 raw,err:=next.ToBytes(false);if err!=nil{return nil,RootChainReport{},err}
 all:=append(append([][]byte{},chain...),raw)
 result,err:=VerifyRootChain(all,pin,o.Now);if err!=nil{return nil,RootChainReport{},err}
 return raw,result,nil
}

// BuildRotatedRepository produces a local research candidate under the
// verified current root. Keep every numbered root available for old clients.
// The separate reviewed ledger enforces its own approval and history gates.
func BuildRotatedRepository(chain [][]byte,pin string,raw []byte,o PublishOptions)(Repository,RootChainReport,error){
 report,err:=VerifyRootChain(chain,pin,o.Now);if err!=nil{return Repository{},RootChainReport{},err}
 if o.RootSHA256!=report.CurrentRootSHA256{return Repository{},RootChainReport{},errors.New("current root pin mismatch")}
 repo,err:=buildRepository(chain[len(chain)-1],raw,o,report.RootVersion);if err!=nil{return Repository{},RootChainReport{},err}
 for i,root:=range chain{repo.Files[fmt.Sprintf("metadata/%d.root.json",i+1)]=bytes.Clone(root)}
 return repo,report,nil
}

// VerifyRotatedRepository is an offline consumer inspection, independent
// of the signing keys and mutable network cache. Caller pins initial root
// and expected current root separately to detect a stale chain.
func VerifyRotatedRepository(chain [][]byte,pin,currentPin string,repo Repository,at time.Time)(Report,error){
 rr,err:=VerifyRootChain(chain,pin,at);if err!=nil{return Report{},err}
 if currentPin!=rr.CurrentRootSHA256||repo.RootSHA256!=currentPin||repo.Version<1||!hashPattern.MatchString(repo.TargetSHA256)||len(repo.Files)!=len(chain)+4{return Report{},errors.New("repository identity or root head mismatch")}
 for i,raw:=range chain{if !bytes.Equal(repo.Files[fmt.Sprintf("metadata/%d.root.json",i+1)],raw){return Report{},errors.New("repository root history mismatch")}}
 v:=evidence{SchemaVersion:"1",AcceptedAt:at,Sequence:uint64(repo.Version),SnapshotSHA256:repo.TargetSHA256,Root:chain[len(chain)-1],Timestamp:repo.Files["metadata/timestamp.json"],SnapshotMetadata:repo.Files[fmt.Sprintf("metadata/%d.snapshot.json",repo.Version)],Targets:repo.Files[fmt.Sprintf("metadata/%d.targets.json",repo.Version)],Snapshot:repo.Files["targets/"+repo.TargetSHA256+"."+TargetName]}
 report,err:=verifyEvidenceWithChain(v,pin,at,chain);if err!=nil{return Report{},err}
 report.ApplicationRollbackStatus="NOT_CHECKED_OFFLINE_ROOT_CHAIN_ONLY"
 return report,nil
}
