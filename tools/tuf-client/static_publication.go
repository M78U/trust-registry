package tufclient

import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sort"
 "strings"
 "time"

 "github.com/M78U/trust-registry/pkg/review"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)

// Local conservative budgets, below Cloudflare's 20k free-plan file count.
// Never shard a signed snapshot or truncate history to fit these limits.
const MaxStaticAssetBytes=25<<20
const MaxStaticAssets=512
const MaxStaticTotalBytes=192<<20
const MaxStaticManifestBytes=256<<10
const timestampAsset="tuf/metadata/timestamp.json"
var immutableAsset=regexp.MustCompile(`^tuf/(metadata/[1-9][0-9]*\.(root|snapshot|targets)\.json|targets/[a-f0-9]{64}\.registry-snapshot\.json)$`)
var explorerAssets=[]string{"404.html","_headers","app.js","data.js","graph-model.js","graph.js","icon.svg","index.html","projection.js","robots.txt","style.css"}
const baseHeaders=`/*
  Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'
  Referrer-Policy: no-referrer
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Cache-Control: public, max-age=0, must-revalidate
  X-Robots-Tag: noindex, nofollow
`
const releaseHeaders=`
/tuf/metadata/*.root.json
  ! Cache-Control
  Cache-Control: public, max-age=31536000, immutable
/tuf/metadata/*.snapshot.json
  ! Cache-Control
  Cache-Control: public, max-age=31536000, immutable
/tuf/metadata/*.targets.json
  ! Cache-Control
  Cache-Control: public, max-age=31536000, immutable
/tuf/targets/*
  ! Cache-Control
  Cache-Control: public, max-age=31536000, immutable
/tuf/metadata/timestamp.json
  ! Cache-Control
  Cache-Control: no-store
`
type StaticFile struct{
 Path string `json:"path"`
 SHA256 string `json:"sha256"`
 Size int `json:"size"`
}
type StaticManifest struct{
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 InitialRootSHA256 string `json:"initialRootSHA256"`
 AuthoritySHA256 string `json:"authoritySHA256"`
 HeadSHA256 string `json:"headSHA256"`
 Sequence uint64 `json:"sequence"`
 TimestampExpires time.Time `json:"timestampExpires"`
 Files []StaticFile `json:"files"`
}
type StaticPlan struct{
 Manifest StaticManifest `json:"manifest"`
 ManifestSHA256 string `json:"manifestSHA256"`
 NewFiles int `json:"newFiles"`
 ChangedFiles int `json:"changedFiles"`
 UnchangedFiles int `json:"unchangedFiles"`
 UploadCandidateBytes int64 `json:"uploadCandidateBytes"`
 TotalBytes int64 `json:"totalBytes"`
 Status string `json:"status"`
 Deployed bool `json:"deployed"`
 TrustStatus string `json:"trustStatus"`
}
type StaticOptions struct{
 LedgerDir,InitialRootSHA256,ExpectedHeadSHA256 string
 Authority *review.Authority
 ExplorerDir string
 At time.Time
 First bool
 PreviousManifest []byte
 PreviousManifestSHA256 string
}
type staticAssets struct{
 files map[string][]byte
 total int64
}
func knownAsset(path string)bool{
 if path==timestampAsset||immutableAsset.MatchString(path){return true}
 for _,v:=range explorerAssets{if path==v{return true}}
 return false
}
func(a *staticAssets)add(path string,raw []byte)error{
 if !knownAsset(path)||len(raw)==0||len(raw)>MaxStaticAssetBytes{return fmt.Errorf("invalid or oversized static asset: %s",path)}
 if existing,ok:=a.files[path];ok{
  if !bytes.Equal(existing,raw){return fmt.Errorf("immutable asset collision: %s",path)}
  return nil
 }
 if len(a.files)>=MaxStaticAssets||int64(len(raw))>MaxStaticTotalBytes-a.total{return errors.New("static publication budget exceeded")}
 a.files[path]=bytes.Clone(raw);a.total+=int64(len(raw));return nil
}
func manifestBytes(m StaticManifest)([]byte,error){
 raw,err:=json.Marshal(m);if err!=nil{return nil,err};raw=append(raw,'\n')
 if len(raw)>MaxStaticManifestBytes{return nil,errors.New("static manifest too large")}
 return raw,nil
}
func StaticManifestBytes(m StaticManifest)([]byte,error){return manifestBytes(m)}
func DecodeStaticManifest(raw []byte,pin string)(StaticManifest,error){
 var m StaticManifest
 if len(raw)==0||len(raw)>MaxStaticManifestBytes||!hashPattern.MatchString(pin)||digest(raw)!=pin{return m,errors.New("independent static manifest pin mismatch")}
 if err:=json.Unmarshal(raw,&m);err!=nil{return m,err}
 canonical,err:=manifestBytes(m)
 if err!=nil||!bytes.Equal(canonical,raw)||m.SchemaVersion!="1"||m.Kind!="LOCAL_STATIC_PUBLICATION_MANIFEST"||!hashPattern.MatchString(m.InitialRootSHA256)||!hashPattern.MatchString(m.AuthoritySHA256)||!hashPattern.MatchString(m.HeadSHA256)||m.Sequence==0||!validTime(m.TimestampExpires)||len(m.Files)<len(explorerAssets)+5||len(m.Files)>MaxStaticAssets{return StaticManifest{},errors.New("invalid canonical static manifest")}
 last:="";total:=int64(0);seen:=map[string]bool{}
 for _,f:=range m.Files{
  if f.Path<=last||!knownAsset(f.Path)||!hashPattern.MatchString(f.SHA256)||f.Size<=0||f.Size>MaxStaticAssetBytes||int64(f.Size)>MaxStaticTotalBytes-total{return StaticManifest{},errors.New("invalid static manifest file")}
  last=f.Path;total+=int64(f.Size);seen[f.Path]=true
 }
 for _,v:=range explorerAssets{if !seen[v]{return StaticManifest{},errors.New("missing explorer asset")}}
 if !seen[timestampAsset]||!seen["tuf/metadata/1.root.json"]||!seen[fmt.Sprintf("tuf/metadata/%d.targets.json",m.Sequence)]||!seen[fmt.Sprintf("tuf/metadata/%d.snapshot.json",m.Sequence)]{return StaticManifest{},errors.New("missing current TUF metadata")}
 return m,nil
}
func readExplorer(dir string,a *staticAssets)error{
 if strings.TrimSpace(dir)==""{return errors.New("explicit built explorer directory required")}
 if err:=regularDir(dir);err!=nil{return err}
 f,err:=os.Open(dir);if err!=nil{return err};defer f.Close()
 entries,err:=f.ReadDir(len(explorerAssets)+1);if err!=nil&&err!=io.EOF{return err}
 if len(entries)!=len(explorerAssets){return errors.New("unexpected explorer file count")}
 for _,v:=range explorerAssets{
  raw,err:=readRegular(filepath.Join(dir,v),MaxStaticAssetBytes);if err!=nil{return err}
  if v=="_headers"{
   // Match the reviewed preview baseline exactly; do not accept extra
   // header rules that can override the release cache/security profile.
   if string(raw)!=baseHeaders{return errors.New("unexpected Explorer header baseline")}
   raw=[]byte(baseHeaders+releaseHeaders)
  }
  if err:=a.add(v,raw);err!=nil{return err}
 }
 return nil
}
func compareStatic(m StaticManifest,previous *StaticManifest)(StaticPlan,error){
 plan:=StaticPlan{Manifest:m,Status:"LOCAL_STATIC_PUBLICATION_CANDIDATE",TrustStatus:"NOT_ESTABLISHED"}
 old:=map[string]StaticFile{}
 if previous!=nil{
  if previous.InitialRootSHA256!=m.InitialRootSHA256||previous.AuthoritySHA256!=m.AuthoritySHA256||previous.Sequence>m.Sequence||previous.Sequence==m.Sequence&&previous.HeadSHA256!=m.HeadSHA256{return StaticPlan{},errors.New("static publication baseline rollback or identity mismatch")}
  for _,v:=range previous.Files{old[v.Path]=v}
 }
 for _,v:=range m.Files{
  plan.TotalBytes+=int64(v.Size)
  prior,ok:=old[v.Path]
  if !ok{plan.NewFiles++;plan.UploadCandidateBytes+=int64(v.Size)}else if prior!=v{
   if immutableAsset.MatchString(v.Path){return StaticPlan{},errors.New("previous immutable asset changed")}
   plan.ChangedFiles++;plan.UploadCandidateBytes+=int64(v.Size)
  }else{plan.UnchangedFiles++}
  delete(old,v.Path)
 }
 // All old files remain in this intentionally append-only profile.
 if len(old)!=0{return StaticPlan{},errors.New("previous deployment asset missing")}
 raw,err:=manifestBytes(m);if err!=nil{return StaticPlan{},err};plan.ManifestSHA256=digest(raw)
 return plan,nil
}
// PrepareStaticPublication re-verifies the entire pinned ledger under its
// existing lock and requires a public credential for every exported record.
// Historical credentials are checked at build time; only head is current.
func PrepareStaticPublication(o StaticOptions)(map[string][]byte,StaticPlan,error){
 if !validTime(o.At)||o.Authority==nil||!hashPattern.MatchString(o.ExpectedHeadSHA256)||!hashPattern.MatchString(o.InitialRootSHA256){return nil,StaticPlan{},errors.New("current UTC time, independent authority/root and ledger head pins required")}
 if o.First!=(len(o.PreviousManifest)==0)||o.First&&o.PreviousManifestSHA256!=""{return nil,StaticPlan{},errors.New("explicit first deployment or pinned prior manifest required")}
 var previous *StaticManifest
 if !o.First{v,err:=DecodeStaticManifest(o.PreviousManifest,o.PreviousManifestSHA256);if err!=nil{return nil,StaticPlan{},err};previous=&v}
 a:=staticAssets{files:map[string][]byte{}}
 if err:=readExplorer(o.ExplorerDir,&a);err!=nil{return nil,StaticPlan{},err}
 var plan StaticPlan
 err:=publicationLock(o.LedgerDir,false,func(dir string)error{
  head,err:=scanPublication(dir,o.InitialRootSHA256,o.Authority.SHA256(),o.ExpectedHeadSHA256,func(v publicationRecord)error{
   e:=v.Evidence
   tg,err:=metadata.Targets().FromBytes(e.Targets);if err!=nil{return err}
   sm,err:=metadata.Snapshot().FromBytes(e.SnapshotMetadata);if err!=nil{return err}
   ts,err:=metadata.Timestamp().FromBytes(e.Timestamp);if err!=nil{return err}
   info:=tg.Signed.Targets[TargetName]
   if _,err:=checkPublicCredential(o.Authority,evidenceChain(e),o.InitialRootSHA256,info,tg.Signed.Version,tg.Signed.Expires,sm.Signed.Expires,ts.Signed.Expires,e.AcceptedAt);err!=nil{return fmt.Errorf("sequence %d lacks verified public approval: %w",e.Sequence,err)}
   c,err:=decodeCredentialCustom(info.Custom);if err!=nil{return err}
   if c.ApprovalSHA256!=v.ApprovalSHA256||c.DossierSHA256!=v.DossierSHA256{return errors.New("ledger receipt and public approval differ")}
   for name,raw:=range repositoryFromRecord(v).Files{
    if name=="metadata/timestamp.json"{continue}
    if err:=a.add("tuf/"+name,raw);err!=nil{return err}
   }
   return nil
  })
  if err!=nil{return err}
  if head.record==nil{return errors.New("empty publication ledger")}
  e:=head.record.Evidence
  if _,err:=verifyEvidence(e,o.InitialRootSHA256,o.At);err!=nil{return err}
  ts,err:=metadata.Timestamp().FromBytes(e.Timestamp);if err!=nil{return err}
  if err:=a.add(timestampAsset,e.Timestamp);err!=nil{return err}
  m:=StaticManifest{SchemaVersion:"1",Kind:"LOCAL_STATIC_PUBLICATION_MANIFEST",InitialRootSHA256:o.InitialRootSHA256,AuthoritySHA256:o.Authority.SHA256(),HeadSHA256:head.hash,Sequence:e.Sequence,TimestampExpires:ts.Signed.Expires.UTC(),Files:[]StaticFile{}}
  for path,raw:=range a.files{m.Files=append(m.Files,StaticFile{path,digest(raw),len(raw)})}
  sort.Slice(m.Files,func(i,j int)bool{return m.Files[i].Path<m.Files[j].Path})
  plan,err=compareStatic(m,previous);return err
 })
 if err!=nil{return nil,StaticPlan{},err}
 return a.files,plan,nil
}

// VerifyStaticDirectory checks exact manifest membership and bytes, including
// headers, immediately before deployment. It is not a replacement for the
// cryptographic publication preparation or independent manifest pin.
func VerifyStaticDirectory(dir string,m StaticManifest,at time.Time)error{
 raw,err:=manifestBytes(m);if err!=nil{return err}
 if _,err:=DecodeStaticManifest(raw,digest(raw));err!=nil{return err}
 if !validTime(at)||!at.Before(m.TimestampExpires){return errors.New("static manifest timestamp expired")}
 if err:=regularDir(dir);err!=nil{return err}
 expected:=map[string]StaticFile{};for _,v:=range m.Files{expected[v.Path]=v}
 count:=0
 err=filepath.WalkDir(dir,func(path string,d os.DirEntry,err error)error{
  if err!=nil{return err}
  if path==dir{return nil}
  count++;if count>MaxStaticAssets+3{return errors.New("unexpected directory entry count")}
  rel,err:=filepath.Rel(dir,path);if err!=nil{return err};rel=filepath.ToSlash(rel)
  if d.IsDir(){
   if rel!="tuf"&&rel!="tuf/metadata"&&rel!="tuf/targets"{return errors.New("unexpected static directory")};return nil
  }
  v,ok:=expected[rel];if !ok||!d.Type().IsRegular(){return errors.New("unexpected static file")}
  raw,err:=readRegular(path,int64(v.Size));if err!=nil{return err}
  if len(raw)!=v.Size||digest(raw)!=v.SHA256{return errors.New("static asset hash mismatch")}
  delete(expected,rel);return nil
 })
 if err!=nil{return err};if len(expected)!=0{return errors.New("missing static files")}
 return nil
}
