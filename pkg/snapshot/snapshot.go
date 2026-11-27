// Package snapshot implements a deterministic, unsigned local research
// envelope. It is not a release authentication or update protocol.
package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/validation"
)

const MaxEnvelopeBytes = 48 << 20

var filePattern=regexp.MustCompile(`^(certificates/[a-f0-9]{64}\.(der|json)|(provenance|policies)/[a-f0-9]{64}\.json)$`)
var revisionPattern=regexp.MustCompile(`^[a-f0-9]{40}$`)
var hashPattern=regexp.MustCompile(`^[a-f0-9]{64}$`)

type Options struct {
	Sequence uint64
	SourceRevision string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type FileEntry struct {
	Path string `json:"path"`
	Size int `json:"size"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	SchemaVersion string `json:"schemaVersion"`
	Kind string `json:"kind"`
	Sequence uint64 `json:"sequence"`
	SourceRevision string `json:"sourceRevision"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Files []FileEntry `json:"files"`
}

type Payload struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type Envelope struct {
	Manifest Manifest `json:"manifest"`
	Payload []Payload `json:"payload"`
}

type Report struct {
	Manifest Manifest `json:"manifest"`
	ManifestSHA256 string `json:"manifestSHA256"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
	Validation validation.Report `json:"validation"`
	IntegrityStatus string `json:"integrityStatus"`
	ExpectedManifestMatched bool `json:"expectedManifestMatched"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	FreshnessStatus string `json:"freshnessStatus"`
	RollbackStatus string `json:"rollbackStatus"`
	TrustStatus string `json:"trustStatus"`
}

func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}
func canonical(v any)([]byte,error){b,err:=json.Marshal(v);if err!=nil{return nil,err};return append(b,'\n'),nil}
func utc(t time.Time)bool{return !t.IsZero()&&t.Location()==time.UTC&&t.Year()>=1&&t.Year()<=9999}

// ManifestBytes is the exact versioned byte representation intended for
// future signature metadata. This is Go struct-order JSON + LF, not JCS.
func ManifestBytes(m Manifest)([]byte,error){
	if err:=validateManifest(m);err!=nil{return nil,err}
	return canonical(m)
}

func validateManifest(m Manifest)error{
	if m.SchemaVersion!="1"||m.Kind!="LOCAL_RESEARCH_SNAPSHOT"||m.Sequence==0||!revisionPattern.MatchString(m.SourceRevision)||!utc(m.CreatedAt)||!utc(m.ExpiresAt)||!m.ExpiresAt.After(m.CreatedAt)||m.Files==nil||len(m.Files)>registry.MaxSnapshotFiles{return errors.New("invalid research manifest")}
	total:=0
	prev:=""
	for _,e:=range m.Files{
		if !filePattern.MatchString(e.Path)||e.Path<=prev||!hashPattern.MatchString(e.SHA256)||e.Size<=0||e.Size>registry.MaxSnapshotPayloadBytes-total{return errors.New("invalid, duplicate, unsorted or oversized manifest entry")}
		limit:=64<<10
		if strings.HasSuffix(e.Path,".der"){limit=registry.MaxCertificateInput}
		if strings.HasPrefix(e.Path,"policies/"){limit=policy.MaxDocumentBytes}
		if e.Size>limit{return errors.New("manifest file size exceeds type limit")}
		if strings.HasSuffix(e.Path,".der")||!strings.HasPrefix(e.Path,"certificates/"){
			name:=strings.TrimSuffix(filepath.Base(e.Path),filepath.Ext(e.Path))
			if name!=e.SHA256{return errors.New("manifest content address mismatch")}
		}
		prev=e.Path;total+=e.Size
	}
	return nil
}

// Build exports only explicit local CA inventory and supplied policy documents.
// It revalidates the exact serialized payload before returning. Input policies
// are preserved in their supplied array order; document ordering is irrelevant.
func Build(s *registry.Store,docs []policy.Document,o Options)([]byte,Report,error){
	m:=Manifest{SchemaVersion:"1",Kind:"LOCAL_RESEARCH_SNAPSHOT",Sequence:o.Sequence,SourceRevision:o.SourceRevision,CreatedAt:o.CreatedAt,ExpiresAt:o.ExpiresAt,Files:[]FileEntry{}}
	if err:=validateManifest(m);err!=nil{return nil,Report{},err}
	if len(docs)>validation.MaxPolicyDocuments{return nil,Report{},errors.New("policy document limit exceeded")}
	if _,err:=validation.Validate(s,docs);err!=nil{return nil,Report{},err}
	inventory,err:=s.ExportInventory();if err!=nil{return nil,Report{},err}
	if len(inventory)+len(docs)>registry.MaxSnapshotFiles{return nil,Report{},errors.New("snapshot file limit exceeded")}
	payload:=make([]Payload,0,len(inventory)+len(docs))
	total:=0
	for _,f:=range inventory{total+=len(f.Data);payload=append(payload,Payload{f.Path,f.Data})}
	for _,d:=range docs{
		raw,err:=canonical(d);if err!=nil{return nil,Report{},err}
		if len(raw)>policy.MaxDocumentBytes||len(raw)>registry.MaxSnapshotPayloadBytes-total{return nil,Report{},errors.New("snapshot policy payload limit exceeded")}
		total+=len(raw)
		payload=append(payload,Payload{"policies/"+digest(raw)+".json",raw})
	}
	sort.Slice(payload,func(i,j int)bool{return payload[i].Path<payload[j].Path})
	for _,f:=range payload{m.Files=append(m.Files,FileEntry{f.Path,len(f.Data),digest(f.Data)})}
	if err:=validateManifest(m);err!=nil{return nil,Report{},err}
	raw,err:=canonical(Envelope{m,payload});if err!=nil{return nil,Report{},err}
	report,err:=Verify(raw,"");if err!=nil{return nil,Report{},err}
	return raw,report,nil
}

// Verify checks canonical envelope bytes, exact manifest membership, hashes,
// and complete inventory/policy semantics. A caller-pinned manifest digest
// is only an equality check. No signature, expiry or rollback is established.
func Verify(raw []byte,expectedManifestSHA256 string)(Report,error){
	if len(raw)==0||len(raw)>MaxEnvelopeBytes{return Report{},errors.New("invalid snapshot envelope size")}
	if expectedManifestSHA256!=""&&!hashPattern.MatchString(expectedManifestSHA256){return Report{},errors.New("expected lowercase manifest SHA-256")}
	var e Envelope
	if err:=json.Unmarshal(raw,&e);err!=nil{return Report{},err}
	if err:=validateManifest(e.Manifest);err!=nil{return Report{},err}
	if e.Payload==nil||len(e.Payload)!=len(e.Manifest.Files){return Report{},errors.New("payload membership mismatch")}
	// Re-encoding equality rejects unknown, duplicate, omitted, differently
	// spelled fields, noncanonical base64/JSON and trailing content.
	encoded,err:=canonical(e);if err!=nil{return Report{},err}
	if !bytes.Equal(encoded,raw){return Report{},errors.New("noncanonical snapshot envelope")}
	mb,err:=ManifestBytes(e.Manifest);if err!=nil{return Report{},err}
	mh:=digest(mb)
	if expectedManifestSHA256!=""&&mh!=expectedManifestSHA256{return Report{},errors.New("manifest pin mismatch")}
	docs:=make([]policy.Document,0)
	for i,f:=range e.Payload{
		entry:=e.Manifest.Files[i]
		if f.Path!=entry.Path||len(f.Data)!=entry.Size||digest(f.Data)!=entry.SHA256{return Report{},fmt.Errorf("payload hash, size or path mismatch: %s",entry.Path)}
		if strings.HasPrefix(f.Path,"policies/"){
			if len(docs)>=validation.MaxPolicyDocuments{return Report{},errors.New("policy count limit exceeded")}
			d,err:=policy.DecodeDocument(f.Data);if err!=nil{return Report{},err}
			p,err:=canonical(d);if err!=nil||!bytes.Equal(p,f.Data){return Report{},errors.New("noncanonical policy payload")}
			docs=append(docs,d)
		}
	}
	// Stage only validated fixed-pattern filenames in a newly owned temp
	// directory. No extraction into caller directories or archives.
	dir,err:=os.MkdirTemp("","trust-registry-snapshot-");if err!=nil{return Report{},err}
	defer os.RemoveAll(dir)
	for _,name:=range []string{"certificates","provenance"}{if err:=os.Mkdir(filepath.Join(dir,name),0700);err!=nil{return Report{},err}}
	for _,f:=range e.Payload{
		if strings.HasPrefix(f.Path,"policies/"){continue}
		if err:=os.WriteFile(filepath.Join(dir,filepath.FromSlash(f.Path)),f.Data,0600);err!=nil{return Report{},err}
	}
	store,err:=registry.OpenStore(dir);if err!=nil{return Report{},err}
	result,err:=validation.Validate(store,docs);if err!=nil{return Report{},err}
	return Report{Manifest:e.Manifest,ManifestSHA256:mh,SnapshotSHA256:digest(raw),Validation:result,IntegrityStatus:"VERIFIED_INTERNAL_CONSISTENCY",ExpectedManifestMatched:expectedManifestSHA256!="",FreshnessStatus:"NOT_CHECKED",RollbackStatus:"NOT_CHECKED",TrustStatus:"NOT_ESTABLISHED"},nil
}
