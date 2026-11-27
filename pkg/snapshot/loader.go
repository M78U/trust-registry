package snapshot

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/M78U/trust-registry/pkg/policy"
	"github.com/M78U/trust-registry/pkg/registry"
	"github.com/M78U/trust-registry/pkg/validation"
)

type policyKey struct{id string;version int}

// Loaded is a detached research view. It exposes no mutable Store and never
// grants production trust. Reopen with current time before a new session.
type Loaded struct {
	index *registry.Index
	payload []Payload
	policies map[policyKey][]byte
	loadedAt time.Time
}

// LoadResearch reauthenticates the latest accepted record, including current
// expiry, before constructing a read-only SDK view. No fallback to older data.
func LoadResearch(root string,o InstallationOptions)(*Loaded,InstallationReport,error){
	if o.Bootstrap{return nil,InstallationReport{},errors.New("load cannot bootstrap")}
	config,err:=configDigest(o);if err!=nil{return nil,InstallationReport{},err}
	var view *Loaded
	var result InstallationReport
	err=withInstallationLock(root,false,func(dir string)error{
		latest,_,err:=latestRecord(dir);if err!=nil{return err}
		if latest==""{return errors.New("no installed snapshot")}
		rec,err:=readInstalled(filepath.Join(dir,latest));if err!=nil{return err}
		auth,err:=authenticateInstalled(rec,config,o,o.At);if err!=nil{return err}
		var env Envelope
		if err:=json.Unmarshal(rec.Snapshot,&env);err!=nil{return err}
		v:=&Loaded{payload:env.Payload,policies:make(map[policyKey][]byte),loadedAt:o.At}
		for _,f:=range env.Payload{
			if strings.HasPrefix(f.Path,"policies/"){
				d,err:=policy.DecodeDocument(f.Data);if err!=nil{return err}
				v.policies[policyKey{d.Policy.ID,d.Policy.Version}]=f.Data
			}
		}
		if err:=v.withStore(func(s *registry.Store)error{
			var err error
			v.index,err=s.BuildIndex()
			return err
		});err!=nil{return err}
		view=v;result=reportInstalled("LOADED_RESEARCH_SNAPSHOT",rec,auth)
		return nil
	})
	if err!=nil{return nil,InstallationReport{},err}
	return view,result,nil
}

// withStore stages only already-authenticated inventory files into a private
// temporary directory. It is never exposed to callers.
func (v *Loaded) withStore(fn func(*registry.Store)error)error{
	if v==nil{return errors.New("loaded snapshot required")}
	dir,err:=os.MkdirTemp("","trust-registry-loaded-");if err!=nil{return err}
	defer os.RemoveAll(dir)
	for _,name:=range []string{"certificates","provenance"}{if err:=os.Mkdir(filepath.Join(dir,name),0700);err!=nil{return err}}
	for _,f:=range v.payload{
		if !filePattern.MatchString(f.Path){return errors.New("invalid loaded payload path")}
		if strings.HasPrefix(f.Path,"policies/"){continue}
		if err:=os.WriteFile(filepath.Join(dir,filepath.FromSlash(f.Path)),f.Data,0600);err!=nil{return err}
	}
	s,err:=registry.OpenStore(dir);if err!=nil{return err}
	return fn(s)
}
func (v *Loaded) Find(fp string)(registry.CertificateRecord,error){
	if v==nil||v.index==nil{return registry.CertificateRecord{},errors.New("loaded snapshot required")}
	return v.index.Find(fp)
}
func (v *Loaded) Search(q registry.Query)(registry.SearchResult,error){
	if v==nil||v.index==nil{return registry.SearchResult{},errors.New("loaded snapshot required")}
	return v.index.Search(q)
}
func (v *Loaded) Policy(id string,version int)(policy.Document,error){
	if v==nil||v.index==nil{return policy.Document{},errors.New("loaded snapshot required")}
	raw,ok:=v.policies[policyKey{id,version}]
	if !ok{return policy.Document{},errors.New("exact policy version not found")}
	return policy.DecodeDocument(raw)
}

// VerifyLocalPath uses the exact policy from the loaded snapshot, not an
// externally substituted policy. Historical knowledge cannot exceed load time.
func (v *Loaded) VerifyLocalPath(input []byte,id string,version int,purpose,dnsName string,at,knownAt time.Time)(validation.LocalPathReport,error){
	d,err:=v.Policy(id,version);if err!=nil{return validation.LocalPathReport{},err}
	if knownAt.After(v.loadedAt){return validation.LocalPathReport{},errors.New("knowledge time exceeds snapshot load time")}
	var report validation.LocalPathReport
	err=v.withStore(func(s *registry.Store)error{
		var err error
		report,err=validation.VerifyLocalPath(s,d,input,purpose,dnsName,at,knownAt)
		return err
	})
	if err!=nil{return validation.LocalPathReport{},err}
	return report,nil
}
