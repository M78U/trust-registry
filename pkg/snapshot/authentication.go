package snapshot

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

const MaxResearchKeys = 16
const MaxSignatureBytes = 4096
const signatureDomain = "M78U Trust Registry local research snapshot signature v1\x00"

type Signature struct {
	SchemaVersion string `json:"schemaVersion"`
	KeyID string `json:"keyId"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
	Signature []byte `json:"signature"`
}

type Checkpoint struct {
	Sequence uint64 `json:"sequence"`
	SnapshotSHA256 string `json:"snapshotSHA256"`
}

type ResearchAuthentication struct {
	Report Report `json:"report"`
	ResearchSignatureStatus string `json:"researchSignatureStatus"`
	VerifiedKeyIDs []string `json:"verifiedKeyIds"`
	Threshold int `json:"threshold"`
	TemporalStatus string `json:"temporalStatus"`
	CheckpointStatus string `json:"checkpointStatus"`
	NextCheckpoint Checkpoint `json:"nextCheckpoint"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	TrustStatus string `json:"trustStatus"`
}

func KeyID(key ed25519.PublicKey)(string,error){
	if len(key)!=ed25519.PublicKeySize{return "",errors.New("invalid Ed25519 public key length")}
	return digest(key),nil
}

func signatureMessage(raw []byte)[]byte{
	return []byte(signatureDomain+digest(raw))
}

// SignResearch signs a fully validated local envelope. No keys are generated
// or stored by this function; no release authorization is implied.
func SignResearch(raw []byte,key ed25519.PrivateKey)(Signature,error){
	if len(key)!=ed25519.PrivateKeySize{return Signature{},errors.New("invalid Ed25519 private key length")}
	// Reject inconsistent seed/public-key suffix.
	if !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()),key){return Signature{},errors.New("inconsistent Ed25519 private key")}
	if _,err:=Verify(raw,"");err!=nil{return Signature{},err}
	id,err:=KeyID(key.Public().(ed25519.PublicKey));if err!=nil{return Signature{},err}
	return Signature{"1",id,digest(raw),ed25519.Sign(key,signatureMessage(raw))},nil
}

func validSignature(s Signature)bool{
	return s.SchemaVersion=="1"&&hashPattern.MatchString(s.KeyID)&&hashPattern.MatchString(s.SnapshotSHA256)&&len(s.Signature)==ed25519.SignatureSize
}
func SignatureBytes(s Signature)([]byte,error){
	if !validSignature(s){return nil,errors.New("invalid research signature")}
	return canonical(s)
}
func DecodeSignature(raw []byte)(Signature,error){
	var s Signature
	if len(raw)==0||len(raw)>MaxSignatureBytes{return s,errors.New("invalid signature file size")}
	if err:=json.Unmarshal(raw,&s);err!=nil{return s,err}
	expected,err:=SignatureBytes(s)
	if err!=nil||!bytes.Equal(raw,expected){return Signature{},errors.New("invalid or noncanonical signature")}
	return s,nil
}

// AuthenticateResearch verifies detached signatures under independently
// supplied keys, never keys from a snapshot. The caller must protect and
// persist the checkpoint and supply a reliable current time. A nil checkpoint
// is an explicit bootstrap, NOT rollback protection. This is not TUF.
func AuthenticateResearch(raw []byte,sigs []Signature,keys []ed25519.PublicKey,threshold int,at time.Time,previous *Checkpoint)(ResearchAuthentication,error){
	if len(raw)==0||len(raw)>MaxEnvelopeBytes{return ResearchAuthentication{},errors.New("invalid snapshot size")}
	if !utc(at)||len(keys)==0||len(keys)>MaxResearchKeys||threshold<1||threshold>len(keys)||len(sigs)==0||len(sigs)>MaxResearchKeys{return ResearchAuthentication{},errors.New("invalid research verification configuration")}
	pinned:=map[string]ed25519.PublicKey{}
	for _,key:=range keys{
		id,err:=KeyID(key);if err!=nil{return ResearchAuthentication{},err}
		if _,exists:=pinned[id];exists{return ResearchAuthentication{},errors.New("duplicate pinned key")}
		pinned[id]=key
	}
	seen:=map[string]bool{}
	verified:=[]string{}
	msg:=signatureMessage(raw);hash:=digest(raw)
	for _,sig:=range sigs{
		if !validSignature(sig)||sig.SnapshotSHA256!=hash||seen[sig.KeyID]{return ResearchAuthentication{},errors.New("invalid, duplicate or mismatched signature")}
		seen[sig.KeyID]=true
		key,ok:=pinned[sig.KeyID]
		if !ok||!ed25519.Verify(key,msg,sig.Signature){return ResearchAuthentication{},errors.New("signature does not verify under pinned research key")}
		verified=append(verified,sig.KeyID)
	}
	if len(verified)<threshold{return ResearchAuthentication{},errors.New("research signature threshold not met")}
	report,err:=Verify(raw,"");if err!=nil{return ResearchAuthentication{},err}
	m:=report.Manifest
	if at.Before(m.CreatedAt)||!at.Before(m.ExpiresAt){return ResearchAuthentication{},errors.New("snapshot outside declared validity window")}
	state:="EXPLICIT_BOOTSTRAP_NO_ROLLBACK_CHECK"
	if previous!=nil{
		if previous.Sequence==0||!hashPattern.MatchString(previous.SnapshotSHA256){return ResearchAuthentication{},errors.New("invalid caller checkpoint")}
		if m.Sequence<previous.Sequence{return ResearchAuthentication{},errors.New("snapshot sequence rollback")}
		if m.Sequence==previous.Sequence&&hash!=previous.SnapshotSHA256{return ResearchAuthentication{},errors.New("same-sequence snapshot conflict")}
		state="MATCHED_OR_ADVANCED_CALLER_CHECKPOINT"
	}
	sort.Strings(verified)
	return ResearchAuthentication{Report:report,ResearchSignatureStatus:"VERIFIED_PINNED_KEYS",VerifiedKeyIDs:verified,Threshold:threshold,TemporalStatus:"WITHIN_DECLARED_WINDOW",CheckpointStatus:state,NextCheckpoint:Checkpoint{m.Sequence,hash},TrustStatus:"NOT_ESTABLISHED"},nil
}
