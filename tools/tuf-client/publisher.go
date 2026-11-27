package tufclient

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type RoleKeys struct {
	PublicKeys []ed25519.PublicKey
	Threshold int
}
type RootOptions struct {
	Expires time.Time
	Roles map[string]RoleKeys
	Signers []ed25519.PrivateKey
}
type PublishOptions struct {
	RootSHA256 string
	Version int64
	Now time.Time
	TargetsExpires time.Time
	SnapshotExpires time.Time
	TimestampExpires time.Time
	TargetsSigners []ed25519.PrivateKey
	SnapshotSigners []ed25519.PrivateKey
	TimestampSigners []ed25519.PrivateKey
}
type Repository struct {
	Files map[string][]byte
	RootSHA256 string
	TargetSHA256 string
	Version int64
}
var roles=[]string{metadata.ROOT,metadata.TARGETS,metadata.SNAPSHOT,metadata.TIMESTAMP}

func validTime(t time.Time)bool{return !t.IsZero()&&t.Location()==time.UTC&&t.Year()>=1&&t.Year()<=9999}
func signerID(key ed25519.PrivateKey)(string,error){
	if len(key)!=ed25519.PrivateKeySize||!bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()),key){return "",errors.New("invalid Ed25519 signing key")}
	k,err:=metadata.KeyFromPublicKey(key.Public());if err!=nil{return "",err}
	return k.ID()
}
func signRole[T metadata.Roles](m *metadata.Metadata[T],root *metadata.Metadata[metadata.RootType],role string,keys []ed25519.PrivateKey)error{
	r:=root.Signed.Roles[role]
	if r==nil||r.Threshold<1||len(keys)<r.Threshold||len(keys)>16{return errors.New("invalid role signer threshold")}
	allowed:=map[string]bool{}
	for _,id:=range r.KeyIDs{allowed[id]=true}
	byID:=map[string]ed25519.PrivateKey{}
	ids:=[]string{}
	for _,key:=range keys{
		id,err:=signerID(key);if err!=nil{return err}
		if !allowed[id]||byID[id]!=nil{return errors.New("duplicate or unauthorized role signer")}
		byID[id]=key;ids=append(ids,id)
	}
	sort.Strings(ids)
	for _,id:=range ids{
		s,err:=signature.LoadED25519Signer(byID[id]);if err!=nil{return err}
		if _,err:=m.Sign(s);err!=nil{return err}
	}
	return root.VerifyDelegate(role,m)
}

// CreateRoot creates version 1 only. Four roles must have distinct Ed25519
// public keys. Root private keys alone are needed for this operation.
func CreateRoot(o RootOptions)([]byte,error){
	if !validTime(o.Expires)||len(o.Roles)!=4{return nil,errors.New("explicit root expiration and four role configurations required")}
	root:=metadata.Root(o.Expires)
	seen:=map[string]bool{}
	for _,role:=range roles{
		r,ok:=o.Roles[role]
		if !ok||r.Threshold<1||r.Threshold>len(r.PublicKeys)||len(r.PublicKeys)>16{return nil,fmt.Errorf("invalid role configuration: %s",role)}
		root.Signed.Roles[role].Threshold=r.Threshold
		type entry struct{id string;key *metadata.Key}
		list:=[]entry{}
		for _,pub:=range r.PublicKeys{
			if len(pub)!=ed25519.PublicKeySize{return nil,errors.New("invalid role public key")}
			k,err:=metadata.KeyFromPublicKey(pub);if err!=nil{return nil,err}
			id,err:=k.ID();if err!=nil{return nil,err}
			if seen[id]{return nil,errors.New("role keys must be distinct")}
			seen[id]=true;list=append(list,entry{id,k})
		}
		sort.Slice(list,func(i,j int)bool{return list[i].id<list[j].id})
		for _,e:=range list{if err:=root.Signed.AddKey(e.key,role);err!=nil{return nil,err}}
	}
	if err:=signRole(root,root,metadata.ROOT,o.Signers);err!=nil{return nil,err}
	raw,err:=root.ToBytes(false)
	if err!=nil{return nil,err}
	if len(raw)>maxRoot{return nil,errors.New("root exceeds size limit")}
	return raw,nil
}

func metadataLink(version int64,raw []byte)*metadata.MetaFiles{
	m:=metadata.MetaFile(version)
	m.Length=int64(len(raw))
	sum:=sha256.Sum256(raw)
	m.Hashes=metadata.Hashes{"sha256":sum[:]}
	return m
}

// BuildRepository creates an offline research publication candidate from an
// independently pinned initial root and an exact validated local snapshot.
// No network, private key output, rotation, upload or release authorization.
func BuildRepository(rootBytes,raw []byte,o PublishOptions)(Repository,error){
	if len(rootBytes)==0||len(rootBytes)>maxRoot||!hashPattern.MatchString(o.RootSHA256)||digest(rootBytes)!=o.RootSHA256{return Repository{},errors.New("root pin mismatch")}
	if o.Version<1||!validTime(o.Now)||!validTime(o.TargetsExpires)||!validTime(o.SnapshotExpires)||!validTime(o.TimestampExpires)||!o.TimestampExpires.After(o.Now)||o.SnapshotExpires.Before(o.TimestampExpires)||o.TargetsExpires.Before(o.SnapshotExpires){return Repository{},errors.New("invalid metadata version or expiration ordering")}
	root,err:=metadata.Root().FromBytes(rootBytes);if err!=nil{return Repository{},err}
	if root.Signed.Version!=1||!root.Signed.ConsistentSnapshot||!root.Signed.Expires.After(o.Now)||root.Signed.Expires.Before(o.TargetsExpires){return Repository{},errors.New("only valid consistent-snapshot initial root supported")}
	if err:=root.VerifyDelegate(metadata.ROOT,root);err!=nil{return Repository{},err}
	report,err:=snapshot.Verify(raw,"");if err!=nil{return Repository{},err}
	if o.Now.Before(report.Manifest.CreatedAt)||!o.Now.Before(report.Manifest.ExpiresAt)||o.TargetsExpires.After(report.Manifest.ExpiresAt){return Repository{},errors.New("snapshot outside declared publication window")}
	if uint64(o.Version)!=report.Manifest.Sequence{return Repository{},errors.New("metadata version must match registry sequence")}
	targets:=metadata.Targets(o.TargetsExpires)
	targets.Signed.Version=o.Version
	target,err:=metadata.TargetFile().FromBytes(TargetName,raw,"sha256");if err!=nil{return Repository{},err}
	targets.Signed.Targets[TargetName]=target
	if err:=signRole(targets,root,metadata.TARGETS,o.TargetsSigners);err!=nil{return Repository{},err}
	targetBytes,err:=targets.ToBytes(false);if err!=nil{return Repository{},err}
	snap:=metadata.Snapshot(o.SnapshotExpires)
	snap.Signed.Version=o.Version
	snap.Signed.Meta["targets.json"]=metadataLink(o.Version,targetBytes)
	if err:=signRole(snap,root,metadata.SNAPSHOT,o.SnapshotSigners);err!=nil{return Repository{},err}
	snapBytes,err:=snap.ToBytes(false);if err!=nil{return Repository{},err}
	stamp:=metadata.Timestamp(o.TimestampExpires)
	stamp.Signed.Version=o.Version
	stamp.Signed.Meta["snapshot.json"]=metadataLink(o.Version,snapBytes)
	if err:=signRole(stamp,root,metadata.TIMESTAMP,o.TimestampSigners);err!=nil{return Repository{},err}
	stampBytes,err:=stamp.ToBytes(false);if err!=nil{return Repository{},err}
	if len(targetBytes)>5_000_000||len(snapBytes)>2_000_000||len(stampBytes)>16384{return Repository{},errors.New("metadata exceeds client limit")}
	h:=digest(raw)
	return Repository{Files:map[string][]byte{
		"metadata/1.root.json":bytes.Clone(rootBytes),
		fmt.Sprintf("metadata/%d.targets.json",o.Version):targetBytes,
		fmt.Sprintf("metadata/%d.snapshot.json",o.Version):snapBytes,
		"metadata/timestamp.json":stampBytes,
		"targets/"+h+"."+TargetName:bytes.Clone(raw),
	},RootSHA256:o.RootSHA256,TargetSHA256:h,Version:o.Version},nil
}
