package registry

import (
	"errors"
	"path/filepath"
	"sort"
)

const MaxSnapshotFiles = 8192
const MaxSnapshotPayloadBytes = 32 << 20

// InventoryFile is a detached copy of a canonical inventory file. Names
// use forward slashes. Export does not approve redistribution or trust.
type InventoryFile struct {
	Path string
	Data []byte
}

// ExportInventory returns only validated CA material and source observations,
// never arbitrary files under the store root. The store must be controlled
// by the caller and not concurrently modified.
func (s *Store) ExportInventory() ([]InventoryFile,error){
	if s==nil{return nil,errors.New("inventory required")}
	certs,sources,err:=s.validatedInventory();if err!=nil{return nil,err}
	if len(certs)>MaxSnapshotFiles/2||len(sources)>MaxSnapshotFiles-2*len(certs){return nil,errors.New("snapshot file limit exceeded")}
	out:=make([]InventoryFile,0,2*len(certs)+len(sources))
	total:=0
	add:=func(path string,data []byte)error{
		if len(data)>MaxSnapshotPayloadBytes-total{return errors.New("snapshot payload limit exceeded")}
		total+=len(data);out=append(out,InventoryFile{path,data});return nil
	}
	for _,c:=range certs{
		fp:=c.FingerprintSHA256
		raw,err:=readRegular(filepath.Join(s.root,"certificates",fp+".der"),MaxCertificateInput);if err!=nil{return nil,err}
		if digest(raw)!=fp{return nil,errors.New("inventory changed during export")}
		meta,err:=canonicalJSON(c);if err!=nil{return nil,err}
		if err:=add("certificates/"+fp+".der",raw);err!=nil{return nil,err}
		if err:=add("certificates/"+fp+".json",meta);err!=nil{return nil,err}
	}
	for _,p:=range sources{
		raw,err:=canonicalJSON(p.Record);if err!=nil{return nil,err}
		if digest(raw)!=p.ID{return nil,errors.New("provenance content address mismatch")}
		if err:=add("provenance/"+p.ID+".json",raw);err!=nil{return nil,err}
	}
	sort.Slice(out,func(i,j int)bool{return out[i].Path<out[j].Path})
	return out,nil
}
