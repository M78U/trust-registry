package revocation

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
 "unicode"
 "unicode/utf8"

 "github.com/emmansun/gmsm/smx509"
)

const MaxStoredEvidence=32
const maxStoredRecordBytes=24<<20
var storedName=regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

// EvidenceRecord describes a local observation, not authenticated receipt or
// verified issuer evidence. The first observation is immutable.
type EvidenceRecord struct {
 SchemaVersion string `json:"schemaVersion"`
 Kind string `json:"kind"`
 SHA256 string `json:"sha256"`
 RecordedAt time.Time `json:"recordedAt"`
 Source string `json:"source"`
 DERBytes int `json:"derBytes"`
 AuthenticationStatus string `json:"authenticationStatus"`
}
type storedEvidence struct {
 Record EvidenceRecord `json:"record"`
 DER []byte `json:"der"`
}
type ImportResult struct {
 Record EvidenceRecord `json:"record"`
 AlreadyPresent bool `json:"alreadyPresent"`
}
type EvidenceStore struct{ root string }
type EvidenceSet struct{
 crls *CRLStore
 ocsp *OCSPStore
 cutoff time.Time
 records []EvidenceRecord
}

func OpenEvidenceStore(root string)(*EvidenceStore,error){
 if strings.TrimSpace(root)==""{return nil,errors.New("evidence directory required")}
 abs,err:=filepath.Abs(root);if err!=nil{return nil,err}
 return &EvidenceStore{abs},nil
}
// Init intentionally never resets an existing directory.
func(s *EvidenceStore)Init()error{
 if s==nil{return errors.New("evidence store required")}
 return os.Mkdir(s.root,0700)
}
func(s *EvidenceStore)lock()(func(),error){
 if s==nil{return nil,errors.New("evidence store required")}
 i,err:=os.Lstat(s.root);if err!=nil{return nil,err}
 if !i.IsDir(){return nil,errors.New("expected local evidence directory")}
 path:=filepath.Join(s.root,".lock")
 if err:=os.Mkdir(path,0700);err!=nil{return nil,fmt.Errorf("evidence store locked: %w",err)}
 return func(){_ = os.Remove(path)},nil
}
func validSource(v string)bool{
 return strings.TrimSpace(v)!=""&&len(v)<=512&&utf8.ValidString(v)&&strings.IndexFunc(v,unicode.IsControl)<0
}
func evidenceBytes(v storedEvidence)([]byte,error){
 b,err:=json.Marshal(v);if err!=nil{return nil,err}
 b=append(b,'\n');if len(b)>maxStoredRecordBytes{return nil,errors.New("stored evidence record too large")};return b,nil
}
func readStored(path string)(storedEvidence,error){
 i,err:=os.Lstat(path);if err!=nil{return storedEvidence{},err}
 if !i.Mode().IsRegular()||i.Size()>maxStoredRecordBytes{return storedEvidence{},errors.New("invalid stored evidence file")}
 f,err:=os.Open(path);if err!=nil{return storedEvidence{},err};defer f.Close()
 opened,err:=f.Stat();if err!=nil{return storedEvidence{},err}
 if !opened.Mode().IsRegular()||!os.SameFile(i,opened){return storedEvidence{},errors.New("evidence file changed")}
 b,err:=io.ReadAll(io.LimitReader(f,maxStoredRecordBytes+1));if err!=nil{return storedEvidence{},err}
 if len(b)>maxStoredRecordBytes{return storedEvidence{},errors.New("stored evidence too large")}
 var v storedEvidence
 if err:=json.Unmarshal(b,&v);err!=nil{return storedEvidence{},err}
 canonical,err:=evidenceBytes(v)
 r:=v.Record
 if err!=nil||!bytes.Equal(canonical,b)||r.SchemaVersion!="1"||r.AuthenticationStatus!="UNVERIFIED_LOCAL_OBSERVATION"||!validTime(r.RecordedAt)||!validSource(r.Source)||len(v.DER)==0||len(v.DER)!=r.DERBytes||r.SHA256!=fingerprint(v.DER)||filepath.Base(path)!=r.SHA256+".json"{return storedEvidence{},errors.New("invalid canonical stored evidence record")}
 return v,nil
}
type inventory struct{
 records []EvidenceRecord
 crls []*smx509.RevocationList
 ocsp []*ocspResponse
 crlBytes,ocspBytes,entries int
}
// add verifies the exact stored DER and aggregate budgets. Unsupported CRL
// profiles are preserved as candidates, then rejected by evidence evaluation.
func(i *inventory)add(v storedEvidence)error{
 if len(i.records)>=MaxStoredEvidence{return errors.New("evidence record limit")}
 r:=v.Record
 switch r.Kind{
 case "CRL":
  if len(i.crls)>=maxCRLs||len(v.DER)>maxBundle-i.crlBytes{return errors.New("stored CRL budget exceeded")}
  c,err:=smx509.ParseRevocationList(v.DER);if err!=nil{return err}
  if !bytes.Equal(c.Raw,v.DER)||len(c.RevokedCertificateEntries)>maxCRLEntries-i.entries{return errors.New("stored CRL entry or DER limit")}
  i.crlBytes+=len(v.DER);i.entries+=len(c.RevokedCertificateEntries);i.crls=append(i.crls,c)
 case "OCSP":
  if len(i.ocsp)>=MaxOCSPResponses||len(v.DER)>maxBundle-i.ocspBytes{return errors.New("stored OCSP budget exceeded")}
  c,err:=parseOCSP(v.DER);if err!=nil{return err}
  i.ocspBytes+=len(v.DER);i.ocsp=append(i.ocsp,c)
 default:return errors.New("unknown evidence kind")
 }
 i.records=append(i.records,r);return nil
}
func(s *EvidenceStore)scan()(inventory,error){
 f,err:=os.Open(s.root);if err!=nil{return inventory{},err};defer f.Close()
 entries,err:=f.ReadDir(MaxStoredEvidence+2);if err!=nil&&err!=io.EOF{return inventory{},err}
 if len(entries)>MaxStoredEvidence+1{return inventory{},errors.New("evidence directory entry limit")}
 sort.Slice(entries,func(i,j int)bool{return entries[i].Name()<entries[j].Name()})
 result:=inventory{records:[]EvidenceRecord{}}
 for _,e:=range entries{
  if e.Name()==".lock"&&e.IsDir(){continue}
  if !e.Type().IsRegular()||!storedName.MatchString(e.Name()){return inventory{},errors.New("unexpected evidence directory entry; inspect interrupted operation")}
  v,err:=readStored(filepath.Join(s.root,e.Name()));if err!=nil{return inventory{},err}
  if err:=result.add(v);err!=nil{return inventory{},err}
 }
 return result,nil
}
func(s *EvidenceStore)Import(kind string,raw []byte,recordedAt time.Time,source string)(ImportResult,error){
 if !validTime(recordedAt)||!validSource(source){return ImportResult{},errors.New("explicit UTC observation time and source label required")}
 var der []byte
 switch kind{
 case "CRL":
  cs,err:=LoadCRLBytes(raw);if err!=nil{return ImportResult{},err}
  if len(cs.lists)!=1{return ImportResult{},errors.New("import exactly one CRL")}
  der=bytes.Clone(cs.lists[0].Raw)
 case "OCSP":
  if _,err:=LoadOCSPBytes([][]byte{raw});err!=nil{return ImportResult{},err}
  der=bytes.Clone(raw)
 default:return ImportResult{},errors.New("kind must be CRL or OCSP")
 }
 rec:=EvidenceRecord{"1",kind,fingerprint(der),recordedAt,source,len(der),"UNVERIFIED_LOCAL_OBSERVATION"}
 unlock,err:=s.lock();if err!=nil{return ImportResult{},err};defer unlock()
 i,err:=s.scan();if err!=nil{return ImportResult{},err}
 for _,old:=range i.records{
  if old.SHA256==rec.SHA256{
   if old.Kind!=kind{return ImportResult{},errors.New("evidence type conflict")}
   return ImportResult{old,true},nil
  }
 }
 v:=storedEvidence{rec,der}
 if err:=i.add(v);err!=nil{return ImportResult{},err}
 data,err:=evidenceBytes(v);if err!=nil{return ImportResult{},err}
 f,err:=os.CreateTemp(s.root,".pending-");if err!=nil{return ImportResult{},err}
 defer os.Remove(f.Name())
 if _,err=f.Write(data);err==nil{err=f.Sync()}
 closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{return ImportResult{},err}
 if err:=os.Link(f.Name(),filepath.Join(s.root,rec.SHA256+".json"));err!=nil{return ImportResult{},err}
 return ImportResult{rec,false},nil
}
func(s *EvidenceStore)List()([]EvidenceRecord,error){
 unlock,err:=s.lock();if err!=nil{return nil,err};defer unlock()
 i,err:=s.scan();if err!=nil{return nil,err}
 return i.records,nil
}
// Load validates the entire store, then detaches only observations recorded
// no later than the explicit cutoff. Even hidden corrupt records fail closed.
func(s *EvidenceStore)Load(knownAt time.Time)(*EvidenceSet,error){
 if !validTime(knownAt){return nil,errors.New("explicit UTC knowledge cutoff required")}
 unlock,err:=s.lock();if err!=nil{return nil,err};defer unlock()
 i,err:=s.scan();if err!=nil{return nil,err}
 set:=&EvidenceSet{crls:&CRLStore{},ocsp:&OCSPStore{},cutoff:knownAt,records:[]EvidenceRecord{}}
 c,o:=0,0
 for _,r:=range i.records{
  if r.Kind=="CRL"{
   if !r.RecordedAt.After(knownAt){set.crls.lists=append(set.crls.lists,i.crls[c]);set.crls.fingerprints=append(set.crls.fingerprints,r.SHA256)}
   c++
  }else{
   if !r.RecordedAt.After(knownAt){set.ocsp.responses=append(set.ocsp.responses,i.ocsp[o]);set.ocsp.fingerprints=append(set.ocsp.fingerprints,r.SHA256)}
   o++
  }
  if !r.RecordedAt.After(knownAt){set.records=append(set.records,r)}
 }
 return set,nil
}
func(s *EvidenceSet)Records()[]EvidenceRecord{
 if s==nil{return nil}
 return append([]EvidenceRecord{},s.records...)
}
func(s *EvidenceSet)EvaluatePair(child,issuer []byte,at time.Time)(Report,error){
 if s==nil{return Report{},errors.New("loaded evidence set required")}
 return EvaluatePair(child,issuer,s.crls,s.ocsp,Options{At:at,KnownAt:s.cutoff})
}
