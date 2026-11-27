package sources

import(
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/emmansun/gmsm/smx509"
)

const MaxBundlePlanBytes=512<<10

type BundleMember struct{
 Position int `json:"position"`
 Certificate registry.CertificateRecord `json:"certificate"`
 MatchStatus string `json:"matchStatus"`
 MatchedListingID string `json:"matchedListingId,omitempty"`
 FingerprintEvidence *FingerprintEvidence `json:"fingerprintEvidence,omitempty"`
}
type BundlePlan struct{
 SchemaVersion string `json:"schemaVersion"`
 Listing MultiCAEntry `json:"listing"`
 CatalogSHA256 string `json:"catalogSHA256"`
 OriginalSHA256 string `json:"originalSHA256"`
 Format string `json:"format"`
 RecordedAt time.Time `json:"recordedAt"`
 Members []BundleMember `json:"members"`
 TrustStatus string `json:"trustStatus"`
}
type BundleImportReport struct{
 PlanSHA256 string `json:"planSHA256"`
 OriginalSHA256 string `json:"originalSHA256"`
 Status string `json:"status"`
 Imports []registry.ImportResult `json:"imports"`
 TrustStatus string `json:"trustStatus"`
 ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}
func BundlePlanBytes(p BundlePlan)([]byte,error){
 raw,err:=json.Marshal(p);if err!=nil{return nil,err}
 raw=append(raw,'\n')
 if len(raw)>MaxBundlePlanBytes{return nil,errors.New("bundle plan size limit")}
 return raw,nil
}
func DecodeBundlePlan(raw []byte,pin string)(BundlePlan,error){
 var p BundlePlan
 if len(raw)==0||len(raw)>MaxBundlePlanBytes||!sha256Pattern.MatchString(pin)||intakeHash(raw)!=pin{return p,errors.New("bundle plan pin mismatch")}
 if err:=json.Unmarshal(raw,&p);err!=nil{return p,err}
 canonical,err:=BundlePlanBytes(p)
 if err!=nil||!bytes.Equal(raw,canonical)||p.SchemaVersion!="1"||!intakeTime(p.RecordedAt)||p.TrustStatus!="NOT_ESTABLISHED"||len(p.Members)==0||len(p.Members)>registry.MaxCertificateBundleMembers{return BundlePlan{},errors.New("invalid canonical bundle plan")}
 return p,nil
}
func prepareBundle(c MultiCACatalog,id string,raw []byte,at time.Time)(BundlePlan,[]registry.BundleCertificate,error){
 if !intakeTime(at){return BundlePlan{},nil,errors.New("explicit UTC observation time required")}
 if err:=c.Validate();err!=nil{return BundlePlan{},nil,err}
 listing,err:=c.Find(id);if err!=nil{return BundlePlan{},nil,err}
 // A direct name lead must be observed on the official page and have an
 // exact published digest. Indexed-only or related-policy leads are not
 // sufficient for this direct intake profile.
 direct:=listing.Kind=="CERTIFICATE_NAME_LEAD"
 if listing.SourceStatus!="OFFICIAL_PAGE_OBSERVED"||
  (listing.Kind!="CHAIN_LISTING"&&(!direct||listing.PublishedSHA256==nil)){
  return BundlePlan{},nil,errors.New("observed chain listing or observed exact-fingerprint certificate lead required")
 }
 if direct&&len(raw)>registry.MaxCertificateInput{return BundlePlan{},nil,errors.New("single certificate input size limit")}
 cb,err:=json.Marshal(c);if err!=nil{return BundlePlan{},nil,err}
 format,members,err:=registry.ParseCertificateBundle(raw);if err!=nil{return BundlePlan{},nil,err}
 if direct{
  // A direct lead is not a chain listing: no extra CA, PKCS#7 wrapper,
  // or other member can be attributed to the selected name.
  if len(members)!=1||(format!="SINGLE_DER"&&format!="PEM_CERTIFICATES"){
   return BundlePlan{},nil,errors.New("direct certificate lead requires one DER or CERTIFICATE PEM")
  }
  if _,err:=auditMultiCA(c,id,raw);err!=nil{return BundlePlan{},nil,err}
 }
 p:=BundlePlan{SchemaVersion:"1",Listing:listing,CatalogSHA256:intakeHash(cb),OriginalSHA256:intakeHash(raw),Format:format,RecordedAt:at,Members:[]BundleMember{},TrustStatus:"NOT_ESTABLISHED"}
 for i,m:=range members{
  row:=BundleMember{Position:i+1,Certificate:m.Certificate,MatchStatus:"UNMATCHED_RESEARCH_CANDIDATE"}
  for _,e:=range c.Entries{
   if e.PublishedSHA256==nil||e.PublishedSHA256.Fingerprint!=m.Certificate.FingerprintSHA256{continue}
   cert,err:=smx509.ParseCertificate(m.DER);if err!=nil{return BundlePlan{},nil,err}
   if e.Authority!=listing.Authority||cert.Subject.CommonName!=e.Label||!cert.BasicConstraintsValid{
    row.MatchStatus="FINGERPRINT_LEAD_CONTEXT_MISMATCH";break
   }
   row.MatchStatus="MATCHED_PUBLISHED_LEAD"
   row.MatchedListingID=e.ID
   f:=*e.PublishedSHA256;row.FingerprintEvidence=&f
   break
  }
  if direct&&(row.MatchStatus!="MATCHED_PUBLISHED_LEAD"||row.MatchedListingID!=listing.ID){return BundlePlan{},nil,errors.New("direct certificate does not match selected listing")}
  p.Members=append(p.Members,row)
 }
 if _,err:=BundlePlanBytes(p);err!=nil{return BundlePlan{},nil,err}
 return p,members,nil
}
func PlanBundle(id string,raw []byte,at time.Time)(BundlePlan,error){
 c,err:=MultiCA();if err!=nil{return BundlePlan{},err}
 p,_,err:=prepareBundle(c,id,raw,at);return p,err
}
func verifyBundle(c MultiCACatalog,original,planBytes []byte,pin string)(BundlePlan,[]registry.BundleCertificate,error){
 p,err:=DecodeBundlePlan(planBytes,pin);if err!=nil{return BundlePlan{},nil,err}
 fresh,members,err:=prepareBundle(c,p.Listing.ID,original,p.RecordedAt);if err!=nil{return BundlePlan{},nil,err}
 canonical,err:=BundlePlanBytes(fresh)
 if err!=nil||!bytes.Equal(canonical,planBytes){return BundlePlan{},nil,errors.New("original bundle or catalog differs from reviewed plan")}
 return fresh,members,nil
}
// BundleArchiveFiles returns the exact private archive files to create in a
// fresh directory. Original and plan must be retained with extracted DER.
func BundleArchiveFiles(original,planBytes []byte,pin string)(map[string][]byte,error){
 c,err:=MultiCA();if err!=nil{return nil,err}
 _,members,err:=verifyBundle(c,original,planBytes,pin);if err!=nil{return nil,err}
 files:=map[string][]byte{"original.bin":bytes.Clone(original),"plan.json":bytes.Clone(planBytes)}
 for _,m:=range members{files[m.Certificate.FingerprintSHA256+".der"]=m.DER}
 return files,nil
}
func readBundleArchiveFile(dir,name string,limit int64)([]byte,error){
 path:=filepath.Join(dir,name)
 info,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !info.Mode().IsRegular()||info.Size()<=0||info.Size()>limit{return nil,errors.New("invalid archive file")}
 // All archive members have explicit, bounded names/sizes. Open identity
 // checks guard replacement between lstat and open.
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 opened,err:=f.Stat();if err!=nil||!opened.Mode().IsRegular()||!os.SameFile(info,opened){return nil,errors.New("archive file changed while opening")}
 raw,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
 if len(raw)==0||int64(len(raw))>limit{return nil,errors.New("archive file exceeds limit")}
 return raw,nil
}
func readVerifiedBundle(c MultiCACatalog,dir,pin string)(BundlePlan,[]registry.BundleCertificate,[]byte,error){
 st,err:=os.Lstat(dir);if err!=nil{return BundlePlan{},nil,nil,err}
 if !st.IsDir(){return BundlePlan{},nil,nil,errors.New("private bundle archive directory required")}
 raw,err:=readBundleArchiveFile(dir,"original.bin",registry.MaxCertificateBundleBytes);if err!=nil{return BundlePlan{},nil,nil,err}
 pb,err:=readBundleArchiveFile(dir,"plan.json",MaxBundlePlanBytes);if err!=nil{return BundlePlan{},nil,nil,err}
 p,members,err:=verifyBundle(c,raw,pb,pin);if err!=nil{return BundlePlan{},nil,nil,err}
 d,err:=os.Open(dir);if err!=nil{return BundlePlan{},nil,nil,err}
 entries,err:=d.ReadDir(registry.MaxCertificateBundleMembers+3);d.Close()
 if err!=nil&&err!=io.EOF{return BundlePlan{},nil,nil,err}
 if len(entries)!=len(members)+2{return BundlePlan{},nil,nil,errors.New("unexpected bundle archive membership")}
 allowed:=map[string]bool{"original.bin":true,"plan.json":true}
 for _,m:=range members{
  name:=m.Certificate.FingerprintSHA256+".der";allowed[name]=true
  der,err:=readBundleArchiveFile(dir,name,registry.MaxCertificateInput)
  if err!=nil||!bytes.Equal(der,m.DER){return BundlePlan{},nil,nil,errors.New("archive DER differs from original member")}
 }
 for _,e:=range entries{if !allowed[e.Name()]||!e.Type().IsRegular(){return BundlePlan{},nil,nil,errors.New("unexpected bundle archive entry")}}
 return p,members,raw,nil
}

// InspectBundleArchive validates the exact private archive and rederives
// provenance only for members eligible under the current source catalog.
// The original source and time are still unauthenticated assertions.
func InspectBundleArchive(dir,pin string)(BundlePlan,[]registry.ProvenanceRecord,error){
 c,err:=MultiCA();if err!=nil{return BundlePlan{},nil,err}
 return inspectBundleArchive(c,dir,pin)
}
func inspectBundleArchive(c MultiCACatalog,dir,pin string)(BundlePlan,[]registry.ProvenanceRecord,error){
 p,members,_,err:=readVerifiedBundle(c,dir,pin);if err!=nil{return BundlePlan{},nil,err}
 records:=[]registry.ProvenanceRecord{}
 for i,m:=range p.Members{
  if m.MatchStatus!="MATCHED_PUBLISHED_LEAD"{continue}
  _,prov,_,err:=registry.ImportCandidate(members[i].DER,p.Listing.SourceURL,p.RecordedAt);if err!=nil{return BundlePlan{},nil,err}
  prov.SourceFileSHA256=p.OriginalSHA256
  records=append(records,prov)
 }
 return p,records,nil
}
func applyBundleArchive(s *registry.Store,c MultiCACatalog,dir,pin string,selected []string)(BundleImportReport,error){
 if s==nil{return BundleImportReport{},errors.New("initialized store required")}
 p,members,raw,err:=readVerifiedBundle(c,dir,pin);if err!=nil{return BundleImportReport{},err}
 matches:=map[string]bool{}
 for _,m:=range p.Members{if m.MatchStatus=="MATCHED_PUBLISHED_LEAD"{matches[m.Certificate.FingerprintSHA256]=true}}
 if len(selected)==0||len(selected)>len(members){return BundleImportReport{},errors.New("explicit matched certificate selection required")}
 seen:=map[string]bool{}
 for _,fp:=range selected{
  if !matches[fp]||seen[fp]{return BundleImportReport{},fmt.Errorf("unmatched or duplicate selected certificate: %s",fp)}
  seen[fp]=true
 }
 imported,err:=s.ImportBundleCandidates(raw,p.Listing.SourceURL,p.RecordedAt,selected)
 report:=BundleImportReport{PlanSHA256:pin,OriginalSHA256:p.OriginalSHA256,Status:"INCOMPLETE_LOCAL_IMPORT",Imports:imported,TrustStatus:"NOT_ESTABLISHED"}
 if err!=nil{return report,err}
 report.Status="UNREVIEWED_BUNDLE_MEMBERS_IMPORTED"
 return report,nil
}
func ApplyBundleArchive(s *registry.Store,dir,pin string,selected []string)(BundleImportReport,error){
 c,err:=MultiCA();if err!=nil{return BundleImportReport{},err}
 return applyBundleArchive(s,c,dir,pin,selected)
}
