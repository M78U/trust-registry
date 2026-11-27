package sources

import (
 "errors"
 "fmt"
 "sort"
 "strings"

 "github.com/M78U/trust-registry/pkg/registry"
)

const MaxCoverageArchives=32
const MaxCoverageBundles=4

type AcquisitionArchiveReference struct{
 ListingID string
 SHA256 string
}
type AcquisitionBundleReference struct{
 Directory string
 SHA256 string
}
type AcquisitionArchiveOptions struct{
 ArchiveDir string
 Archives []AcquisitionArchiveReference
 Bundles []AcquisitionBundleReference
}
type ArchiveMemberCoverage struct{
 ListingID string `json:"listingId"`
 CertificateSHA256 string `json:"certificateSHA256"`
 ProvenanceID string `json:"provenanceId,omitempty"`
 Status string `json:"status"`
}
type PinnedArchiveLink struct{
 Kind string `json:"kind"`
 Authority string `json:"authority"`
 ListingID string `json:"listingId"`
 PinSHA256 string `json:"pinSHA256"`
 OriginalSHA256 string `json:"originalSHA256"`
 MemberCount int `json:"memberCount"`
 Members []ArchiveMemberCoverage `json:"members"`
 Status string `json:"status"`
}
type PinnedArchiveCoverage struct{
 Archives []PinnedArchiveLink `json:"archives"`
 CheckedArchives int `json:"checkedArchives"`
 MatchedArchives int `json:"matchedArchives"`
 MatchedProvenanceRecords int `json:"matchedProvenanceRecords"`
}

// Check only explicit independent references; never discover a pin from a
// file, enumerate archive directories (except existing exact bundle member
// validation), fetch, repair, or write. A bad selection fails the whole report.
func attachArchiveCoverage(r *AcquisitionCoverage,c Catalog,endpoints []Endpoint,m MultiCACatalog,i *registry.Index,o AcquisitionArchiveOptions)error{
 if len(o.Archives)>MaxCoverageArchives||len(o.Bundles)>MaxCoverageBundles||(len(o.Archives)>0)!=(strings.TrimSpace(o.ArchiveDir)!=""){return errors.New("invalid archive reference count or directory")}
 if len(o.Archives)==0&&len(o.Bundles)==0{return nil}
 refs:=append([]AcquisitionArchiveReference{},o.Archives...)
 bundles:=append([]AcquisitionBundleReference{},o.Bundles...)
 sort.Slice(refs,func(a,b int)bool{return refs[a].ListingID<refs[b].ListingID})
 sort.Slice(bundles,func(a,b int)bool{return bundles[a].SHA256<bundles[b].SHA256})
 last:=""
 for _,ref:=range refs{
  if !idPattern.MatchString(ref.ListingID)||!sha256Pattern.MatchString(ref.SHA256)||ref.ListingID==last{return errors.New("invalid or duplicate endpoint reference")}
  last=ref.ListingID
  e,err:=archiveEndpoint(endpoints,ref.ListingID);if err!=nil{return err}
  if e.PublishedSHA256==nil{return errors.New("coverage endpoint references require published SHA-256")}
 }
 last=""
 for _,ref:=range bundles{
  if !sha256Pattern.MatchString(ref.SHA256)||ref.SHA256==last||strings.TrimSpace(ref.Directory)==""{return errors.New("invalid or duplicate bundle reference")}
  last=ref.SHA256
 }
 tasks:=map[string]*AcquisitionTask{}
 for n:=range r.Tasks{t:=&r.Tasks[n];tasks[t.Authority+"/"+t.ListingID]=t}
 out:=&PinnedArchiveCoverage{Archives:[]PinnedArchiveLink{}}
 matched:=map[string]bool{}
 mark:=func(authority,id string,linked bool)error{
  t:=tasks[authority+"/"+id];if t==nil{return errors.New("archive listing absent from coverage catalog")}
  if linked{t.ArchiveStatus="PINNED_ARCHIVE_MATCHED_PROVENANCE"}else if t.ArchiveStatus=="NOT_CHECKED"{t.ArchiveStatus="PINNED_ARCHIVE_CHECKED"}
  return nil
 }
 addMember:=func(link *PinnedArchiveLink,id string,p registry.ProvenanceRecord)error{
  pid,ok,err:=i.MatchProvenance(p);if err!=nil{return err}
  member:=ArchiveMemberCoverage{ListingID:id,CertificateSHA256:p.CertificateSHA256,Status:"NO_EXACT_LOCAL_PROVENANCE"}
  if ok{member.ProvenanceID=pid;member.Status="EXACT_LOCAL_PROVENANCE_MATCH";matched[pid]=true;link.Status="MATCHED_LOCAL_PROVENANCE"}
  if err:=mark(link.Authority,id,ok);err!=nil{return err}
  link.Members=append(link.Members,member)
  return nil
 }
 finish:=func(link PinnedArchiveLink)error{
  if err:=mark(link.Authority,link.ListingID,link.Status=="MATCHED_LOCAL_PROVENANCE");err!=nil{return err}
  out.CheckedArchives++
  if link.Status=="MATCHED_LOCAL_PROVENANCE"{out.MatchedArchives++}
  out.Archives=append(out.Archives,link)
  return nil
 }
 for _,ref:=range refs{
  a,_,err:=readArchive(c,endpoints,o.ArchiveDir,ref.ListingID,ref.SHA256)
  if err!=nil{return fmt.Errorf("endpoint archive %s: %w",ref.ListingID,err)}
  p:=a.Report.Preview.Provenance
  link:=PinnedArchiveLink{Kind:"ENDPOINT_ARCHIVE",Authority:"SHECA",ListingID:ref.ListingID,PinSHA256:ref.SHA256,OriginalSHA256:p.SourceFileSHA256,MemberCount:1,Members:[]ArchiveMemberCoverage{},Status:"NO_EXACT_LOCAL_PROVENANCE"}
  if err:=addMember(&link,ref.ListingID,p);err!=nil{return err}
  if err:=finish(link);err!=nil{return err}
 }
 for _,ref:=range bundles{
  p,records,err:=inspectBundleArchive(m,ref.Directory,ref.SHA256)
  if err!=nil{return fmt.Errorf("bundle pin %s: %w",ref.SHA256,err)}
  link:=PinnedArchiveLink{Kind:"BUNDLE_PLAN",Authority:p.Listing.Authority,ListingID:p.Listing.ID,PinSHA256:ref.SHA256,OriginalSHA256:p.OriginalSHA256,MemberCount:len(p.Members),Members:[]ArchiveMemberCoverage{},Status:"NO_EXACT_LOCAL_PROVENANCE"}
  n:=0
  for _,member:=range p.Members{
   if member.MatchStatus!="MATCHED_PUBLISHED_LEAD"{continue}
   if n>=len(records)||records[n].CertificateSHA256!=member.Certificate.FingerprintSHA256{return errors.New("bundle provenance/member mismatch")}
   if err:=addMember(&link,member.MatchedListingID,records[n]);err!=nil{return err}
   n++
  }
  if n!=len(records){return errors.New("unexpected bundle provenance records")}
  if n==0{link.Status="NO_ELIGIBLE_MEMBERS"}
  if err:=finish(link);err!=nil{return err}
 }
 out.MatchedProvenanceRecords=len(matched)
 r.ArchiveCoverage=out
 return nil
}
