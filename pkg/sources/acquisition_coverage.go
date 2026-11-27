package sources

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/M78U/trust-registry/pkg/registry"
)

// AcquisitionTask describes a catalog row, not a verified source or a unique
// certificate. AcquisitionRoute is independent of local inventory coverage.
type AcquisitionTask struct {
	Authority string `json:"authority"`
	ListingID string `json:"listingId"`
	Label string `json:"label"`
	Track string `json:"track"`
	ListingURL string `json:"listingURL"`
	SourceStatus string `json:"sourceStatus"`
	DownloadURL string `json:"downloadURL,omitempty"`
	PublishedSHA1 string `json:"publishedSHA1,omitempty"`
	PublishedSHA256 *FingerprintEvidence `json:"publishedSHA256,omitempty"`
	AcquisitionRoute string `json:"acquisitionRoute"`
	ExpectedProvenanceURL string `json:"expectedProvenanceURL,omitempty"`
	InventoryStatus string `json:"inventoryStatus"`
	MatchingSourceAssertions int `json:"matchingSourceAssertions"`
	ArchiveStatus string `json:"archiveStatus"`
	RedistributionStatus string `json:"redistributionStatus"`
}

type AcquisitionCoverageCounts struct {
	ListingRows int `json:"listingRows"`
	ExactFingerprintRows int `json:"exactFingerprintRows"`
	MatchingInventoryRows int `json:"matchingInventoryRows"`
	MatchingSourceAssertionRows int `json:"matchingSourceAssertionRows"`
	MissingInventoryRows int `json:"missingInventoryRows"`
	NoExactFingerprintRows int `json:"noExactFingerprintRows"`
}

// AcquisitionCoverage reports a deterministic local research queue. Counts
// refer to catalog rows, not distinct certificates or authorized trust anchors.
type AcquisitionCoverage struct {
	SchemaVersion string `json:"schemaVersion"`
	SHECACatalogSHA256 string `json:"shecaCatalogSHA256"`
	EndpointsSHA256 string `json:"endpointsSHA256"`
	MultiCACatalogSHA256 string `json:"multiCACatalogSHA256"`
	Inventory registry.ValidationReport `json:"inventory"`
	Counts AcquisitionCoverageCounts `json:"counts"`
	RouteCounts map[string]int `json:"routeCounts"`
	Tasks []AcquisitionTask `json:"tasks"`
	SourceAuthentication string `json:"sourceAuthentication"`
	TrustStatus string `json:"trustStatus"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
}

func catalogDigest(v any)(string,error){
	raw,err:=json.Marshal(v)
	if err!=nil{return "",err}
	return intakeHash(raw),nil
}

// PlanAcquisitionCoverage builds one validated read-only local inventory index.
// No downloads, private archive reads, imports, or trust evaluation occur.
func PlanAcquisitionCoverage(s *registry.Store)(AcquisitionCoverage,error){
	if s==nil{return AcquisitionCoverage{},errors.New("initialized local registry required")}
	c,err:=SHECA();if err!=nil{return AcquisitionCoverage{},err}
	endpoints,err:=Endpoints();if err!=nil{return AcquisitionCoverage{},err}
	m,err:=MultiCA();if err!=nil{return AcquisitionCoverage{},err}
	i,err:=s.BuildIndex();if err!=nil{return AcquisitionCoverage{},err}
	return acquisitionCoverage(c,endpoints,m,i)
}

func acquisitionCoverage(c Catalog,endpoints []Endpoint,m MultiCACatalog,i *registry.Index)(AcquisitionCoverage,error){
	if err:=c.Validate();err!=nil{return AcquisitionCoverage{},err}
	if err:=m.Validate();err!=nil{return AcquisitionCoverage{},err}
	inventory,err:=i.Report();if err!=nil{return AcquisitionCoverage{},err}
	r:=AcquisitionCoverage{SchemaVersion:"1",Inventory:inventory,RouteCounts:map[string]int{},Tasks:[]AcquisitionTask{},SourceAuthentication:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
	r.SHECACatalogSHA256,err=catalogDigest(c);if err!=nil{return AcquisitionCoverage{},err}
	r.EndpointsSHA256,err=catalogDigest(endpoints);if err!=nil{return AcquisitionCoverage{},err}
	r.MultiCACatalogSHA256,err=catalogDigest(m);if err!=nil{return AcquisitionCoverage{},err}
	byID:=map[string]Endpoint{}
	for _,e:=range endpoints{
		if _,err:=c.Find(e.ListingID);err!=nil{return AcquisitionCoverage{},err}
		if _,ok:=byID[e.ListingID];ok{return AcquisitionCoverage{},errors.New("duplicate acquisition endpoint")}
		if e.PublishedSHA256!=nil&&!sha256Pattern.MatchString(e.PublishedSHA256.Fingerprint){return AcquisitionCoverage{},errors.New("invalid endpoint fingerprint")}
		byID[e.ListingID]=e
	}
	for _,e:=range c.Entries{
		t:=AcquisitionTask{Authority:"SHECA",ListingID:e.ID,Label:e.Label,Track:e.ResearchTrack,ListingURL:c.RepositoryURL,SourceStatus:"PUBLISHED_CATALOG_ROW",PublishedSHA1:e.PublishedSHA1,AcquisitionRoute:"RESEARCH_DOWNLOAD_ENDPOINT",RedistributionStatus:e.RedistributionStatus}
		if endpoint,ok:=byID[e.ID];ok{
			t.ListingURL=endpoint.ListingURL
			t.SourceStatus="OBSERVED_DOWNLOAD_ENDPOINT"
			t.DownloadURL=endpoint.DownloadURL
			t.PublishedSHA256=endpoint.PublishedSHA256
			t.ExpectedProvenanceURL=endpoint.DownloadURL
			t.AcquisitionRoute="EXPLICIT_LEGACY_ONLY_RESEARCH"
			if endpoint.PublishedSHA256!=nil{t.AcquisitionRoute="PINNED_ENDPOINT_ARCHIVE"}
		}
		r.Tasks=append(r.Tasks,t)
	}
	for _,e:=range m.Entries{
		t:=AcquisitionTask{Authority:e.Authority,ListingID:e.ID,Label:e.Label,Track:e.Track,ListingURL:e.SourceURL,SourceStatus:e.SourceStatus,PublishedSHA256:e.PublishedSHA256,RedistributionStatus:e.RedistributionStatus}
		switch{
		case e.Kind=="CHAIN_LISTING"&&e.SourceStatus=="OFFICIAL_PAGE_OBSERVED":
			t.AcquisitionRoute="MANUAL_CHAIN_BUNDLE_RESEARCH"
		case e.SourceStatus!="OFFICIAL_PAGE_OBSERVED":
			t.AcquisitionRoute="RESEARCH_OFFICIAL_SOURCE"
		case e.PublishedSHA256==nil:
			t.AcquisitionRoute="RESEARCH_EXACT_FINGERPRINT"
		default:
			t.AcquisitionRoute="PINNED_SINGLE_CERTIFICATE_ARCHIVE"
		}
		if e.PublishedSHA256!=nil{t.ExpectedProvenanceURL=e.SourceURL}
		r.Tasks=append(r.Tasks,t)
	}
	sort.Slice(r.Tasks,func(a,b int)bool{
		if r.Tasks[a].Authority!=r.Tasks[b].Authority{return r.Tasks[a].Authority<r.Tasks[b].Authority}
		return r.Tasks[a].ListingID<r.Tasks[b].ListingID
	})
	r.Counts.ListingRows=len(r.Tasks)
	for n:=range r.Tasks{
		t:=&r.Tasks[n]
		r.RouteCounts[t.AcquisitionRoute]++
		t.ArchiveStatus="NOT_CHECKED"
		t.InventoryStatus="NO_EXACT_FINGERPRINT_LEAD"
		if t.PublishedSHA256==nil{
			r.Counts.NoExactFingerprintRows++
			continue
		}
		r.Counts.ExactFingerprintRows++
		result,err:=i.Search(registry.Query{Fingerprint:t.PublishedSHA256.Fingerprint,Limit:1})
		if err!=nil{return AcquisitionCoverage{},err}
		t.InventoryStatus="EXACT_FINGERPRINT_NOT_IN_INVENTORY"
		if len(result.Certificates)==0{
			r.Counts.MissingInventoryRows++
			continue
		}
		// Exact fingerprint identifies a local DER record. It does not
		// prove that the source listing, SHA-1, name or track is authentic.
		r.Counts.MatchingInventoryRows++
		t.InventoryStatus="EXACT_FINGERPRINT_PRESENT"
		provenance,err:=i.Provenance(t.PublishedSHA256.Fingerprint)
		if err!=nil{return AcquisitionCoverage{},err}
		for _,p:=range provenance{
			if t.ExpectedProvenanceURL!=""&&p.Record.SourceURL==t.ExpectedProvenanceURL{
				t.MatchingSourceAssertions++
			}
		}
		if t.MatchingSourceAssertions>0{r.Counts.MatchingSourceAssertionRows++}
	}
	return r,nil
}
