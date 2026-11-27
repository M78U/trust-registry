package sources

import (
	_ "embed"
	"encoding/json"
	"errors"
	"time"
)

//go:embed satl.json
var satlJSON []byte

type ProgramLead struct {
	ID string `json:"id"`
	Authority string `json:"authority"`
	Label string `json:"label"`
	MatchStatus string `json:"matchStatus"`
	CandidateListingID string `json:"candidateListingId,omitempty"`
}

type ProgramCatalog struct {
	SchemaVersion string `json:"schemaVersion"`
	ProgramID string `json:"programId"`
	ProgramName string `json:"programName"`
	ListingURL string `json:"listingURL"`
	StrategyURL string `json:"strategyURL"`
	ObservedOn string `json:"observedOn"`
	Coverage string `json:"coverage"`
	EvidenceStatus string `json:"evidenceStatus"`
	ProgramScope string `json:"programScope"`
	TrustStatus string `json:"trustStatus"`
	Entries []ProgramLead `json:"entries"`
}

// SATL exposes name-only research leads from indexed public program pages.
// It cannot confirm current membership or establish exact certificate identity.
func SATL()(ProgramCatalog,error){
	var c ProgramCatalog
	if err:=json.Unmarshal(satlJSON,&c);err!=nil{return ProgramCatalog{},err}
	if err:=c.Validate();err!=nil{return ProgramCatalog{},err}
	return c,nil
}
func (c ProgramCatalog) Validate()error{
	if c.SchemaVersion!="1"||c.ProgramID!="satl"||c.ProgramName!="Suwell Approved Trust List"||c.ListingURL!="https://satl.ofd.cn/list"||c.StrategyURL!="https://satl.ofd.cn/strategy"||c.Coverage!="SELECTED_INDEXED_PAGE_ROWS"||c.EvidenceStatus!="SEARCH_INDEXED_PAGE_ONLY"||c.ProgramScope!="DOCUMENT_SIGNING"||c.TrustStatus!="NOT_ESTABLISHED"||len(c.Entries)==0||len(c.Entries)>1000{return errors.New("invalid SATL research catalog")}
	if _,err:=time.Parse(time.DateOnly,c.ObservedOn);err!=nil{return err}
	sheca,err:=SHECA();if err!=nil{return err}
	seen:=map[string]bool{}
	for _,e:=range c.Entries{
		if !idPattern.MatchString(e.ID)||seen[e.ID]||e.Authority==""||e.Label==""||e.MatchStatus!="NAME_LEAD_ONLY"{return errors.New("invalid or duplicate SATL research lead")}
		if e.CandidateListingID!=""{
			candidate,err:=sheca.Find(e.CandidateListingID);if err!=nil||candidate.Label!=e.Label||e.Authority!="上海数字证书认证中心有限公司"{return errors.New("invalid name-only candidate reference")}
		}
		seen[e.ID]=true
	}
	return nil
}
