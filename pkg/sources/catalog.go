// Package sources contains research listings, not trust policies or anchors.
package sources

import (
	"crypto/sha1"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/M78U/trust-registry/pkg/registry"
)

//go:embed sheca.json
var shecaJSON []byte

type Entry struct {
	ID string `json:"id"`
	Label string `json:"label"`
	PublishedRole string `json:"publishedRole"`
	PublishedStatus string `json:"publishedStatus"`
	PublishedSHA1 string `json:"publishedSHA1"`
	PublishedValidUntil string `json:"publishedValidUntil"`
	ResearchTrack string `json:"researchTrack"`
	RedistributionStatus string `json:"redistributionStatus"`
}

type Catalog struct {
	SchemaVersion string `json:"schemaVersion"`
	AuthorityID string `json:"authorityId"`
	AuthorityName string `json:"authorityName"`
	ObservedOn string `json:"observedOn"`
	RepositoryURL string `json:"repositoryURL"`
	Coverage string `json:"coverage"`
	Entries []Entry `json:"entries"`
}

var idPattern=regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
var sha1Pattern=regexp.MustCompile(`^[a-f0-9]{40}$`)
var sha256Pattern=regexp.MustCompile(`^[a-f0-9]{64}$`)

func SHECA() (Catalog,error) {
	var c Catalog
	if err:=json.Unmarshal(shecaJSON,&c);err!=nil{return Catalog{},err}
	if err:=c.Validate();err!=nil{return Catalog{},err}
	return c,nil
}

func (c Catalog) Validate() error {
	if c.SchemaVersion!="1" || c.AuthorityID!="cn.sheca" || c.AuthorityName=="" || c.RepositoryURL!="https://www.sheca.com/repository" || c.Coverage!="SELECTED_RESEARCH_ROWS" || len(c.Entries)==0 || len(c.Entries)>1000 {return errors.New("invalid SHECA research catalog")}
	if _,err:=time.Parse(time.DateOnly,c.ObservedOn);err!=nil{return err}
	ids:=map[string]bool{}
	hashes:=map[string]bool{}
	for _,e:=range c.Entries {
		if !idPattern.MatchString(e.ID)||ids[e.ID]||e.Label==""||!sha1Pattern.MatchString(e.PublishedSHA1)||hashes[e.PublishedSHA1]||e.RedistributionStatus!="NOT_REVIEWED" {return errors.New("invalid or duplicate research entry")}
		if e.PublishedRole!="ROOT"&&e.PublishedRole!="INTERMEDIATE"{return errors.New("invalid published role")}
		if e.PublishedStatus!="LISTED"&&e.PublishedStatus!="DISUSE"{return errors.New("invalid published status")}
		switch e.ResearchTrack {
		case "GENERAL_RESEARCH","SM2_RESEARCH","EVENT_RESEARCH","TIMESTAMP_RESEARCH","HISTORICAL_RESEARCH":
		default:return errors.New("invalid research track")
		}
		if _,err:=time.Parse(time.DateOnly,e.PublishedValidUntil);err!=nil{return err}
		ids[e.ID]=true;hashes[e.PublishedSHA1]=true
	}
	return nil
}

func (c Catalog) Find(id string)(Entry,error){
	for _,e:=range c.Entries{if e.ID==id{return e,nil}}
	return Entry{},errors.New("unknown source listing ID")
}

type IntakePreview struct {
	AuthorityID string `json:"authorityId"`
	RepositoryURL string `json:"repositoryURL"`
	Listing Entry `json:"listing"`
	Certificate registry.CertificateRecord `json:"certificate"`
	Provenance registry.ProvenanceRecord `json:"provenance"`
	ComputedSHA1 string `json:"computedSHA1"`
	PublishedSHA1Match bool `json:"publishedSHA1Match"`
	IndependentSHA256Status string `json:"independentSHA256Status"`
	TrustStatus string `json:"trustStatus"`
	Persisted bool `json:"persisted"`
}

// Preview compares local bytes with an issuer-published historical SHA-1
// listing. This is only a research cross-check, never authentication. The
// optional caller-supplied SHA-256 is also an assertion, not verified evidence.
// No file writes, network requests, trust promotion or redistribution.
func (c Catalog) Preview(id string,input []byte,expectedSHA256 string,at time.Time)(IntakePreview,error){
	if err:=c.Validate();err!=nil{return IntakePreview{},err}
	e,err:=c.Find(id);if err!=nil{return IntakePreview{},err}
	if expectedSHA256!=""&&!sha256Pattern.MatchString(expectedSHA256){return IntakePreview{},errors.New("expected lowercase SHA-256")}
	record,provenance,der,err:=registry.ImportCandidate(input,c.RepositoryURL,at)
	if err!=nil{return IntakePreview{},err}
	if !record.IsCA{return IntakePreview{},errors.New("research intake accepts CA certificates only")}
	// SHA-1 is deliberately restricted to comparing a legacy published label.
	sum:=sha1.Sum(der)
	actual:=hex.EncodeToString(sum[:])
	if actual!=e.PublishedSHA1{return IntakePreview{},fmt.Errorf("published SHA-1 mismatch for %s",id)}
	status:="NOT_SUPPLIED"
	if expectedSHA256!=""{
		if expectedSHA256!=record.FingerprintSHA256{return IntakePreview{},errors.New("supplied SHA-256 mismatch")}
		status="MATCHED_CALLER_ASSERTION"
	}
	return IntakePreview{c.AuthorityID,c.RepositoryURL,e,record,provenance,actual,true,status,"NOT_ESTABLISHED",false},nil
}
