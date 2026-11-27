package registry

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

const DefaultSearchLimit = 100
const MaxSearchLimit = 1000

// Index is a read-only, in-memory view of an already validated local inventory.
// Build a new index after any change. It is not an authenticated release.
type Index struct {
	records map[string]CertificateRecord
	all []string
	postings map[string]map[string][]string
	sources map[string]ProvenanceEntry
	byCertificate map[string][]string
	report ValidationReport
}

const (
	fieldFingerprint = "fingerprint"
	fieldSubject = "subject"
	fieldIssuer = "issuer"
	fieldSerial = "serial"
	fieldSKI = "ski"
	fieldAKI = "aki"
	fieldKey = "key"
	fieldSignature = "signature"
	fieldHost = "sourceHost"
)

func (i *Index) add(field, value, fp string) {
	if value == "" { return }
	if i.postings[field] == nil { i.postings[field] = make(map[string][]string) }
	i.postings[field][value] = append(i.postings[field][value], fp)
}

// BuildIndex validates the entire inventory before constructing any query view.
func (s *Store) BuildIndex() (*Index, error) {
	if s == nil { return nil, errors.New("inventory required") }
	certs, sources, err := s.validatedInventory()
	if err != nil { return nil, err }
	i := &Index{records:make(map[string]CertificateRecord,len(certs)), all:make([]string,0,len(certs)), postings:make(map[string]map[string][]string), sources:make(map[string]ProvenanceEntry,len(sources)), byCertificate:make(map[string][]string), report:ValidationReport{len(certs),len(sources)}}
	for _, c := range certs {
		fp := c.FingerprintSHA256
		i.records[fp] = c
		i.all = append(i.all, fp)
		for field, value := range map[string]string{
			fieldFingerprint:fp, fieldSubject:c.Subject, fieldIssuer:c.Issuer,
			fieldSerial:c.SerialNumber, fieldSKI:c.SubjectKeyIdentifier, fieldAKI:c.AuthorityKeyIdentifier,
			fieldKey:c.PublicKeyAlgorithm, fieldSignature:c.SignatureAlgorithm,
		} { i.add(field,value,fp) }
	}
	// Multiple observations from one host must not duplicate a certificate.
	hosts := make(map[string]map[string]bool)
	for _, entry := range sources {
		fp := entry.Record.CertificateSHA256
		i.sources[entry.ID] = entry
		i.byCertificate[fp] = append(i.byCertificate[fp],entry.ID)
		u, err := url.Parse(entry.Record.SourceURL)
		if err != nil || u.Hostname() == "" { return nil, errors.New("invalid indexed source URL") }
		host := strings.ToLower(u.Hostname())
		if hosts[host] == nil { hosts[host] = make(map[string]bool) }
		if !hosts[host][fp] { i.add(fieldHost,host,fp); hosts[host][fp] = true }
	}
	for _, values := range i.postings { for _, list := range values { sort.Strings(list) } }
	for _, ids := range i.byCertificate { sort.Strings(ids) }
	return i,nil
}

func (i *Index) Report() (ValidationReport,error) {
	if i == nil || i.records == nil { return ValidationReport{},errors.New("validated index required") }
	return i.report,nil
}

func (i *Index) Find(fp string) (CertificateRecord,error) {
	if i == nil || i.records == nil || !validFingerprint(fp) { return CertificateRecord{},errors.New("validated index and lowercase SHA-256 required") }
	c,ok := i.records[fp]
	if !ok { return CertificateRecord{},errors.New("certificate not found") }
	return c,nil
}

// ProvenanceByID returns a copy of an unverified observation, not review evidence.
func (i *Index) ProvenanceByID(id string) (ProvenanceEntry,error) {
	if i == nil || i.records == nil || !validFingerprint(id) { return ProvenanceEntry{},errors.New("validated index and lowercase provenance SHA-256 required") }
	p,ok := i.sources[id]
	if !ok { return ProvenanceEntry{},errors.New("provenance not found") }
	p.Record.ReviewEvidence = append([]string{},p.Record.ReviewEvidence...)
	return p,nil
}

func (i *Index) Provenance(fp string) ([]ProvenanceEntry,error) {
	if _,err:=i.Find(fp);err!=nil { return nil,err }
	out:=make([]ProvenanceEntry,0,len(i.byCertificate[fp]))
	for _,id:=range i.byCertificate[fp] { p,err:=i.ProvenanceByID(id);if err!=nil{return nil,err};out=append(out,p) }
	return out,nil
}

// Query filters are exact and combined with AND. Hex identifiers use lowercase
// canonical storage spelling. DN strings are display search keys, not identities.
// SourceHost is the asserted URL hostname, not a verified CA organization.
type Query struct {
	Fingerprint string
	Subject string
	Issuer string
	Serial string
	SKI string
	AKI string
	PublicKeyAlgorithm string
	SignatureAlgorithm string
	SourceHost string
	After string
	Limit int
}

type SearchResult struct {
	TrustStatus string `json:"trustStatus"`
	Certificates []CertificateRecord `json:"certificates"`
	NextAfter string `json:"nextAfter,omitempty"`
}

func hexString(s string, even bool) bool {
	if s=="" { return true }
	if even && len(s)%2!=0 { return false }
	for _,c:=range s { if !strings.ContainsRune("0123456789abcdef",c) { return false } }
	return true
}

func (q Query) filters() (map[string]string,error) {
	if q.Fingerprint!="" && !validFingerprint(q.Fingerprint) || q.After!="" && !validFingerprint(q.After) { return nil,errors.New("invalid fingerprint or cursor") }
	if !hexString(q.SKI,true) || !hexString(q.AKI,true) || !hexString(q.Serial,false) || strings.HasPrefix(q.Serial,"0") { return nil,errors.New("invalid canonical hexadecimal search key") }
	host:=strings.ToLower(q.SourceHost)
	if strings.ContainsAny(host,"/\\?#@ \t\r\n") { return nil,errors.New("source-host must be a hostname, not a URL") }
	f:=map[string]string{fieldFingerprint:q.Fingerprint,fieldSubject:q.Subject,fieldIssuer:q.Issuer,fieldSerial:q.Serial,fieldSKI:q.SKI,fieldAKI:q.AKI,fieldKey:q.PublicKeyAlgorithm,fieldSignature:q.SignatureAlgorithm,fieldHost:host}
	for k,v:=range f {
		if len(v)>maxRecordBytes { return nil,fmt.Errorf("search key too long: %s",k) }
		if v=="" { delete(f,k) }
	}
	return f,nil
}

// Search selects the smallest posting list, intersects the remaining filters
// and returns a fingerprint-ordered page. The cursor is exclusive and only
// meaningful against the same inventory and filters.
func (i *Index) Search(q Query) (SearchResult,error) {
	if _,err:=i.Report();err!=nil { return SearchResult{},err }
	if q.Limit==0 { q.Limit=DefaultSearchLimit }
	if q.Limit<1 || q.Limit>MaxSearchLimit { return SearchResult{},errors.New("search limit must be between 1 and 1000") }
	f,err:=q.filters()
	if err!=nil { return SearchResult{},err }
	result:=SearchResult{TrustStatus:"NOT_ESTABLISHED",Certificates:make([]CertificateRecord,0)}
	candidates:=i.all
	for k,v:=range f { if list:=i.postings[k][v]; len(list)<len(candidates) { candidates=list } }
	start:=sort.Search(len(candidates),func(n int)bool{return candidates[n]>q.After})
	for _,fp:=range candidates[start:] {
		match:=true
		for k,v:=range f {
			list:=i.postings[k][v]
			pos:=sort.SearchStrings(list,fp)
			if pos==len(list) || list[pos]!=fp { match=false;break }
		}
		if !match { continue }
		if len(result.Certificates)==q.Limit {
			result.NextAfter=result.Certificates[len(result.Certificates)-1].FingerprintSHA256
			break
		}
		result.Certificates=append(result.Certificates,i.records[fp])
	}
	return result,nil
}

// issuerCandidates returns the union of display-name and SKI postings.
// Discovery must still check exact DER names and verify signatures.
func (i *Index) issuerCandidates(issuer,aki string) []CertificateRecord {
	set:=make(map[string]bool)
	// An empty DN is not indexed, so preserve completeness via fallback.
	if issuer=="" { for _,fp:=range i.all { if i.records[fp].Subject=="" { set[fp]=true } } }
	for _,fp:=range i.postings[fieldSubject][issuer] { set[fp]=true }
	if aki!="" { for _,fp:=range i.postings[fieldSKI][aki] { set[fp]=true } }
	fps:=make([]string,0,len(set))
	for fp:=range set { fps=append(fps,fp) }
	sort.Strings(fps)
	out:=make([]CertificateRecord,0,len(fps))
	for _,fp:=range fps { out=append(out,i.records[fp]) }
	return out
}

// MatchProvenance finds an exact canonical candidate observation in this
// validated index by its content address. No filesystem read or scan.
// It does not authenticate the asserted source or receipt time.
func(i *Index) MatchProvenance(record ProvenanceRecord)(string,bool,error){
 if _,err:=i.Report();err!=nil{return "",false,err}
 raw,err:=canonicalJSON(record);if err!=nil{return "",false,err}
 if len(raw)>maxRecordBytes{return "",false,errors.New("provenance too large")}
 id:=digest(raw)
 p,ok:=i.sources[id];if !ok{return "",false,nil}
 actual,err:=canonicalJSON(p.Record);if err!=nil{return "",false,err}
 if string(actual)!=string(raw){return "",false,errors.New("provenance content address conflict")}
 return id,true,nil
}
