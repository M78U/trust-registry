package sources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"time"
)

const MaxSourceBodyBytes = 2 << 20
const MaxSourceObservationBytes = 3 << 20

// MonitorSource is an explicit research URL, not an authenticated CA identity.
type MonitorSource struct {
	ID string `json:"id"`
	Authority string `json:"authority"`
	URL string `json:"url"`
	Kind string `json:"kind"`
}

// MonitorSources returns a fresh fixed allowlist, based on the existing research
// catalog. No discovered link, URL parameter, or caller-provided host is fetched.
func MonitorSources() []MonitorSource {
	return []MonitorSource{
		{"bjca-downloads", "BJCA", "https://www.bjca.cn/service/down_198.html", "CATALOG"},
		{"bjca-root-directory", "BJCA", "https://repo.bjca.cn/global/cert/", "CATALOG"},
		{"cfca-repository", "CFCA", "https://www.cfca.com.cn/zhengshuzizhu/", "CATALOG"},
		{"gdca-repository", "GDCA", "https://www.gdca.com.cn/customer_service/knowledge_universe/ca_cq/", "CATALOG"},
		{"satl-list", "SATL", "https://satl.ofd.cn/list", "PROGRAM_LIST"},
		{"satl-strategy", "SATL", "https://satl.ofd.cn/strategy", "PROGRAM_POLICY"},
		{"sheca-auxiliary", "SHECA", auxiliaryListing, "AUXILIARY_LISTING"},
		{"sheca-repository", "SHECA", "https://www.sheca.com/repository", "CATALOG"},
	}
}
func monitorSource(id string) (MonitorSource, error) {
	for _, s := range MonitorSources() {
		if s.ID == id { return s, nil }
	}
	return MonitorSource{}, errors.New("unknown monitored source ID")
}

type SourceObservation struct {
	SchemaVersion string `json:"schemaVersion"`
	Source MonitorSource `json:"source"`
	RecordedAt time.Time `json:"recordedAt"`
	Mode string `json:"mode"`
	MediaType string `json:"mediaType,omitempty"`
	BodySHA256 string `json:"bodySHA256"`
	BodyBytes int `json:"bodyBytes"`
	Raw []byte `json:"raw"`
	SourceAuthentication string `json:"sourceAuthentication"`
	TrustStatus string `json:"trustStatus"`
}
type SourceObservationReceipt struct {
	Source MonitorSource `json:"source"`
	RecordedAt time.Time `json:"recordedAt"`
	Mode string `json:"mode"`
	ObservationSHA256 string `json:"observationSHA256"`
	BodySHA256 string `json:"bodySHA256"`
	BodyBytes int `json:"bodyBytes"`
	SourceAuthentication string `json:"sourceAuthentication"`
	TrustStatus string `json:"trustStatus"`
}
func allowedSourceMediaType(s string) bool {
	return s == "text/html" || s == "application/xhtml+xml" || s == "text/plain"
}
func makeSourceObservation(id, mode, media string, raw []byte, at time.Time) ([]byte, SourceObservationReceipt, error) {
	s, err := monitorSource(id)
	if err != nil { return nil, SourceObservationReceipt{}, err }
	if !intakeTime(at) || len(raw) == 0 || len(raw) > MaxSourceBodyBytes ||
		!(mode == "LOCAL_INPUT" && media == "" || mode == "HTTPS_RESPONSE" && allowedSourceMediaType(media)) {
		return nil, SourceObservationReceipt{}, errors.New("invalid source observation bytes, mode, media type or UTC time")
	}
	o := SourceObservation{SchemaVersion:"1", Source:s, RecordedAt:at, Mode:mode, MediaType:media, BodySHA256:intakeHash(raw), BodyBytes:len(raw), Raw:raw, SourceAuthentication:"NOT_ESTABLISHED", TrustStatus:"NOT_ESTABLISHED"}
	b, err := json.Marshal(o)
	if err != nil { return nil, SourceObservationReceipt{}, err }
	b = append(b, '\n')
	if len(b) > MaxSourceObservationBytes { return nil, SourceObservationReceipt{}, errors.New("source observation size limit") }
	return b, SourceObservationReceipt{Source:s, RecordedAt:at, Mode:mode, ObservationSHA256:intakeHash(b), BodySHA256:o.BodySHA256, BodyBytes:o.BodyBytes, SourceAuthentication:o.SourceAuthentication, TrustStatus:o.TrustStatus}, nil
}

// ObserveLocalSource retains supplied bytes; it never asserts network origin.
func ObserveLocalSource(id string, raw []byte, at time.Time) ([]byte, SourceObservationReceipt, error) {
	return makeSourceObservation(id,"LOCAL_INPUT","",raw,at)
}

// FetchSourceObservation performs one explicit bounded GET. The ordinary TLS
// transport is not proof that the body is a current, complete CA catalog.
func FetchSourceObservation(ctx context.Context, id string) ([]byte, SourceObservationReceipt, error) {
	client, closeClient := newResearchClient()
	defer closeClient()
	return fetchSourceObservation(ctx,client,id)
}
func fetchSourceObservation(ctx context.Context, client *http.Client, id string) ([]byte, SourceObservationReceipt, error) {
	s,err:=monitorSource(id)
	if err!=nil { return nil,SourceObservationReceipt{},err }
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,s.URL,nil)
	if err!=nil { return nil,SourceObservationReceipt{},err }
	req.Header.Set("Accept","text/html, application/xhtml+xml, text/plain")
	resp,err:=client.Do(req)
	if err!=nil { return nil,SourceObservationReceipt{},err }
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK { return nil,SourceObservationReceipt{},fmt.Errorf("source returned HTTP %d",resp.StatusCode) }
	media,_,err:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err!=nil || !allowedSourceMediaType(media) || resp.ContentLength>MaxSourceBodyBytes || resp.Uncompressed || (resp.Header.Get("Content-Encoding")!="" && resp.Header.Get("Content-Encoding")!="identity") {
		return nil,SourceObservationReceipt{},errors.New("unsupported source response type, length or encoding")
	}
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,MaxSourceBodyBytes+1))
	if err!=nil { return nil,SourceObservationReceipt{},err }
	if err:=ctx.Err();err!=nil { return nil,SourceObservationReceipt{},err }
	return makeSourceObservation(id,"HTTPS_RESPONSE",media,raw,time.Now().UTC())
}

func verifySourceObservation(b []byte,pin string)(SourceObservationReceipt,error) {
	if len(b)==0 || len(b)>MaxSourceObservationBytes || !sha256Pattern.MatchString(pin) || intakeHash(b)!=pin {
		return SourceObservationReceipt{},errors.New("source observation size or independent pin mismatch")
	}
	var o SourceObservation
	if err:=json.Unmarshal(b,&o);err!=nil { return SourceObservationReceipt{},err }
	canonical,r,err:=makeSourceObservation(o.Source.ID,o.Mode,o.MediaType,o.Raw,o.RecordedAt)
	if err!=nil { return SourceObservationReceipt{},err }
	if !bytes.Equal(canonical,b) { return SourceObservationReceipt{},errors.New("noncanonical or inconsistent source observation") }
	return r,nil
}

type SourceObservationDiff struct {
	Previous SourceObservationReceipt `json:"previous"`
	Current SourceObservationReceipt `json:"current"`
	Status string `json:"status"`
	ReviewSuggested bool `json:"reviewSuggested"`
	SemanticChange string `json:"semanticChange"`
	SourceAuthentication string `json:"sourceAuthentication"`
	TrustStatus string `json:"trustStatus"`
}

// CompareSourceObservations compares independently pinned exact private records.
// A byte change (or no change) says nothing about membership or trust.
func CompareSourceObservations(previous []byte,previousPin string,current []byte,currentPin string)(SourceObservationDiff,error) {
	a,err:=verifySourceObservation(previous,previousPin)
	if err!=nil { return SourceObservationDiff{},err }
	b,err:=verifySourceObservation(current,currentPin)
	if err!=nil { return SourceObservationDiff{},err }
	if a.Source!=b.Source || a.Mode!=b.Mode || !b.RecordedAt.After(a.RecordedAt) {
		return SourceObservationDiff{},errors.New("same source and observation mode with strictly increasing time required")
	}
	r:=SourceObservationDiff{Previous:a,Current:b,Status:"BODY_UNCHANGED",SemanticChange:"NOT_EVALUATED",SourceAuthentication:"NOT_ESTABLISHED",TrustStatus:"NOT_ESTABLISHED"}
	if a.BodySHA256!=b.BodySHA256 {
		r.Status="BODY_CHANGED_REVIEW_REQUIRED"
		r.ReviewSuggested=true
	}
	return r,nil
}
