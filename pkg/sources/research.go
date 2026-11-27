package sources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
)

type ResearchItem struct {
	ListingID string `json:"listingId"`
	Status string `json:"status"`
	Report *AcquisitionReport `json:"report,omitempty"`
	Error string `json:"error,omitempty"`
}

type ResearchReport struct {
	SchemaVersion string `json:"schemaVersion"`
	StartedAt time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Mode string `json:"mode"`
	Attempted int `json:"attempted"`
	Succeeded int `json:"succeeded"`
	Failed int `json:"failed"`
	Skipped int `json:"skipped"`
	Items []ResearchItem `json:"items"`
	OriginalFilesSaved bool `json:"originalFilesSaved"`
	RegistryImported bool `json:"registryImported"`
	TrustStatus string `json:"trustStatus"`
}

// Research performs explicit, bounded requests to the embedded endpoints.
// Bytes are used in memory only and never included in the report. All results
// are unreviewed, even when both published fingerprints match.
func Research(ctx context.Context,includeLegacy bool)(ResearchReport,error){
	c,err:=SHECA();if err!=nil{return ResearchReport{},err}
	endpoints,err:=Endpoints();if err!=nil{return ResearchReport{},err}
	client,closeClient:=newResearchClient();defer closeClient()
	return research(ctx,client,c,endpoints,includeLegacy)
}

func research(ctx context.Context,client *http.Client,c Catalog,endpoints []Endpoint,includeLegacy bool)(ResearchReport,error){
	mode:="SHA256_LEADS_ONLY"
	if includeLegacy{mode="INCLUDE_LEGACY_ONLY"}
	r:=ResearchReport{SchemaVersion:"1",StartedAt:time.Now().UTC(),Mode:mode,Items:make([]ResearchItem,0,len(endpoints)),TrustStatus:"NOT_ESTABLISHED"}
	for _,e:=range endpoints{
		item:=ResearchItem{ListingID:e.ListingID}
		switch {
		case e.PublishedSHA256==nil&&!includeLegacy:
			item.Status="SKIPPED_NO_SHA256_LEAD";r.Skipped++
		case ctx.Err()!=nil:
			item.Status="SKIPPED_CONTEXT_CANCELLED";r.Skipped++
		default:
			r.Attempted++
			_,report,err:=fetchBytes(ctx,client,c,e,includeLegacy)
			if err!=nil{
				item.Status="FAILED";r.Failed++
				msg:=strings.ToValidUTF8(err.Error(),"?")
				if len(msg)>2048{msg=strings.ToValidUTF8(msg[:2048],"?")}
				item.Error=msg
			}else{
				item.Status="DOWNLOADED_UNREVIEWED";r.Succeeded++
				item.Report=&report
			}
		}
		r.Items=append(r.Items,item)
	}
	r.FinishedAt=time.Now().UTC()
	if r.Failed>0||r.Attempted==0||ctx.Err()!=nil{return r,errors.New("research incomplete; inspect report for per-source status")}
	return r,nil
}
