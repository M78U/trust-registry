package schemas

import (
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedSchemas(t *testing.T) {
	loadOnce.Do(compileAll)
	if compileErr != nil {
		t.Fatalf("schema compilation: %v", compileErr)
	}
	names, err := fs.Glob(files, "*.schema.json")
	if err != nil || len(names) == 0 {
		t.Fatalf("enumerate embedded schemas: %v (count %d)", err, len(names))
	}
	if len(compiled) != len(names) {
		t.Fatalf("compiled schema count %d, embedded schema count %d", len(compiled), len(names))
	}
	for _, name := range names {
		if compiled[name] == nil {
			t.Fatalf("embedded schema not compiled: %s", name)
		}
		if err := ValidateJSON(name, []byte("{}")); err == nil {
			t.Fatalf("empty object accepted: %s", name)
		}
	}
	// Keep both review schemas explicitly covered, even if a future change
	// removes one from both the embedded files and compiler registration.
	for _, name := range []string{Certificate, Provenance, Policy, ProvenanceReview, Decision, PolicyDocument, ReleaseReview, ReviewAuthority} {
		if compiled[name] == nil {
			t.Fatalf("required schema missing: %s", name)
		}
	}
	if err:=ValidateJSON("https://example.org/external.json",[]byte("{}"));err==nil { t.Fatal("external schema accepted") }
}

func TestPolicySchemaRefsAndFormat(t *testing.T) {
	const policyJSON = `{"policy":{"schemaVersion":"1","id":"cn.document-signing","version":1,"jurisdiction":"CN","purpose":"document-signing","trustAnchors":[],"intermediateCandidates":[],"constraints":{"requireExplicitTrustDecision":true,"requireValidCertificatePath":true,"allowSystemTrustFallback":false}},"reviews":[],"decisions":[]}`
	if err:=ValidateJSON(PolicyDocument,[]byte(policyJSON));err!=nil { t.Fatal(err) }
	for _,bad:=range []string{
		strings.Replace(policyJSON,`"version":1`,`"version":0`,1),
		strings.Replace(policyJSON,`"version":1`,`"version":1,"version":2`,1),
		strings.Replace(policyJSON,`"allowSystemTrustFallback":false`,`"allowSystemTrustFallback":true`,1),
		strings.Replace(policyJSON,`"trustAnchors":[]`,`"trustAnchors":null`,1),
		strings.Replace(policyJSON,`"reviews":[]`,`"reviews":[{}]`,1),
		policyJSON+"{}",
	} { if err:=ValidateJSON(PolicyDocument,[]byte(bad));err==nil { t.Fatal("invalid policy accepted") } }
	review:=map[string]any{"id":"review-1","provenanceId":strings.Repeat("a",64),"certificateSHA256":strings.Repeat("b",64),"status":"PROVENANCE_VERIFIED","recordedAt":"2026-02-30T00:00:00Z","evidence":[]string{"source"},"reviewReferences":[]string{"review"}}
	if err:=ValidateValue(ProvenanceReview,review);err==nil { t.Fatal("invalid date-time accepted") }
	review["recordedAt"]="2026-02-28T00:00:00Z"
	if err:=ValidateValue(ProvenanceReview,review);err!=nil { t.Fatal(err) }
	decision:=map[string]any{"id":"d-1","certificateSHA256":strings.Repeat("b",64),"policyId":"cn.document-signing","policyVersion":1,"role":"TRUST_ANCHOR","status":"TRUSTED","recordedAt":"2026-02-28T00:00:00Z","effectiveFrom":"2026-02-28T00:00:00Z","effectiveUntil":nil,"reason":"synthetic","evidenceIds":[]string{},"reviewReferences":[]string{"review"}}
	if err:=ValidateValue(Decision,decision);err==nil { t.Fatal("conditional evidence requirement ignored") }
	decision["evidenceIds"]=[]string{"review-1"}
	if err:=ValidateValue(Decision,decision);err!=nil { t.Fatal(err) }
	b,_:=json.Marshal(decision)
	if err:=ValidateJSON(Decision,append(b,0xff));err==nil { t.Fatal("invalid UTF-8 accepted") }
}
