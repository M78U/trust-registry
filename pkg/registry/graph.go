package registry

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/emmansun/gmsm/smx509"
)

const (
	MaxGraphNodes = 2048
	MaxGraphDERBytes = 32 << 20
	MaxGraphEdges = 16384
	MaxPathDepth = 32
	MaxCandidatePaths = 256
	MaxPathSteps = 32768
)

type GraphNode struct {
	Certificate CertificateRecord `json:"certificate"`
	InInventory bool `json:"inInventory"`
	SelfIssued bool `json:"selfIssued"`
	SelfSignatureStatus string `json:"selfSignatureStatus"`
	MatchedIssuerCount int `json:"matchedIssuerCount"`
}

type GraphEdge struct {
	ChildSHA256 string `json:"childSHA256"`
	IssuerSHA256 string `json:"issuerSHA256"`
	IssuerDNMatch bool `json:"issuerDNMatch"`
	AKISKIMatch bool `json:"akiSkiMatch"`
	KeyIdentifierConflict bool `json:"keyIdentifierConflict"`
	SignatureStatus string `json:"signatureStatus"`
	DirectIssuerStatus string `json:"directIssuerStatus"`
	Reason string `json:"reason"`
}

type RelationshipGraph struct {
	SchemaVersion string `json:"schemaVersion"`
	TrustStatus string `json:"trustStatus"`
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
	MatchedEdges int `json:"matchedEdges"`
}

// Graph is an immutable, locally derived view. No authentication or full
// certificate path validation is performed. Export returns a copy.
type Graph struct {
	view RelationshipGraph
	nodes map[string]GraphNode
	parents map[string][]string
}

type parsedNode struct {
	record CertificateRecord
	cert *smx509.Certificate
	inventory bool
}

// BuildGraph validates inventory and constructs exact-DER-DN / AKI-SKI
// candidate edges. Optional input is a single ephemeral certificate (nil means
// no additional input); it is never stored and cannot act as an issuer unless
// already in inventory. Graph and path limits fail closed with no partial view.
// The local directory must not be concurrently mutated.
func (s *Store) BuildGraph(input []byte)(*Graph,error){
	idx,err:=s.BuildIndex()
	if err!=nil{return nil,err}
	if len(idx.all)>MaxGraphNodes{return nil,errors.New("graph node limit exceeded")}
	parsed:=make(map[string]parsedNode,len(idx.all)+1)
	total:=0
	add:=func(r CertificateRecord,raw []byte,inInventory bool)error{
		if len(parsed)>=MaxGraphNodes||len(raw)>MaxGraphDERBytes-total{return errors.New("graph node or DER byte limit exceeded")}
		if digest(raw)!=r.FingerprintSHA256{return errors.New("certificate changed during graph construction")}
		c,err:=smx509.ParseCertificate(raw);if err!=nil{return err}
		parsed[r.FingerprintSHA256]=parsedNode{r,c,inInventory}
		total+=len(raw)
		return nil
	}
	for _,fp:=range idx.all{
		raw,err:=readRegular(filepath.Join(s.root,"certificates",fp+".der"),MaxCertificateInput)
		if err!=nil{return nil,err}
		if err:=add(idx.records[fp],raw,true);err!=nil{return nil,err}
	}
	if input!=nil{
		r,der,err:=ParseCertificate(input);if err!=nil{return nil,err}
		if _,exists:=parsed[r.FingerprintSHA256];!exists{
			if err:=add(r,der,false);err!=nil{return nil,err}
		}
	}
	return buildGraph(parsed)
}

func buildGraph(parsed map[string]parsedNode)(*Graph,error){
	g:=&Graph{view:RelationshipGraph{SchemaVersion:"1",TrustStatus:"NOT_ESTABLISHED",Nodes:[]GraphNode{},Edges:[]GraphEdge{}},nodes:make(map[string]GraphNode,len(parsed)),parents:make(map[string][]string)}
	fps:=make([]string,0,len(parsed))
	byDN:=map[string][]string{}
	bySKI:=map[string][]string{}
	for fp:=range parsed{fps=append(fps,fp)}
	sort.Strings(fps)
	for _,fp:=range fps{
		n:=parsed[fp]
		if !n.inventory{continue}
		byDN[string(n.cert.RawSubject)]=append(byDN[string(n.cert.RawSubject)],fp)
		if len(n.cert.SubjectKeyId)>0{bySKI[string(n.cert.SubjectKeyId)]=append(bySKI[string(n.cert.SubjectKeyId)],fp)}
	}
	for _,fp:=range fps{
		n:=parsed[fp]
		node:=GraphNode{Certificate:n.record,InInventory:n.inventory,SelfIssued:bytes.Equal(n.cert.RawSubject,n.cert.RawIssuer),SelfSignatureStatus:"NOT_CHECKED_NOT_SELF_ISSUED"}
		if node.SelfIssued{
			node.SelfSignatureStatus="NOT_VERIFIED"
			if err:=n.cert.CheckSignature(n.cert.SignatureAlgorithm,n.cert.RawTBSCertificate,n.cert.Signature);err==nil{node.SelfSignatureStatus="VERIFIED"}
		}
		set:=map[string]bool{}
		for _,parent:=range byDN[string(n.cert.RawIssuer)]{if parent!=fp{set[parent]=true}}
		if len(n.cert.AuthorityKeyId)>0{
			for _,parent:=range bySKI[string(n.cert.AuthorityKeyId)]{if parent!=fp{set[parent]=true}}
		}
		if len(set)>MaxIssuerCandidates||len(set)>MaxGraphEdges-len(g.view.Edges){return nil,fmt.Errorf("graph candidate edge limit exceeded for %s",fp)}
		candidates:=make([]string,0,len(set))
		for parent:=range set{candidates=append(candidates,parent)}
		sort.Strings(candidates)
		for _,parent:=range candidates{
			p:=parsed[parent]
			c,ok:=checkDirectIssuer(n.cert,p.cert,p.record)
			if !ok{return nil,errors.New("graph candidate index mismatch")}
			g.view.Edges=append(g.view.Edges,GraphEdge{fp,parent,c.IssuerDNMatch,c.AKISKIMatch,c.KeyIdentifierConflict,c.SignatureStatus,c.DirectIssuerStatus,c.Reason})
			if c.DirectIssuerStatus=="MATCHED"{
				g.parents[fp]=append(g.parents[fp],parent)
				node.MatchedIssuerCount++
				g.view.MatchedEdges++
			}
		}
		g.nodes[fp]=node
		g.view.Nodes=append(g.view.Nodes,node)
	}
	return g,nil
}

func (g *Graph) Export()(RelationshipGraph,error){
	if g==nil||g.nodes==nil{return RelationshipGraph{},errors.New("constructed graph required")}
	v:=g.view
	v.Nodes=append([]GraphNode{},v.Nodes...)
	v.Edges=append([]GraphEdge{},v.Edges...)
	return v,nil
}

type CandidatePath struct {
	Fingerprints []string `json:"fingerprints"`
	TerminalStatus string `json:"terminalStatus"`
}

type PathReport struct {
	StartSHA256 string `json:"startSHA256"`
	TrustStatus string `json:"trustStatus"`
	Paths []CandidatePath `json:"paths"`
}

// Paths walks only matched direct issuer edges. Self-signature is a possible
// stopping point, not a trusted root; alternative parents are still explored.
// Cycles and missing issuer/depth endpoints are explicit. No time, policy,
// revocation, name/path-length constraint or full path verification is claimed.
func (g *Graph) Paths(fp string,maxDepth int)(PathReport,error){
	if g==nil||g.nodes==nil||!validFingerprint(fp){return PathReport{},errors.New("constructed graph and valid fingerprint required")}
	if _,ok:=g.nodes[fp];!ok{return PathReport{},errors.New("start certificate not in graph")}
	if maxDepth<1||maxDepth>MaxPathDepth{return PathReport{},fmt.Errorf("path depth must be 1–%d",MaxPathDepth)}
	r:=PathReport{StartSHA256:fp,TrustStatus:"NOT_ESTABLISHED",Paths:[]CandidatePath{}}
	seen:=map[string]bool{}
	steps:=0
	emit:=func(path []string,status string)error{
		if len(r.Paths)>=MaxCandidatePaths{return errors.New("candidate path limit exceeded")}
		r.Paths=append(r.Paths,CandidatePath{append([]string{},path...),status})
		return nil
	}
	var walk func(string,[]string)error
	walk=func(cur string,path []string)error{
		steps++
		if steps>MaxPathSteps{return errors.New("path exploration limit exceeded")}
		if seen[cur]{return emit(append(path,cur),"CYCLE")}
		path=append(path,cur)
		seen[cur]=true
		defer delete(seen,cur)
		node:=g.nodes[cur]
		self:=node.SelfSignatureStatus=="VERIFIED"
		if self{if err:=emit(path,"SELF_SIGNATURE_VERIFIED");err!=nil{return err}}
		parents:=g.parents[cur]
		if len(parents)==0{
			if self{return nil}
			return emit(path,"NO_MATCHED_ISSUER")
		}
		if len(path)>=maxDepth{return emit(path,"DEPTH_LIMIT")}
		for _,parent:=range parents{if err:=walk(parent,path);err!=nil{return err}}
		return nil
	}
	if err:=walk(fp,nil);err!=nil{return PathReport{},err}
	return r,nil
}
