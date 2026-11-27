// Package tufclient is an opt-in online research distribution adapter.
// TUF authenticates target bytes; it does not authorize CA trust.
package tufclient

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/M78U/trust-registry/pkg/snapshot"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const TargetName = "registry-snapshot.json"
const maxRoot = 512000
const maxRequests = 128
const maxDownloadBytes = 96 << 20

var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var metadataName = regexp.MustCompile(`^([1-9][0-9]*\.)?(root|timestamp|snapshot|targets)\.json$`)
var targetName = regexp.MustCompile(`^([a-f0-9]{64}\.)?registry-snapshot\.json$`)

type Options struct {
	StateDir string
	MetadataURL string
	TargetsURL string
	InitialRootSHA256 string
	BootstrapRoot []byte // only supplied on explicit first initialization
}

type stateConfig struct {
	SchemaVersion string `json:"schemaVersion"`
	MetadataURL string `json:"metadataURL"`
	TargetsURL string `json:"targetsURL"`
	InitialRootSHA256 string `json:"initialRootSHA256"`
}

type Report struct {
	Target string `json:"target"`
	TUFTargetAuthenticated bool `json:"tufTargetAuthenticated"`
	RootVersion int64 `json:"rootVersion"`
	TimestampVersion int64 `json:"timestampVersion"`
	SnapshotMetadataVersion int64 `json:"snapshotMetadataVersion"`
	TargetsVersion int64 `json:"targetsVersion"`
	Registry snapshot.Report `json:"registry"`
	ApplicationRollbackStatus string `json:"applicationRollbackStatus"`
	ReleaseAuthenticated bool `json:"releaseAuthenticated"`
	TrustStatus string `json:"trustStatus"`
}

func digest(b []byte)string{h:=sha256.Sum256(b);return hex.EncodeToString(h[:])}

// Explicit HTTPS repository directories, no query/userinfo/fragment or
// ambiguous escaping. No redirection to another origin or scheme.
func baseURL(raw string)(string,error){
	u,err:=url.Parse(raw)
	if err!=nil||u.Scheme!="https"||u.Hostname()==""||u.User!=nil||u.RawQuery!=""||u.ForceQuery||u.Fragment!=""||u.RawPath!=""||strings.ContainsAny(u.Path,"\\%") {return "",errors.New("unambiguous HTTPS repository URL required")}
	for _,part:=range strings.Split(u.Path,"/"){if part=="."||part==".."{return "",errors.New("invalid repository path")}}
	return strings.TrimRight(u.String(),"/")+"/",nil
}

type boundedFetcher struct {
	ctx context.Context
	client *http.Client
	metadataBase,targetsBase string
	requests int
	remaining int64
}

func (f *boundedFetcher) DownloadFile(raw string,maxLength int64,_ time.Duration)([]byte,error){
	// This adapter intentionally supports only the top-level TUF roles
	// and one fixed target, not delegated role names or arbitrary URLs.
	allowed:=false
	if strings.HasPrefix(raw,f.metadataBase){allowed=metadataName.MatchString(strings.TrimPrefix(raw,f.metadataBase))}
	if strings.HasPrefix(raw,f.targetsBase)&&targetName.MatchString(strings.TrimPrefix(raw,f.targetsBase)){allowed=true}
	if !allowed{return nil,errors.New("download outside configured repository paths")}
	if maxLength<=0||maxLength>snapshot.MaxEnvelopeBytes||f.requests>=maxRequests||maxLength>f.remaining{return nil,errors.New("download budget exceeded")}
	f.requests++
	req,err:=http.NewRequestWithContext(f.ctx,http.MethodGet,raw,nil);if err!=nil{return nil,err}
	resp,err:=f.client.Do(req);if err!=nil{return nil,err};defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK{return nil,&metadata.ErrDownloadHTTP{StatusCode:resp.StatusCode,URL:raw}}
	if resp.ContentLength>maxLength||resp.Uncompressed||(resp.Header.Get("Content-Encoding")!=""&&resp.Header.Get("Content-Encoding")!="identity"){return nil,errors.New("invalid download size or encoding")}
	data,err:=io.ReadAll(io.LimitReader(resp.Body,maxLength+1))
	f.remaining-=int64(len(data))
	if err!=nil{return nil,err}
	if int64(len(data))>maxLength{return nil,errors.New("download exceeds bound")}
	return data,nil
}

func readRegular(path string,limit int64)([]byte,error){
	info,err:=os.Lstat(path);if err!=nil{return nil,err}
	if !info.Mode().IsRegular()||info.Size()>limit{return nil,errors.New("invalid local state file")}
	f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
	stat,err:=f.Stat();if err!=nil{return nil,err}
	if !stat.Mode().IsRegular()||!os.SameFile(info,stat){return nil,errors.New("local state changed")}
	b,err:=io.ReadAll(io.LimitReader(f,limit+1));if err!=nil{return nil,err}
	if int64(len(b))>limit{return nil,errors.New("local state too large")}
	return b,nil
}

func regularDir(path string)error{
	i,err:=os.Lstat(path);if err!=nil{return err}
	if !i.IsDir(){return errors.New("expected private local directory")}
	return nil
}

// Refresh downloads a top-level target after go-tuf verifies root rotations,
// timestamp, snapshot and targets metadata. The protected local metadata
// cache is retained across invocations. No default roots, unsafe local mode,
// automatic cache reset, or automatic installation.
func Refresh(ctx context.Context,o Options)([]byte,Report,error){
	return refresh(ctx,o,false,nil)
}

// RefreshAndInstall validates and persists a versioned offline evidence record
// under the same cooperative lock as TUF metadata refresh.
func RefreshAndInstall(ctx context.Context,o Options)(Report,error){
	_,report,err:=refresh(ctx,o,true,nil)
	return report,err
}
func refresh(ctx context.Context,o Options,install bool,testClient *http.Client)([]byte,Report,error){
	metaURL,err:=baseURL(o.MetadataURL);if err!=nil{return nil,Report{},err}
	targetURL,err:=baseURL(o.TargetsURL);if err!=nil{return nil,Report{},err}
	if o.StateDir==""||!hashPattern.MatchString(o.InitialRootSHA256){return nil,Report{},errors.New("state directory and independent initial root SHA-256 required")}
	dir,err:=filepath.Abs(o.StateDir);if err!=nil{return nil,Report{},err}
	bootstrap:=o.BootstrapRoot!=nil
	expected:=stateConfig{"1",metaURL,targetURL,o.InitialRootSHA256}
	configBytes,err:=json.Marshal(expected);if err!=nil{return nil,Report{},err}
	metadataDir:=filepath.Join(dir,"metadata")
	targetDir:=filepath.Join(dir,"targets")
	rootPath:=filepath.Join(metadataDir,"root.json")
	if bootstrap{
		if len(o.BootstrapRoot)==0||len(o.BootstrapRoot)>maxRoot||digest(o.BootstrapRoot)!=o.InitialRootSHA256{return nil,Report{},errors.New("initial root pin mismatch")}
		// Check root type and self-signature threshold before creating state.
		check,err:=config.New(metaURL,o.BootstrapRoot);if err!=nil{return nil,Report{},err}
		check.DisableLocalCache=true
		if _,err:=updater.New(check);err!=nil{return nil,Report{},err}
		if err:=os.Mkdir(dir,0700);err!=nil{return nil,Report{},fmt.Errorf("bootstrap requires nonexistent directory: %w",err)}
	}
	if err:=regularDir(dir);err!=nil{return nil,Report{},err}
	lock:=filepath.Join(dir,".lock")
	if err:=os.Mkdir(lock,0700);err!=nil{return nil,Report{},fmt.Errorf("TUF state locked: %w",err)}
	defer os.Remove(lock)
	if bootstrap{
		for _,d:=range []string{metadataDir,targetDir}{if err:=os.Mkdir(d,0700);err!=nil{return nil,Report{},err}}
		if err:=os.WriteFile(filepath.Join(dir,"configuration.json"),configBytes,0600);err!=nil{return nil,Report{},err}
		if err:=os.WriteFile(rootPath,o.BootstrapRoot,0600);err!=nil{return nil,Report{},err}
	}
	actual,err:=readRegular(filepath.Join(dir,"configuration.json"),16384);if err!=nil{return nil,Report{},err}
	if !bytes.Equal(actual,configBytes){return nil,Report{},errors.New("repository identity changed")}
	for _,d:=range []string{metadataDir,targetDir}{if err:=regularDir(d);err!=nil{return nil,Report{},err}}
	entries,err:=os.ReadDir(metadataDir);if err!=nil{return nil,Report{},err}
	for _,e:=range entries{
		switch e.Name(){case "root.json","timestamp.json","snapshot.json","targets.json":default:return nil,Report{},errors.New("unexpected cached metadata; inspect state")}
		i,err:=e.Info();if err!=nil{return nil,Report{},err}
		if !i.Mode().IsRegular()||i.Size()>5_000_000{return nil,Report{},errors.New("invalid cached metadata")}
	}
	root,err:=readRegular(rootPath,maxRoot);if err!=nil{return nil,Report{},err}
	cfg,err:=config.New(metaURL,root);if err!=nil{return nil,Report{},err}
	cfg.LocalMetadataDir=metadataDir
	cfg.LocalTargetsDir=targetDir
	cfg.RemoteTargetsURL=targetURL
	cfg.MaxRootRotations=32
	cfg.MaxDelegations=0
	tr:=&http.Transport{TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},DisableCompression:true,ResponseHeaderTimeout:15*time.Second}
	defer tr.CloseIdleConnections()
	client:=&http.Client{Transport:tr,Timeout:30*time.Second,CheckRedirect:func(*http.Request,[]*http.Request)error{return errors.New("redirect disabled")}}
	if testClient!=nil{client=testClient} // private integration test seam only
	ctx,cancel:=context.WithTimeout(ctx,5*time.Minute);defer cancel()
	cfg.Fetcher=&boundedFetcher{ctx:ctx,client:client,metadataBase:metaURL,targetsBase:targetURL,remaining:maxDownloadBytes}
	u,err:=updater.New(cfg);if err!=nil{return nil,Report{},err}
	if err:=u.Refresh();err!=nil{return nil,Report{},err}
	info:=u.GetTopLevelTargets()[TargetName]
	if info==nil||info.Path!=TargetName||info.Length<=0||info.Length>snapshot.MaxEnvelopeBytes||len(info.Hashes)!=1||len(info.Hashes["sha256"])!=sha256.Size{return nil,Report{},errors.New("required top-level snapshot target with SHA-256 absent or invalid")}
	// Temporary file is only transport staging; do not leave a mutable
	// target in the trusted metadata directory.
	staging,err:=os.MkdirTemp("","m78u-tuf-target-");if err!=nil{return nil,Report{},err}
	defer os.RemoveAll(staging)
	_,raw,err:=u.DownloadTarget(info,filepath.Join(staging,TargetName),"");if err!=nil{return nil,Report{},err}
	reg,err:=snapshot.Verify(raw,"");if err!=nil{return nil,Report{},err}
	now:=time.Now().UTC()
	if now.Before(reg.Manifest.CreatedAt)||!now.Before(reg.Manifest.ExpiresAt){return nil,Report{},errors.New("registry envelope outside declared validity window")}
	trusted:=u.GetTrustedMetadataSet()
	report:=Report{Target:TargetName,TUFTargetAuthenticated:true,RootVersion:trusted.Root.Signed.Version,TimestampVersion:trusted.Timestamp.Signed.Version,SnapshotMetadataVersion:trusted.Snapshot.Signed.Version,TargetsVersion:trusted.Targets[metadata.TARGETS].Signed.Version,Registry:reg,ApplicationRollbackStatus:"NOT_CHECKED",TrustStatus:"NOT_ESTABLISHED"}
	if install{
		if err:=installEvidence(dir,o.InitialRootSHA256,raw,report,now);err!=nil{return nil,Report{},err}
		report.ApplicationRollbackStatus="CHECKED_LOCAL_INSTALLATION"
	}
	return raw,report,nil
}
