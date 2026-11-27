package tufclient

import (
 "bytes"
 "context"
 "net/http"
 "net/http/httptest"
 "sync/atomic"
 "crypto/ecdsa"
 "crypto/ed25519"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/json"
 "math/big"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/M78U/trust-registry/pkg/registry"
 "github.com/M78U/trust-registry/pkg/review"
 "github.com/M78U/trust-registry/pkg/snapshot"
 "github.com/theupdateframework/go-tuf/v2/metadata"
)
func TestReviewedPublication(t *testing.T){
 now:=time.Now().UTC().Truncate(time.Second).Add(-2*time.Minute)
 opts:=RootOptions{Expires:now.Add(48*time.Hour),Roles:map[string]RoleKeys{}}
 keys:=map[string]ed25519.PrivateKey{}
 for _,role:=range roles{
  pub,k,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  opts.Roles[role]=RoleKeys{[]ed25519.PublicKey{pub},1};keys[role]=k
 }
 opts.Signers=[]ed25519.PrivateKey{keys[metadata.ROOT]}
 root,err:=CreateRoot(opts);if err!=nil{t.Fatal(err)}
 s,err:=registry.OpenStore(t.TempDir());if err!=nil{t.Fatal(err)}
 k,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if err!=nil{t.Fatal(err)}
 c:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"Synthetic candidate"},NotBefore:now,NotAfter:now.AddDate(1,0,0),BasicConstraintsValid:true,IsCA:true,KeyUsage:x509.KeyUsageCertSign}
 der,err:=x509.CreateCertificate(rand.Reader,c,c,&k.PublicKey,k);if err!=nil{t.Fatal(err)}
 if _,err:=s.Import(der,"https://example.org/ca",now);err!=nil{t.Fatal(err)}
 raw,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:1,SourceRevision:strings.Repeat("a",40),CreatedAt:now,ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
 d,err:=review.Plan(raw);if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 cfg:=review.AuthorityConfig{SchemaVersion:"1",ReleaseThreshold:2,Keys:[]review.AuthorityKey{}}
 reviewers:=map[string]ed25519.PrivateKey{}
 for _,v:=range []struct{id,role string}{{"source","SOURCE_IDENTITY"},{"rights","REVIEW"},{"release-a","RELEASE"},{"release-b","RELEASE"}}{
  pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  cfg.Keys=append(cfg.Keys,review.AuthorityKey{ID:v.id,Role:v.role,PublicKey:pub});reviewers[v.id]=priv
 }
 ab,err:=json.Marshal(cfg);if err!=nil{t.Fatal(err)}
 a,err:=review.ParseAuthority(ab,digest(ab));if err!=nil{t.Fatal(err)}
 for i:=range d.Reviews{
  v:=&d.Reviews[i];v.Status="APPROVED";v.ReviewedAt=&now;v.Note="synthetic fixture";v.Reviewer="rights"
  kinds:=[]string{"REDISTRIBUTION_TERMS"}
  if v.Requirement.Kind=="SOURCE_IDENTITY"{v.Reviewer="source";kinds=[]string{"ISSUER_SOURCE","INDEPENDENT_FINGERPRINT"}}
  for _,kind:=range kinds{
   data:=[]byte("synthetic "+kind);h:=digest(data)
   if err:=os.WriteFile(filepath.Join(dir,h+".evidence"),data,0600);err!=nil{t.Fatal(err)}
   v.Evidence=append(v.Evidence,review.Artifact{Kind:kind,SHA256:h,Reference:"fixture"})
  }
 }
 approval,err:=review.NewApproval(raw,d,dir,a,now,now.Add(time.Hour));if err!=nil{t.Fatal(err)}
 o:=ReviewedPublishOptions{Publish:PublishOptions{RootSHA256:digest(root),Version:1,Now:now,TargetsExpires:now.Add(12*time.Hour),SnapshotExpires:now.Add(6*time.Hour),TimestampExpires:now.Add(time.Hour),TargetsSigners:[]ed25519.PrivateKey{keys[metadata.TARGETS]},SnapshotSigners:[]ed25519.PrivateKey{keys[metadata.SNAPSHOT]},TimestampSigners:[]ed25519.PrivateKey{keys[metadata.TIMESTAMP]}},Authority:a,Dossier:d,EvidenceDir:dir,Approval:approval,Bootstrap:true}
 if _,_,err:=BuildReviewedRepository(root,raw,o);err==nil{t.Fatal("unsigned approval")}
 for _,v:=range d.Reviews{approval,err=review.SignReview(raw,d,dir,a,approval,v.Requirement.ID,reviewers[v.Reviewer],now);if err!=nil{t.Fatal(err)}}
 for _,id:=range []string{"release-a","release-b"}{approval,err=review.SignRelease(raw,d,dir,a,approval,id,reviewers[id],now);if err!=nil{t.Fatal(err)}}
 o.Approval=approval
 repo,report,err:=BuildReviewedRepository(root,raw,o);if err!=nil||len(repo.Files)!=5||report.Status!="REVIEWED_LOCAL_PUBLICATION_CANDIDATE"||report.ReleaseAuthenticated||report.TrustStatus!="NOT_ESTABLISHED"{t.Fatal(report,err)}
 bad:=o;bad.Bootstrap=false
 if _,_,err:=BuildReviewedRepository(root,raw,bad);err==nil{t.Fatal("missing baseline")}
 bad=o;bad.Publish.Now=now.Add(time.Hour)
 if _,_,err:=BuildReviewedRepository(root,raw,bad);err==nil{t.Fatal("expired approval")}
 // Public receipt adds no target file and uses separate approval signatures.
 binding:=review.ReleaseBinding{InitialRootSHA256:digest(root),CurrentRootSHA256:digest(root),SnapshotSHA256:digest(raw),Sequence:1,TargetsExpires:o.Publish.TargetsExpires,SnapshotMetadataExpires:o.Publish.SnapshotExpires,TimestampExpires:o.Publish.TimestampExpires}
 credential,err:=review.PrepareCredential(raw,d,dir,a,approval,binding,now);if err!=nil{t.Fatal(err)}
 if _,err:=review.VerifyCredential(a,credential,binding,now);err==nil{t.Fatal("unsigned credential")}
 if _,err:=review.SignCredential(raw,d,dir,a,approval,credential,"rights",reviewers["rights"],now);err==nil{t.Fatal("review key signed public credential")}
 for _,id:=range []string{"release-a","release-b"}{credential,err=review.SignCredential(raw,d,dir,a,approval,credential,id,reviewers[id],now);if err!=nil{t.Fatal(err)}}
 publicBytes,err:=review.CredentialBytes(credential);if err!=nil{t.Fatal(err)}
 strict:=o;strict.PublicCredential=publicBytes
 publicRepo,_,err:=BuildReviewedRepository(root,raw,strict);if err!=nil||len(publicRepo.Files)!=5{t.Fatal(err)}
 targets,err:=metadata.Targets().FromBytes(publicRepo.Files["metadata/1.targets.json"]);if err!=nil{t.Fatal(err)}
 info:=targets.Signed.Targets[TargetName]
 check,err:=checkPublicCredential(a,[][]byte{root},digest(root),info,1,o.Publish.TargetsExpires,o.Publish.SnapshotExpires,o.Publish.TimestampExpires,now)
 if err!=nil||!check.ReleaseApprovalVerified||check.PrivateEvidenceVerified{t.Fatal(check,err)}
 if _,err:=checkPublicCredential(a,[][]byte{root},digest(root),info,2,o.Publish.TargetsExpires,o.Publish.SnapshotExpires,o.Publish.TimestampExpires,now);err==nil{t.Fatal("sequence substitution")}
 if _,err:=checkPublicCredential(a,[][]byte{root},digest(root),info,1,o.Publish.TargetsExpires,o.Publish.SnapshotExpires,o.Publish.TimestampExpires.Add(time.Minute),now);err==nil{t.Fatal("expiry substitution")}
 strict.PublicCredential=[]byte("{}")
 if _,_,err:=BuildReviewedRepository(root,raw,strict);err==nil{t.Fatal("invalid public credential")}
 // Strict clients require the receipt before fetching the target. Separate
 // state directories ensure research and strict bootstrap are not mixed.
 serve:=func(repository Repository)(*httptest.Server,*atomic.Int32){
  hits:=&atomic.Int32{}
  server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){
   if strings.HasPrefix(req.URL.Path,"/targets/"){hits.Add(1)}
   data,ok:=repository.Files[strings.TrimPrefix(req.URL.Path,"/")]
   if !ok{http.NotFound(w,req);return};_,_=w.Write(data)
  }))
  t.Cleanup(server.Close)
  return server,hits
 }
 unsignedServer,unsignedHits:=serve(repo)
 strictOptions:=Options{StateDir:filepath.Join(t.TempDir(),"state"),MetadataURL:unsignedServer.URL+"/metadata",TargetsURL:unsignedServer.URL+"/targets",InitialRootSHA256:digest(root),BootstrapRoot:root,ReviewAuthority:a}
 if _,_,err:=refresh(context.Background(),strictOptions,true,unsignedServer.Client());err==nil||unsignedHits.Load()!=0{t.Fatal("missing credential did not stop target download",err)}
 signedServer,signedHits:=serve(publicRepo)
 strictOptions.StateDir=filepath.Join(t.TempDir(),"state")
 strictOptions.MetadataURL=signedServer.URL+"/metadata";strictOptions.TargetsURL=signedServer.URL+"/targets"
 if _,r,err:=refresh(context.Background(),strictOptions,true,signedServer.Client());err!=nil||r.ReleaseApproval==nil||!r.ReleaseApproval.ReleaseApprovalVerified||signedHits.Load()!=1{t.Fatal(r,err)}
 if view,r,err:=LoadAuthorizedInstalled(strictOptions.StateDir,digest(root),a);err!=nil||view==nil||r.ReleaseApproval==nil||!r.ReleaseApproval.ReleaseApprovalVerified{t.Fatal(r,err)}
 // The public SDK only opens strict verified installations and checks
 // the independent checkpoint and expiry. Returned candidate bytes keep
 // the existing consumer schema and never include the root.
 co:=ConsumerOptions{StateDir:strictOptions.StateDir,InitialRootSHA256:digest(root),Authority:a,MinimumSequence:1,ExpectedSnapshotSHA256:digest(raw)}
 session,err:=OpenConsumer(co);if err!=nil{t.Fatal(err)}
 ci,err:=session.Info();if err!=nil||ci.Sequence!=1||!ci.TUFTargetAuthenticated||!ci.ReleaseApprovalVerified||ci.PrivateEvidenceVerified||ci.ReleaseAuthenticated||ci.TrustStatus!="NOT_ESTABLISHED"||ci.SessionExpiresAt.After(binding.TimestampExpires){t.Fatal(ci,err)}
 record,err:=session.Find(digest(der));if err!=nil||record.FingerprintSHA256!=digest(der){t.Fatal(record,err)}
 ps,err:=session.Provenance(digest(der));if err!=nil||len(ps)!=1{t.Fatal(ps,err)}
 cb,err:=session.CandidateBundle(nil);if err!=nil{t.Fatal(err)}
 var candidates snapshot.ConsumerBundle
 if err:=json.Unmarshal(cb,&candidates);err!=nil||candidates.Kind!="UNTRUSTED_CA_CANDIDATES"||candidates.SnapshotSHA256!=ci.SnapshotSHA256||len(candidates.Certificates)!=0{t.Fatal(candidates,err)}
 if session.checkAt(ci.SessionExpiresAt)==nil||session.checkAt(ci.VerifiedAt.Add(-time.Nanosecond))==nil{t.Fatal("invalid session time accepted")}
 if _,err:=(&ConsumerSession{}).Find(digest(der));err==nil{t.Fatal("zero session usable")}
 badConsumer:=co;badConsumer.MinimumSequence=2
 if _,err:=OpenConsumer(badConsumer);err==nil{t.Fatal("checkpoint rollback")}
 badConsumer=co;badConsumer.Authority=nil
 if _,err:=OpenConsumer(badConsumer);err==nil{t.Fatal("missing authority")}
 badConsumer=co;badConsumer.ExpectedSnapshotSHA256=strings.Repeat("0",64)
 if _,err:=OpenConsumer(badConsumer);err==nil{t.Fatal("wrong snapshot pin")}
 if _,err:=session.Diff(session,false);err==nil{t.Fatal("same sequence comparison")}
 if signedHits.Load()!=1{t.Fatal("offline SDK downloaded target")}
 if _,_,err:=LoadInstalled(strictOptions.StateDir,digest(root));err==nil{t.Fatal("strict offline downgrade")}
 strictOptions.BootstrapRoot=nil;strictOptions.ReviewAuthority=nil
 if _,_,err:=refresh(context.Background(),strictOptions,true,signedServer.Client());err==nil{t.Fatal("strict online downgrade")}
 // Ledger commits exact signed metadata, with an independently retainable head.
 ledger:=filepath.Join(t.TempDir(),"publication")
 o.PublicCredential=publicBytes
 lo:=LedgerOptions{Directory:ledger,AuthoritySHA256:digest(ab),Reviewed:o}
 receipt,err:=BuildInLedger(root,raw,lo);if err!=nil||receipt.Sequence!=1||receipt.Status!="LOCAL_REVIEWED_BUILD_COMMITTED"{t.Fatal(receipt,err)}
 exported,er,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt.RecordSHA256,now)
 if err!=nil||er.RecordSHA256!=receipt.RecordSHA256||len(exported.Files)!=5{t.Fatal(er,err)}
 for name,data:=range publicRepo.Files{if !bytes.Equal(exported.Files[name],data){t.Fatal("changed export",name)}}
 if _,err:=BuildInLedger(root,raw,lo);err==nil{t.Fatal("repeat bootstrap")}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),strings.Repeat("b",64),now);err==nil{t.Fatal("wrong head pin")}
 if err:=os.Mkdir(filepath.Join(ledger,".lock"),0700);err!=nil{t.Fatal(err)}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),"",now);err==nil{t.Fatal("concurrent operation")}
 if err:=os.Remove(filepath.Join(ledger,".lock"));err!=nil{t.Fatal(err)}
 // Build from exact ledger and preview assets; no private files exported.
 explorer:=t.TempDir()
 for _,name:=range explorerAssets{data:=[]byte("fixture "+name);if name=="_headers"{data=[]byte(baseHeaders)};if err:=os.WriteFile(filepath.Join(explorer,name),data,0600);err!=nil{t.Fatal(err)}}
 staticOpts:=StaticOptions{LedgerDir:ledger,InitialRootSHA256:digest(root),ExpectedHeadSHA256:receipt.RecordSHA256,Authority:a,ExplorerDir:explorer,At:now,First:true}
 files,plan,err:=PrepareStaticPublication(staticOpts);if err!=nil||plan.NewFiles!=len(explorerAssets)+5||plan.Deployed{t.Fatal(plan,err)}
 oldManifest,err:=StaticManifestBytes(plan.Manifest);if err!=nil{t.Fatal(err)}
 if !bytes.Equal(files["tuf/metadata/1.targets.json"],publicRepo.Files["metadata/1.targets.json"]){t.Fatal("metadata changed")}
 assets:=t.TempDir()
 for name,data:=range files{path:=filepath.Join(assets,filepath.FromSlash(name));if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{t.Fatal(err)};if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}}
 if err:=VerifyStaticDirectory(assets,plan.Manifest,now);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(assets,"extra.txt"),[]byte("private"),0600);err!=nil{t.Fatal(err)}
 if err:=VerifyStaticDirectory(assets,plan.Manifest,now);err==nil{t.Fatal("extra asset accepted")}
 if err:=os.Remove(filepath.Join(assets,"extra.txt"));err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(assets,"app.js"),[]byte("changed"),0600);err!=nil{t.Fatal(err)}
 if err:=VerifyStaticDirectory(assets,plan.Manifest,now);err==nil{t.Fatal("changed asset accepted")}
 // Sequence two reuses inventory but needs a fresh signed approval.
 later:=now.Add(time.Minute)
 raw2,_,err:=snapshot.Build(s,nil,snapshot.Options{Sequence:2,SourceRevision:strings.Repeat("b",40),CreatedAt:later,ExpiresAt:now.Add(24*time.Hour)});if err!=nil{t.Fatal(err)}
 d2,err:=review.Plan(raw2);if err!=nil{t.Fatal(err)}
 for i:=range d2.Reviews{
  for _,v:=range d.Reviews{if d2.Reviews[i].Requirement.ID==v.Requirement.ID{d2.Reviews[i]=v;d2.Reviews[i].ReviewedAt=&later;break}}
 }
 a2,err:=review.NewApproval(raw2,d2,dir,a,later,later.Add(time.Hour));if err!=nil{t.Fatal(err)}
 for _,v:=range d2.Reviews{a2,err=review.SignReview(raw2,d2,dir,a,a2,v.Requirement.ID,reviewers[v.Reviewer],later);if err!=nil{t.Fatal(err)}}
 for _,id:=range []string{"release-a","release-b"}{a2,err=review.SignRelease(raw2,d2,dir,a,a2,id,reviewers[id],later);if err!=nil{t.Fatal(err)}}
 lo.Reviewed.Bootstrap=false;lo.Reviewed.Publish.Version=2;lo.Reviewed.Publish.Now=later;lo.Reviewed.Dossier=d2;lo.Reviewed.Approval=a2;lo.ExpectedHeadSHA256=receipt.RecordSHA256
 nextRootOpts,nextKeys:=rotationFixture(t,now.Add(72*time.Hour))
 root2,_,err:=RotateRoot([][]byte{root},digest(root),RotateRootOptions{Now:later,Next:nextRootOpts,OldSigners:opts.Signers,ExpectedCurrentSHA256:digest(root)});if err!=nil{t.Fatal(err)}
 lo.RootChain=[][]byte{root,root2};lo.InitialRootSHA256=digest(root)
 lo.Reviewed.Publish.RootSHA256=digest(root2)
 lo.Reviewed.Publish.TargetsSigners=[]ed25519.PrivateKey{nextKeys[metadata.TARGETS]}
 lo.Reviewed.Publish.SnapshotSigners=[]ed25519.PrivateKey{nextKeys[metadata.SNAPSHOT]}
 lo.Reviewed.Publish.TimestampSigners=[]ed25519.PrivateKey{nextKeys[metadata.TIMESTAMP]}
 b2:=review.ReleaseBinding{InitialRootSHA256:digest(root),CurrentRootSHA256:digest(root2),SnapshotSHA256:digest(raw2),Sequence:2,TargetsExpires:lo.Reviewed.Publish.TargetsExpires,SnapshotMetadataExpires:lo.Reviewed.Publish.SnapshotExpires,TimestampExpires:lo.Reviewed.Publish.TimestampExpires}
 c2,err:=review.PrepareCredential(raw2,d2,dir,a,a2,b2,later);if err!=nil{t.Fatal(err)}
 for _,id:=range []string{"release-a","release-b"}{c2,err=review.SignCredential(raw2,d2,dir,a,a2,c2,id,reviewers[id],later);if err!=nil{t.Fatal(err)}}
 lo.Reviewed.PublicCredential,err=review.CredentialBytes(c2);if err!=nil{t.Fatal(err)}
 noPin:=lo;noPin.ExpectedHeadSHA256=""
 if _,err:=BuildInLedger(root2,raw2,noPin);err==nil{t.Fatal("rotation without prior head pin")}
 receipt2,err:=BuildInLedger(root2,raw2,lo);if err!=nil||receipt2.Sequence!=2||receipt2.PreviousRecordSHA256!=receipt.RecordSHA256{t.Fatal(receipt2,err)}
 if receipt2.RootVersion!=2||receipt2.InitialRootSHA256!=digest(root)||receipt2.RootSHA256!=digest(root2){t.Fatal(receipt2)}
 rotated,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt2.RecordSHA256,later);if err!=nil||len(rotated.Files)!=6||!bytes.Equal(rotated.Files["metadata/1.root.json"],root)||!bytes.Equal(rotated.Files["metadata/2.root.json"],root2){t.Fatal(err)}
 staticOpts.First=false;staticOpts.At=later;staticOpts.ExpectedHeadSHA256=receipt2.RecordSHA256;staticOpts.PreviousManifest=oldManifest;staticOpts.PreviousManifestSHA256=plan.ManifestSHA256
 files2,delta,err:=PrepareStaticPublication(staticOpts)
 if err!=nil||delta.NewFiles!=4||delta.ChangedFiles!=1||delta.UnchangedFiles!=len(files)-1||!bytes.Equal(files2["tuf/metadata/1.targets.json"],files["tuf/metadata/1.targets.json"]){t.Fatal(delta,err)}
 // Exercise the actual prepared static directory over local TLS, not
 // only repository maps. Keep v1 history while switching to v2.
 if err:=os.WriteFile(filepath.Join(assets,"app.js"),files["app.js"],0600);err!=nil{t.Fatal(err)}
 if err:=VerifyStaticDirectory(assets,plan.Manifest,now);err!=nil{t.Fatal(err)}
 assets2:=t.TempDir()
 for name,data:=range files2{path:=filepath.Join(assets2,filepath.FromSlash(name));if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{t.Fatal(err)};if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}}
 if err:=VerifyStaticDirectory(assets2,delta.Manifest,later);err!=nil{t.Fatal(err)}
 var currentDir atomic.Value;currentDir.Store(assets)
 staticServer:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){
  http.FileServer(http.Dir(currentDir.Load().(string))).ServeHTTP(w,req)
 }));defer staticServer.Close()
 state:=filepath.Join(t.TempDir(),"static-client")
 so:=Options{StateDir:state,MetadataURL:staticServer.URL+"/tuf/metadata",TargetsURL:staticServer.URL+"/tuf/targets",InitialRootSHA256:digest(root),BootstrapRoot:root,ReviewAuthority:a}
 if _,r,err:=refresh(context.Background(),so,true,staticServer.Client());err!=nil||r.RootVersion!=1||r.Registry.Manifest.Sequence!=1||r.ReleaseApproval==nil||!r.ReleaseApproval.ReleaseApprovalVerified{t.Fatal(r,err)}
 currentDir.Store(assets2);so.BootstrapRoot=nil
 if _,r,err:=refresh(context.Background(),so,true,staticServer.Client());err!=nil||r.RootVersion!=2||r.Registry.Manifest.Sequence!=2||r.ReleaseApproval==nil||!r.ReleaseApproval.ReleaseApprovalVerified{t.Fatal(r,err)}
 if view,r,err:=LoadAuthorizedInstalled(state,digest(root),a);err!=nil||view==nil||r.RootVersion!=2||r.Registry.Manifest.Sequence!=2||r.ReleaseApproval==nil||!r.ReleaseApproval.ReleaseApprovalVerified{t.Fatal(r,err)}
 nextSession,err:=OpenConsumer(ConsumerOptions{StateDir:state,InitialRootSHA256:digest(root),Authority:a,MinimumSequence:2,ExpectedSnapshotSHA256:digest(raw2)})
 if err!=nil{t.Fatal(err)}
 delta,err:=session.Diff(nextSession,true)
 if err!=nil||delta.Next.Sequence!=2||delta.Previous.Sequence!=1||len(delta.CertificateChanges)!=0||delta.Transition==nil||delta.ReleaseAuthenticated{t.Fatal(delta,err)}

 currentDir.Store(assets)
 if _,_,err:=refresh(context.Background(),so,true,staticServer.Client());err==nil{t.Fatal("older static deployment accepted")}
 staticOpts.PreviousManifestSHA256=strings.Repeat("f",64)
 if _,_,err:=PrepareStaticPublication(staticOpts);err==nil{t.Fatal("bad prior manifest pin")}
 if _,err:=BuildInLedger(root2,raw2,lo);err==nil{t.Fatal("stale head replay")}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt2.RecordSHA256,now.Add(time.Hour));err==nil{t.Fatal("expired timestamp exported")}
 if err:=os.Remove(filepath.Join(ledger,evidenceName(1)));err!=nil{t.Fatal(err)}
 if _,_,err:=ExportLedgerHead(ledger,digest(root),digest(ab),receipt2.RecordSHA256,later);err==nil{t.Fatal("gap ignored")}
 // A review key listed in ANY TUF role is rejected, even if not used to sign.
 opts.Roles[metadata.TARGETS]=RoleKeys{[]ed25519.PublicKey{reviewers["source"].Public().(ed25519.PublicKey)},1}
 badRoot,err:=CreateRoot(opts);if err!=nil{t.Fatal(err)}
 if err:=checkRoleSeparation(badRoot,digest(badRoot),a);err==nil{t.Fatal("cross-config role key reuse")}
}
