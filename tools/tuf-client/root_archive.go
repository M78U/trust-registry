package tufclient

import (
 "bytes"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strconv"
 "strings"
 "time"
)

func evidenceChain(v evidence)[][]byte{
 return append(append([][]byte(nil),v.RootHistory...),v.Root)
}
func rootPrefix(old,next [][]byte)bool{
 if len(old)==0||len(next)<len(old){return false}
 for i,b:=range old{if !bytes.Equal(b,next[i]){return false}}
 return true
}
func rootArchiveName(version int)string{return fmt.Sprintf("%d.root.json",version)}
func commitRoot(dir string,version int,raw []byte)error{
 if len(raw)==0||len(raw)>maxRoot||version<1||version>MaxRootChain{return errors.New("invalid root archive record")}
 // Keep incomplete staging files outside the numbered archive.
 f,err:=os.CreateTemp(filepath.Dir(dir),".root-stage-");if err!=nil{return err}
 defer os.Remove(f.Name())
 if _,err=f.Write(raw);err==nil{err=f.Sync()}
 closeErr:=f.Close();if err==nil{err=closeErr};if err!=nil{return err}
 return os.Link(f.Name(),filepath.Join(dir,rootArchiveName(version)))
}
// readRootArchive is called under the existing client-state lock. A missing
// archive is legacy v1 only; never infer v1 from rotated cached metadata.
func readRootArchive(state,pin string,cached []byte,at time.Time,initialize bool)([][]byte,error){
 dir:=filepath.Join(state,"roots")
 if err:=regularDir(dir);err!=nil{
  if !os.IsNotExist(err){return nil,err}
  chain:=[][]byte{cached}
  if _,_,err:=validateRootChain(chain,pin,at,false);err!=nil{return nil,errors.New("root archive missing and cache is not pinned v1")}
  if initialize{
   if err:=os.Mkdir(dir,0700);err!=nil{return nil,err}
   if err:=commitRoot(dir,1,cached);err!=nil{return nil,err}
  }
  return chain,nil
 }
 chain,err:=readNumberedRootArchive(dir,pin,at);if err!=nil{return nil,err}
 if !bytes.Equal(chain[len(chain)-1],cached){return nil,errors.New("cached root differs from verified archive; inspect interrupted update")}
 return chain,nil
}

// readNumberedRootArchive does not consult the mutable cached root. Only the
// explicit forward recovery operation may use it without cache equality.
func readNumberedRootArchive(dir,pin string,at time.Time)([][]byte,error){
 if err:=regularDir(dir);err!=nil{return nil,err}
 f,err:=os.Open(dir);if err!=nil{return nil,err};defer f.Close()
 entries,err:=f.ReadDir(MaxRootChain+1);if err!=nil&&err!=io.EOF{return nil,err}
 if len(entries)<1||len(entries)>MaxRootChain{return nil,errors.New("root archive count limit")}
 names:=map[string]bool{}
 for _,v:=range entries{
  if !v.Type().IsRegular(){return nil,errors.New("invalid root archive entry")}
  names[v.Name()]=true
 }
 chain:=[][]byte{}
 for i:=1;i<=len(entries);i++{
  name:=rootArchiveName(i)
  if !names[name]{return nil,errors.New("missing numbered root archive record")}
  raw,err:=readRegular(filepath.Join(dir,name),maxRoot);if err!=nil{return nil,err}
  chain=append(chain,raw)
 }
 if _,_,err:=validateRootChain(chain,pin,at,false);err!=nil{return nil,err}
 return chain,nil
}
// rootArchiveCapture independently verifies each downloaded numbered root
// before allowing the upstream updater to persist it. On interrupted writes,
// mismatched archive/cache is rejected rather than silently falling back.
type rootArchiveCapture struct{
 state,pin string
 chain [][]byte
 at time.Time
}
func(c *rootArchiveCapture)accept(name string,raw []byte)error{
 if !strings.HasSuffix(name,".root.json"){return nil}
 n,err:=strconv.Atoi(strings.TrimSuffix(name,".root.json"))
 if err!=nil||n!=len(c.chain)+1||name!=rootArchiveName(n)||n>MaxRootChain{return errors.New("unexpected numbered root download")}
 chain:=append(append([][]byte(nil),c.chain...),bytes.Clone(raw))
 if _,_,err:=validateRootChain(chain,c.pin,c.at,false);err!=nil{return err}
 if err:=commitRoot(filepath.Join(c.state,"roots"),n,raw);err!=nil{return err}
 c.chain=chain
 return nil
}
// checkInstalledRootBaseline prevents a rotated installation from being
// silently replaced by a shorter or forked archive, even before refreshing.
func checkInstalledRootBaseline(state,pin string,chain [][]byte)error{
 dir:=filepath.Join(state,"installed")
 if _,err:=os.Lstat(dir);os.IsNotExist(err){return nil}else if err!=nil{return err}
 old,_,err:=latestEvidence(dir);if err!=nil{return err}
 if old==nil{return nil}
 if _,err:=verifyEvidence(*old,pin,old.AcceptedAt);err!=nil{return err}
 if !rootPrefix(evidenceChain(*old),chain){return errors.New("root archive precedes or forks installed history")}
 return nil
}
