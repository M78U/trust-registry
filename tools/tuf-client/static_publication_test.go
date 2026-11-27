package tufclient

import(
 "strings"
 "testing"
 "time"
)
func TestStaticAssetBudgetAndDelta(t *testing.T){
 a:=staticAssets{files:map[string][]byte{}}
 if err:=a.add("tuf/metadata/1.root.json",[]byte("root"));err!=nil{t.Fatal(err)}
 if err:=a.add("tuf/metadata/1.root.json",[]byte("root"));err!=nil||len(a.files)!=1||a.total!=4{t.Fatal(err)}
 if err:=a.add("tuf/metadata/1.root.json",[]byte("changed"));err==nil{t.Fatal("overwrite")}
 for _,name:=range []string{"private-evidence/a","tuf/../secret","tuf/metadata/root.json","tuf/metadata/01.root.json","tuf/targets/not-a-hash.registry-snapshot.json"}{if err:=a.add(name,[]byte("x"));err==nil{t.Fatal(name)}}
 if err:=a.add("app.js",make([]byte,MaxStaticAssetBytes+1));err==nil{t.Fatal("oversized file")}
 a.total=MaxStaticTotalBytes
 if err:=a.add("app.js",[]byte("x"));err==nil{t.Fatal("total budget")}
 m:=StaticManifest{Sequence:1,InitialRootSHA256:strings.Repeat("a",64),AuthoritySHA256:strings.Repeat("b",64),HeadSHA256:strings.Repeat("c",64),TimestampExpires:time.Now().UTC().Add(time.Hour),Files:[]StaticFile{{"tuf/metadata/1.root.json",digest([]byte("root")),4}}}
 n:=m;n.Files=append([]StaticFile{},m.Files...);n.Files[0].SHA256=digest([]byte("changed"))
 if _,err:=compareStatic(n,&m);err==nil{t.Fatal("immutable asset replaced")}
 n=m;n.Files=nil;if _,err:=compareStatic(n,&m);err==nil{t.Fatal("immutable asset removed")}
 if !strings.Contains(releaseHeaders,"/tuf/metadata/timestamp.json\n  ! Cache-Control\n  Cache-Control: no-store"){t.Fatal("missing timestamp override")}
}
