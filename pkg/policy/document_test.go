package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictDecode(t *testing.T) {
	d:=Document{Defaults()[0],[]Review{},[]Decision{}}
	b,err:=json.Marshal(d)
	if err!=nil { t.Fatal(err) }
	if _,err:=DecodeDocument(b);err!=nil { t.Fatal(err) }
	for _,bad:=range []string{
		strings.Replace(string(b),`"allowSystemTrustFallback":false`,`"allowSystemTrustFallback":false,"allowSystemTrustFallback":true`,1),
		strings.Replace(string(b),`,"allowSystemTrustFallback":false`,"",1),
		strings.Replace(string(b),`"purpose":`,`"Purpose":`,1),
		string(b)+"{}",
		strings.Replace(string(b),`"trustAnchors":[]`,`"trustAnchors":null`,1),
	} {
		decoded,err:=DecodeDocument([]byte(bad))
		if err==nil && decoded.Policy.Validate()==nil { t.Fatal("invalid document accepted") }
	}
}
