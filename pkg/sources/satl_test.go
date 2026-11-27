package sources

import "testing"

func TestSATLNameOnly(t *testing.T){
	c,err:=SATL();if err!=nil{t.Fatal(err)}
	if len(c.Entries)!=7||c.TrustStatus!="NOT_ESTABLISHED"{t.Fatal("unexpected SATL catalog")}
	matches:=0
	for _,e:=range c.Entries{if e.CandidateListingID!=""{matches++;if e.ID!="sheca-g2"{t.Fatal("ambiguous name mapped")}}}
	if matches!=1{t.Fatal("unexpected name match count")}
	c.Entries[0].CandidateListingID="uca-rapid-sm2"
	if err:=c.Validate();err==nil{t.Fatal("different labels mapped")}
	c,err=SATL();if err!=nil{t.Fatal(err)}
	c.TrustStatus="TRUSTED"
	if err:=c.Validate();err==nil{t.Fatal("trust promotion accepted")}
}
