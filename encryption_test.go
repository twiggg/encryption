package encryption

import (
	//"fmt"
	//"fmt"
	"testing"
)

var passtests = []struct {
	pass     string
	salt     string
	expected []byte
}{
	{"1K9l8985", "secretsalt", []byte("")},
	{"1K9l8985", "secretsa", []byte("")},
	{"1K9l8985", "secretsalterrrr", []byte("")},
}

func TestHashbcrypt(t *testing.T) {
	pass := passtests[0].pass
	salt := passtests[0].salt
	//shorter := passtests[1].salt
	//longer := passtests[2].salt
	cost := 12
	hash, err := Hashbcrypt(pass, []byte(salt), cost)
	//fmt.Println("err: ", err)
	if err != nil {
		t.Error("there was an error while bcrypting the pass !")
	}
	passtests[0].expected = hash
	//fmt.Println("expected: ", passtests[0].expected)

}

func TestCheckbcrypt(t *testing.T) {
	pass := passtests[0].pass
	salt := passtests[0].salt
	shorter := passtests[1].salt
	longer := passtests[2].salt
	cost := 12
	hash, _ := Hashbcrypt([]byte(pass), []byte(salt), cost)

	//hash := passtests[0].expected
	//fmt.Println("hash : ", hash)

	ok := Checkbcrypt(hash, []byte(pass), []byte(salt))
	//fmt.Println("ok: ", ok)
	if ok != nil {
		t.Error("Sorry the passwords do not match...")
		t.Fail()
	}
	short := Checkbcrypt(hash, []byte(pass), []byte(shorter))
	//fmt.Println("too short: ", short)
	if short == nil {
		t.Error("Problem: shorter sequence works...")
		t.Fail()
	}
	long := Checkbcrypt(hash, []byte(pass), []byte(longer))
	//fmt.Println("too long: ", long)
	if long == nil {
		t.Error("Problem: longer sequence works...")
		t.Fail()
	}
}
