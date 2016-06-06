package encryption

import (
	"crypto/hmac"
	"crypto/sha256"
	"golang.org/x/crypto/bcrypt"
	//"golang.org/x/crypto/scrypt"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	//"fmt"
)

/* ---------------------------------------------------------------------------------------------------
   ---------------------------------------------- CSPRNG (salt)  -------------------------------------
   ---------------------------------------------------------------------------------------------------
   ---------------------------------------------------------------------------------------------------*/
//random bytes for salts, that are supposed to be added to the password before hashing

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

/*
// Example: this will give us a 44 byte, base64 encoded output
token, err := GenerateRandomString(32)
if err != nil {
    // Serve an appropriately vague error to the
    // user, but log the details internally.
}
*/

/* ---------------------------------------------------------------------------------------------------
   ---------------------------------------------- BCRYPT   -------------------------------------------
   ---------------------------------------------------------------------------------------------------
   ---------------------------------------------------------------------------------------------------*/
//bcrypt for password encryption
// generate password hash
func Hashbcrypt(message string, salt []byte, cost int) ([]byte, error) {
	pass := []byte(message)
	s := [][]byte{pass, salt}
	sentence := bytes.Join(s, []byte(""))
	hash, err := bcrypt.GenerateFromPassword(sentence, bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func Checkbcrypt(hashed []byte, password []byte, salt []byte) error {
	s := [][]byte{password, salt}
	sentence := bytes.Join(s, []byte(""))
	err := bcrypt.CompareHashAndPassword(hashed, sentence)
	/*if err != nil {
		//log.Fatalln("incorrect password")
		fmt.Println("password is incorrect")

	}*/
	return err

}

func HashHS256(message string, salt []byte) ([]byte, error) {
	h := hmac.New(sha256.New, salt)
	h.Write([]byte(message))
	return h.Sum(nil), nil
}
func ComputeHmac256(message string, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

// TODO: store the hash
// later, when they try to log in again...
