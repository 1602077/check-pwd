package password

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

const (
	pwnedpasswordsAPI string = "https://api.pwnedpasswords.com/range/"
	headSize          int    = 5
)

// PwnedHash splits a hash into a head and tail. Only the head of the hash is
// sent to the pwnedpasswords api, which returns the full hashes matching the
// head. Hashes can then be compared locally to identify any compromised
// passwords.
type PwnedHash struct {
	unhashed string
	head     string
	tail     string
}

// NewHash generates a sha1 hash of an input string and splits this up into a
// head and tail ready to be spend to pwnedpasswordsAPI.
func NewHash(password string) *PwnedHash {
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	return &PwnedHash{
		head:     hash[:headSize],
		tail:     hash[headSize:],
		unhashed: password,
	}
}

// CheckPassword uses api.pwnedpasswords.com to check for compromised passwords.
// It sends a partial hash and receives a list of hashes that match the first 5
// characters of your passwords hash as a response, meaning passwords are not
// shared over the internet in a hashed or un-hashed form.
func CheckPassword(hash PwnedHash) (bool, error) {
	resp, err := http.Get(pwnedpasswordsAPI + hash.head)
	if err != nil {
		log.Printf("get request failed|%v", err)
		return true, err
	}
	defer resp.Body.Close()

	var body bytes.Buffer
	if _, err = io.Copy(&body, resp.Body); err != nil {
		log.Printf("Failed to read response body%v", err)
		return true, err
	}

	results := make(map[string]string)
	for _, v := range strings.Split(body.String(), "\r\n") {
		a := strings.Split(v, ":")
		if len(a) != 2 {
			log.Printf("failed to parse response line %v|Got <2 args", v)
			continue
		}
		results[a[0]] = a[1]
	}

	if v, ok := results[hash.tail]; ok {
		fmt.Printf("password %q is compromised. Found in %v breaches.\n", hash.unhashed, v)
		return true, nil
	}

	return false, nil
}
