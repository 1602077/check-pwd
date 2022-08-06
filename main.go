package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var WEBSITE_URL string = "https://api.pwnedpasswords.com/range/"

type Hash struct {
	head string
	tail string
}

func NewHash(pwd string) *Hash {
	h := sha1.New()
	h.Write([]byte(pwd))
	hexS := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
	return &Hash{
		head: hexS[:5],
		tail: hexS[5:],
	}
}

// CheckPass uses api.pwnedpasswords.com to check for compromised passwords.
// It sends a partial hash and receives a list of hashes that match the first 5
// chars of your passwords hash as a response, meaning your password isn't
// shared over the internet in hashed or un-hashed form.
func CheckPass(pwd string) (bool, error) {
	log.Printf("INFO|Checking if '%v' is compromised|", pwd)
	hash := NewHash(pwd)

	log.Printf("INFO|Sending request to '%v'|", WEBSITE_URL+hash.head)

	resp, err := http.Get(WEBSITE_URL + hash.head)
	if err != nil {
		log.Printf("ERROR|Get request failed|%v|", err)
		return true, err
	}
	defer resp.Body.Close()

	var body bytes.Buffer
	_, err = io.Copy(&body, resp.Body)
	if err != nil {
		log.Printf("ERROR|Failed to read response body|%v|", err)
		return true, err
	}

	results := make(map[string]string)
	for _, v := range strings.Split(body.String(), "\r\n") {
		a := strings.Split(v, ":")
		if len(a) != 2 {
			log.Printf("INFO|Failed to parse response line %v|Got <2 args|", v)
			continue
		}
		results[a[0]] = a[1]
	}

	if v, ok := results[hash.tail]; ok {
		log.Printf("WARN|Password '%v' is compromised|Found %v times|", pwd, v)
		return true, nil
	}
	log.Printf("WARN|Password '%v' is not compromised|", pwd)
	return false, nil
}

func parseFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var l []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		l = append(l, s.Text())
	}
	return l, s.Err()
}

func main() {
	flag.Usage = func() {
		fmt.Printf("Usage: %s [flags] <passwords>\n", os.Args[0])
		fmt.Println("Either pass a password directly or use a '\\n' deliminated file:")
		fmt.Println(" - check-pwd password1")
		fmt.Println(" - check-pwd --file passwords.txt")

		fmt.Println("\nFlags:")
		flag.PrintDefaults()
	}

	file := flag.Bool("file", false, "path to file of passwords")
	flag.Parse()
	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(0)
	}
	pwd := flag.Arg(0)

	if !*file {
		_, err := CheckPass(pwd)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}

	pwds, err := parseFile(pwd)
	if err != nil {
		log.Fatal(err)
	}
	var compPwd int
	for _, p := range pwds {
		bad, err := CheckPass(p)
		if err != nil {
			log.Fatal(err)
		}
		if bad {
			compPwd++
		}
	}
	fmt.Println()
	log.Printf("WARN|%v/%v of your passwords are compromised!|", compPwd, len(pwds))
}
