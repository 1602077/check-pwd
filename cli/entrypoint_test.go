package cli

import (
	"os"
	"testing"
)

func TestParseFile(t *testing.T) {
	file, err := os.CreateTemp("", "TestFile.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	passwords := []string{"password", "password2", "password3"}
	for _, pwd := range passwords {
		file.Write([]byte(pwd + "\n"))
	}

	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	parsedPasswords, err := parseFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(parsedPasswords) != len(passwords) {
		t.Fatalf("Expected %v passwords, Got %v",
			len(passwords),
			len(parsedPasswords),
		)
	}

	for i := range passwords {
		if passwords[i] != parsedPasswords[i] {
			t.Fatalf("Expected %v, Got %v", passwords[i], parsedPasswords[i])
		}
	}
}
