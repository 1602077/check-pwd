package password

import (
	"math/rand"
	"testing"
	"time"
)

var badPasswords = []string{"password", "password123", "helloworld"}

func TestIntegrationCheckPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test")
	}

	t.Run("vulnerable passwords are identified as compromised",
		func(t *testing.T) {
			for _, pwd := range badPasswords {
				hash := NewHash(pwd)
				compromised, err := CheckPassword(*hash)
				if err != nil {
					t.Fatal(err)
				}
				if !compromised {
					t.Fatal("Expected password to be identified as compromised.")
				}
			}
		})

	t.Run("non-vulnerable passwords are identified as safe",
		func(t *testing.T) {
			// Generate a very long random string, hereby the chances of it
			// being compromised are low.
			pwd := randomString(500)
			hash := NewHash(pwd)
			compromised, err := CheckPassword(*hash)
			if err != nil {
				t.Fatal(err)
			}
			if compromised {
				t.Fatal("Expected password to be identified as not compromised.")
			}
		})
}

func TestNewHash(t *testing.T) {
	t.Run("Are deterministic", func(t *testing.T) {
		pwd := "jack"

		hash1 := NewHash(pwd)
		hash2 := NewHash(pwd)

		if hash1.head != hash2.head {
			t.Fatal("Expected heads of hashes to be equal.")
		}
		if hash1.tail != hash2.tail {
			t.Fatal("Expected tails of hashes to be equal.")
		}

		if len(hash1.head) != 5 {
			t.Fatalf("Expected head to be of length 5, Got %v", len(hash1.head))
		}
	})
}

// randomString generates a random alpha-numeric string of a given length.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	var seededRand *rand.Rand = rand.New(
		rand.NewSource(time.Now().UnixNano()))

	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}

	return string(b)
}
